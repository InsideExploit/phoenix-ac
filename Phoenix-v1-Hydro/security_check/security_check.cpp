#include "security_check.hpp"

#include "vendor/lazy_importer.hpp"
#include "vendor/oreans/include/VirtualizerSDK.h"
#pragma auto_inline(off)
#include "vendor/xor_string.hpp"

#include <Windows.h>
#include <winternl.h>
#include <tbs.h>

#include <cstring>
#include <vector>

#pragma comment(lib, "tbs.lib")

namespace security_check
{
    namespace
    {

        __declspec(noinline) bool query_tpm_2_0()
        {
            VIRTUALIZER_START;
            TPM_DEVICE_INFO info{};
            volatile bool r = Tbsi_GetDeviceInfo(sizeof(info), &info) == TBS_SUCCESS
                && info.tpmVersion == TPM_VERSION_20;
            VIRTUALIZER_END;
            return r;
        }

        __declspec(noinline) bool query_secure_boot()
        {
            VIRTUALIZER_START;
            DWORD value = 0;
            DWORD size  = sizeof(value);
            volatile bool r = LI_ADVAPI(RegGetValueW)(HKEY_LOCAL_MACHINE,
                                  XSW(L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State"),
                                  XSW(L"UEFISecureBootEnabled"),
                                  RRF_RT_REG_DWORD, nullptr, &value, &size) == ERROR_SUCCESS
                && value == 1;
            VIRTUALIZER_END;
            return r;
        }

        __declspec(noinline) bool query_hvci()
        {
            VIRTUALIZER_START;
            const wchar_t* scenario_key = XSW(
                L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios"
                L"\\HypervisorEnforcedCodeIntegrity");

            DWORD value = 0;
            DWORD size  = sizeof(value);

            if (LI_ADVAPI(RegGetValueW)(HKEY_LOCAL_MACHINE, scenario_key, XSW(L"Running"),
                             RRF_RT_REG_DWORD, nullptr, &value, &size) == ERROR_SUCCESS && value == 1)
                return true;

            value = 0; size = sizeof(value);
            if (LI_ADVAPI(RegGetValueW)(HKEY_LOCAL_MACHINE, scenario_key, XSW(L"Enabled"),
                             RRF_RT_REG_DWORD, nullptr, &value, &size) == ERROR_SUCCESS && value == 1)
                return true;

            value = 0; size = sizeof(value);
            if (LI_ADVAPI(RegGetValueW)(HKEY_LOCAL_MACHINE,
                             XSW(L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard"),
                             XSW(L"SecurityServicesRunning"),
                             RRF_RT_REG_DWORD, nullptr, &value, &size) == ERROR_SUCCESS && (value & 2))
                return true;

            struct code_integrity_info
            {
                ULONG length;
                ULONG options;
            };

            {
                auto nt_qsi = LI_NTDLL(NtQuerySystemInformation);
                if (nt_qsi)
                {
                    code_integrity_info info{ sizeof(code_integrity_info), 0 };
                    if (nt_qsi(static_cast<SYSTEM_INFORMATION_CLASS>(103), &info, sizeof(info), nullptr) >= 0 && (info.options & 0x400))
                        return true;
                }
            }

            VIRTUALIZER_END;
            return false;
        }

        __declspec(noinline) bool query_dma_guard()
        {
            VIRTUALIZER_START;
            {
                auto nt_qsi = LI_NTDLL(NtQuerySystemInformation);
                if (nt_qsi)
                {
                    BOOLEAN enabled = FALSE;
                    if (nt_qsi(static_cast<SYSTEM_INFORMATION_CLASS>(202), &enabled, sizeof(enabled), nullptr) >= 0 && enabled)
                        return true;
                }
            }

            DWORD value = 0;
            DWORD size  = sizeof(value);
            if (LI_ADVAPI(RegGetValueW)(HKEY_LOCAL_MACHINE,
                             XSW(L"SYSTEM\\CurrentControlSet\\Control\\DmaSecurity"),
                             XSW(L"DmaGuardEnabled"),
                             RRF_RT_REG_DWORD, nullptr, &value, &size) == ERROR_SUCCESS && value == 1)
                return true;

            VIRTUALIZER_END;
            return false;
        }

        __declspec(noinline) bool query_iommu()
        {
            VIRTUALIZER_START;
            UINT buf_size = LI_KERNEL(EnumSystemFirmwareTables)('ACPI', nullptr, 0);
            if (buf_size >= 4 && buf_size <= 64 * 1024)
            {
                std::vector<BYTE> buffer(buf_size);
                if (LI_KERNEL(EnumSystemFirmwareTables)('ACPI', buffer.data(), buf_size) == buf_size)
                {
                    for (UINT i = 0; i + 4 <= buf_size; i += 4)
                    {
                        if (std::memcmp(buffer.data() + i, XS("DMAR"), 4) == 0) return true;
                        if (std::memcmp(buffer.data() + i, XS("IVRS"), 4) == 0) return true;
                    }
                }
            }

            HKEY key = nullptr;
            if (LI_ADVAPI(RegOpenKeyExW)(HKEY_LOCAL_MACHINE,
                              XSW(L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard"), 0,
                              KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) == ERROR_SUCCESS)
            {
                DWORD type = 0;
                DWORD size = 0;
                if (LI_ADVAPI(RegQueryValueExW)(key, XSW(L"AvailableSecurityProperties"),
                                     nullptr, &type, nullptr, &size) == ERROR_SUCCESS
                    && size > 0 && size <= 256)
                {
                    std::vector<BYTE> buffer(size);
                    if (LI_ADVAPI(RegQueryValueExW)(key, XSW(L"AvailableSecurityProperties"),
                                         nullptr, &type, buffer.data(), &size) == ERROR_SUCCESS)
                    {
                        const DWORD* items = reinterpret_cast<const DWORD*>(buffer.data());
                        const size_t count = size / sizeof(DWORD);
                        for (size_t i = 0; i < count; ++i)
                        {
                            if (items[i] == 3)
                            {
                                LI_ADVAPI(RegCloseKey)(key);
                                return true;
                            }
                        }
                    }
                }
                LI_ADVAPI(RegCloseKey)(key);
            }

            VIRTUALIZER_END;
            return false;
        }
    }

    std::wstring status::missing_list() const
    {
        std::wstring list;
        auto append = [&](const wchar_t* name) {
            if (!list.empty())
                list += XSW(L"\n");
            list += XSW(L"  - ");
            list += name;
        };

        if (!tpm20)       append(XSW(L"TPM 2.0"));
        if (!secure_boot) append(XSW(L"Secure Boot"));
        if (!hvci)        append(XSW(L"Core Isolation (Memory Integrity)"));
        if (!dma_guard)   append(XSW(L"Kernel DMA Protection"));
        if (!iommu)       append(XSW(L"IOMMU (VT-d / AMD-Vi)"));

        return list;
    }

    __declspec(noinline) status query()
    {
        VIRTUALIZER_START;
        status s{};
        s.tpm20       = true;// query_tpm_2_0();
        s.secure_boot = query_secure_boot();
        s.hvci        = query_hvci();
        s.dma_guard   = query_dma_guard();
        s.iommu       = query_iommu();
        VIRTUALIZER_END;
        return s;
    }
}
