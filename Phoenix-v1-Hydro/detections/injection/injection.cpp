#include "injection.hpp"
#include "vendor/lazy_importer.hpp"
#include "vendor/xor_string.hpp"
#include <TlHelp32.h>
#include <cstring>
#include <cwctype>
namespace detections::injection
{
    namespace
    {
        bool is_executable(DWORD protect)
        {
            protect &= 0xFF;
            return protect == PAGE_EXECUTE
                || protect == PAGE_EXECUTE_READ
                || protect == PAGE_EXECUTE_READWRITE
                || protect == PAGE_EXECUTE_WRITECOPY;
        }

        bool has_pe_header(HANDLE process, uint64_t base)
        {
            uint8_t buffer[0x400]{};
            SIZE_T got = 0;
            if (!LI_KERNEL(ReadProcessMemory)(process, reinterpret_cast<LPCVOID>(base), buffer, sizeof(buffer), &got)
                || got < 0x40)
                return false;

            if (buffer[0] != 'M' || buffer[1] != 'Z')
                return false;

            const DWORD pe_offset = *reinterpret_cast<DWORD*>(buffer + 0x3C);
            if (pe_offset + 4 > got)
                return false;

            return buffer[pe_offset]     == 'P'
                && buffer[pe_offset + 1] == 'E'
                && buffer[pe_offset + 2] == 0
                && buffer[pe_offset + 3] == 0;
        }

        bool is_fivem_module(const wchar_t* exe_path)
        {
            wchar_t lower[MAX_PATH * 2]{};
            wcsncpy_s(lower, exe_path, MAX_PATH * 2 - 1);
            for (wchar_t* p = lower; *p; ++p)
                *p = static_cast<wchar_t>(towlower(*p));

            return wcsstr(lower, XSW(L"fivem"))   != nullptr
                || wcsstr(lower, XSW(L"citizen")) != nullptr
                || wcsstr(lower, XSW(L"cfx"))     != nullptr;
        }
    }

    std::vector<hit> scan(DWORD fivem_pid, HANDLE fivem_handle)
    {
        std::vector<hit> out;

        HANDLE module_snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, fivem_pid);
        if (module_snapshot != INVALID_HANDLE_VALUE)
        {
            MODULEENTRY32W me{};
            me.dwSize = sizeof(me);

            if (LI_KERNEL(Module32FirstW)(module_snapshot, &me))
            {
                do
                {
                    if (is_fivem_module(me.szExePath))
                        continue;

                    const uint64_t module_base = reinterpret_cast<uint64_t>(me.modBaseAddr);
                    MEMORY_BASIC_INFORMATION mbi{};
                    if (!LI_KERNEL(VirtualQueryEx)(fivem_handle, reinterpret_cast<LPCVOID>(module_base), &mbi, sizeof(mbi)))
                        continue;

                    if (mbi.Type == MEM_PRIVATE && mbi.State == MEM_COMMIT)
                    {
                        hit h{};
                        h.type        = hit_type::stomped_module;
                        h.address     = module_base;
                        h.region_size = static_cast<uint32_t>(me.modBaseSize);
                        swprintf_s(h.detail,
                                   XSW(L"stomped: %s base=0x%llX prot=0x%lX"),
                                   me.szModule,
                                   static_cast<unsigned long long>(module_base),
                                   static_cast<unsigned long>(mbi.Protect));
                        out.push_back(h);
                    }
                } while (LI_KERNEL(Module32NextW)(module_snapshot, &me));
            }
            LI_KERNEL(CloseHandle)(module_snapshot);
        }

        {
            LPVOID address = nullptr;
            MEMORY_BASIC_INFORMATION mbi{};
            while (LI_KERNEL(VirtualQueryEx)(fivem_handle, address, &mbi, sizeof(mbi)) == sizeof(mbi))
            {
                if (mbi.State == MEM_COMMIT
                    && mbi.Type == MEM_PRIVATE
                    && is_executable(mbi.Protect)
                    && mbi.RegionSize >= 0x1000)
                {
                    const uint64_t base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
                    if (has_pe_header(fivem_handle, base))
                    {
                        hit h{};
                        h.type        = hit_type::private_exec_pe;
                        h.address     = base;
                        h.region_size = static_cast<uint32_t>(mbi.RegionSize);
                        swprintf_s(h.detail,
                                   XSW(L"PE in MEM_PRIVATE exec: base=0x%llX size=0x%lX prot=0x%lX"),
                                   static_cast<unsigned long long>(base),
                                   static_cast<unsigned long>(mbi.RegionSize),
                                   static_cast<unsigned long>(mbi.Protect));
                        out.push_back(h);
                    }
                }

                if (mbi.RegionSize == 0)
                    break;
                address = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
            }
        }

        return out;
    }
}