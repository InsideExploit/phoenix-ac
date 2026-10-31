#include "modules.hpp"
#include "vendor/lazy_importer.hpp"
#include "vendor/xor_string.hpp"
#include <TlHelp32.h>
#include <cwchar>
#include <cwctype>
#include <string>
namespace detections::modules
{
    namespace
    {
        int parse_build(const wchar_t* exe_name)
        {
            const wchar_t* p = wcsstr(exe_name, XSW(L"_b"));
            if (!p)
                return -1;
            p += 2;
            int value = 0;
            int digits = 0;
            while (*p >= L'0' && *p <= L'9' && digits < 5)
            {
                value = value * 10 + (*p - L'0');
                ++p;
                ++digits;
            }
            return digits ? value : -1;
        }
    }

    bool is_allowed_name(const wchar_t* exe_name)
    {
        if (!exe_name || !exe_name[0])
            return false;

        static const wchar_t* const k_exact[] = {
            XSW(L"FiveM.exe"), XSW(L"GTA5.exe"), XSW(L"steam.exe"), XSW(L"steamwebhelper.exe"),
            XSW(L"explorer.exe"), XSW(L"dwm.exe"), XSW(L"svchost.exe"), XSW(L"csrss.exe"), XSW(L"winlogon.exe"),
            XSW(L"services.exe"), XSW(L"lsass.exe"), XSW(L"smss.exe"), XSW(L"chrome.exe"), XSW(L"msedge.exe"),
            XSW(L"firefox.exe"), XSW(L"discord.exe"), XSW(L"obs64.exe"), XSW(L"obs32.exe"),
            XSW(L"NVIDIA Web Helper.exe"), XSW(L"NVDisplay.Container.exe"),
            XSW(L"RuntimeBroker.exe"), XSW(L"ApplicationFrameHost.exe"), XSW(L"sihost.exe"),
            XSW(L"ctfmon.exe"), XSW(L"SearchHost.exe"), XSW(L"StartMenuExperienceHost.exe"),
            XSW(L"MicrosoftEdgeUpdate.exe"), XSW(L"TextInputHost.exe"),
            XSW(L"module.exe"),
        };
        static const wchar_t* const k_prefix[] = { XSW(L"FiveM_") };

        for (auto* p : k_exact)
        {
            if (_wcsicmp(exe_name, p) == 0)
                return true;
        }
        for (auto* p : k_prefix)
        {
            if (_wcsnicmp(exe_name, p, wcslen(p)) == 0)
                return true;
        }
        return false;
    }

    bool is_safe_name(const wchar_t* exe_name)
    {
        if (!exe_name || !exe_name[0])
            return false;

        static const wchar_t* const k_exact[] = {
            XSW(L"csrss.exe"), XSW(L"smss.exe"), XSW(L"lsass.exe"), XSW(L"wininit.exe"),
            XSW(L"services.exe"), XSW(L"winlogon.exe"), XSW(L"svchost.exe"),
            XSW(L"module.exe"),
            XSW(L"FiveM.exe"),
        };
        static const wchar_t* const k_prefix[] = { XSW(L"FiveM_") };

        for (auto* p : k_exact)
        {
            if (_wcsicmp(exe_name, p) == 0)
                return true;
        }
        for (auto* p : k_prefix)
        {
            if (_wcsnicmp(exe_name, p, wcslen(p)) == 0)
                return true;
        }
        return false;
    }

    bool is_safe_pid(DWORD pid)
    {
        HANDLE snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return false;

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        bool safe = false;

        if (LI_KERNEL(Process32FirstW)(snapshot, &pe))
        {
            do
            {
                if (pe.th32ProcessID == pid)
                {
                    safe = is_safe_name(pe.szExeFile);
                    break;
                }
            } while (LI_KERNEL(Process32NextW)(snapshot, &pe));
        }

        LI_KERNEL(CloseHandle)(snapshot);
        return safe;
    }

    bool is_allowed_pid(DWORD pid)
    {
        HANDLE snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return false;

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        bool allowed = false;

        if (LI_KERNEL(Process32FirstW)(snapshot, &pe))
        {
            do
            {
                if (pe.th32ProcessID == pid)
                {
                    allowed = is_allowed_name(pe.szExeFile);
                    break;
                }
            } while (LI_KERNEL(Process32NextW)(snapshot, &pe));
        }

        LI_KERNEL(CloseHandle)(snapshot);
        return allowed;
    }

    int highest_fivem_build()
    {
        int best = -1;

        HANDLE snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return best;

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);

        if (LI_KERNEL(Process32FirstW)(snapshot, &pe))
        {
            do
            {
                std::wstring name = pe.szExeFile;
                std::wstring lower;
                lower.resize(name.size());
                for (size_t i = 0; i < name.size(); ++i)
                    lower[i] = static_cast<wchar_t>(towlower(name[i]));
                if (lower.find(XSW(L"fivem")) == std::wstring::npos)
                    continue;

                const int build = parse_build(pe.szExeFile);
                if (build > best)
                    best = build;
            } while (LI_KERNEL(Process32NextW)(snapshot, &pe));
        }

        LI_KERNEL(CloseHandle)(snapshot);
        return best;
    }

    bool find_gta_internal_cheat(gta_cheat_hit& out_hit)
    {
        static const wchar_t* const k_internal_modules[] = {
            XSW(L"D3DCompiler_43.dll"),
            XSW(L"d3dx11_43.dll"),
            XSW(L"D3DX9_43.dll"),
        };

        HANDLE process_snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
        if (process_snapshot == INVALID_HANDLE_VALUE)
            return false;

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (!LI_KERNEL(Process32FirstW)(process_snapshot, &pe))
        {
            LI_KERNEL(CloseHandle)(process_snapshot);
            return false;
        }

        bool found = false;

        do
        {
            const wchar_t* name = pe.szExeFile;
            if (!name || !name[0])
                continue;
            if (_wcsnicmp(name, XSW(L"FiveM"), 5) != 0)
                continue;

            std::wstring lower;
            lower.resize(wcslen(name));
            for (size_t i = 0; i < lower.size(); ++i)
                lower[i] = static_cast<wchar_t>(towlower(name[i]));
            if (lower.find(XSW(L"gtaprocess")) == std::wstring::npos)
                continue;

            const DWORD pid = pe.th32ProcessID;
            HANDLE module_snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if (module_snapshot == INVALID_HANDLE_VALUE)
                continue;

            MODULEENTRY32W me{};
            me.dwSize = sizeof(me);
            std::wstring hit_modules;

            if (LI_KERNEL(Module32FirstW)(module_snapshot, &me))
            {
                do
                {
                    for (auto* suspicious : k_internal_modules)
                    {
                        if (_wcsicmp(me.szModule, suspicious) == 0)
                        {
                            if (!hit_modules.empty())
                                hit_modules += XSW(L", ");
                            hit_modules += me.szModule;
                            break;
                        }
                    }
                } while (LI_KERNEL(Module32NextW)(module_snapshot, &me));
            }

            LI_KERNEL(CloseHandle)(module_snapshot);

            if (!hit_modules.empty())
            {
                out_hit.pid      = pid;
                out_hit.exe_name = name;
                out_hit.modules  = std::move(hit_modules);
                found = true;
                break;
            }
        } while (LI_KERNEL(Process32NextW)(process_snapshot, &pe));

        LI_KERNEL(CloseHandle)(process_snapshot);
        return found;
    }

    std::vector<DWORD> fingerprint_scan(DWORD self_pid, DWORD fivem_pid)
    {
        std::vector<DWORD> results;

        static const wchar_t* const k_suspicious_modules[] = {
            XSW(L"d3dx9_43.dll"),
            XSW(L"armando.dll"),
        };

        HANDLE process_snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
        if (process_snapshot == INVALID_HANDLE_VALUE)
            return results;

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (!LI_KERNEL(Process32FirstW)(process_snapshot, &pe))
        {
            LI_KERNEL(CloseHandle)(process_snapshot);
            return results;
        }

        do
        {
            const DWORD pid = pe.th32ProcessID;
            if (pid == 0 || pid == 4 || pid == self_pid || pid == fivem_pid)
                continue;
            if (is_allowed_name(pe.szExeFile))
                continue;

            HANDLE module_snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if (module_snapshot == INVALID_HANDLE_VALUE)
                continue;

            MODULEENTRY32W me{};
            me.dwSize = sizeof(me);
            bool matched = false;

            if (LI_KERNEL(Module32FirstW)(module_snapshot, &me))
            {
                do
                {
                    for (auto* fingerprint : k_suspicious_modules)
                    {
                        if (_wcsicmp(me.szModule, fingerprint) == 0)
                        {
                            matched = true;
                            break;
                        }
                    }
                    if (matched)
                        break;
                } while (LI_KERNEL(Module32NextW)(module_snapshot, &me));
            }

            LI_KERNEL(CloseHandle)(module_snapshot);

            if (matched)
                results.push_back(pid);
        } while (LI_KERNEL(Process32NextW)(process_snapshot, &pe));

        LI_KERNEL(CloseHandle)(process_snapshot);
        return results;
    }
}