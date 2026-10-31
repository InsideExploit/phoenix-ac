#include "common.hpp"

#include "vendor/lazy_importer.hpp"
#include "vendor/xor_string.hpp"

#include <Psapi.h>
#include <TlHelp32.h>
#include <cstring>
#include <cwctype>
#include <vector>

namespace common
{
    namespace
    {
        bool match_fivem_name(const wchar_t* name, std::wstring& out_lower)
        {
            if (!name || !*name)
                return false;

            const size_t n = wcslen(name);
            if (n < 5)
                return false;

            out_lower.assign(name, n);
            for (auto& c : out_lower)
                c = static_cast<wchar_t>(towlower(c));

            if (out_lower.compare(0, 5, XSW(L"fivem")) != 0)
                return false;

            const wchar_t* suffixes[] = {
                XSW(L"gtaprocess.exe"),
                XSW(L"gameprocess.exe"),
                XSW(L"_process.exe"),
            };

            for (auto sfx : suffixes)
            {
                const size_t sl = wcslen(sfx);
                if (out_lower.size() >= sl &&
                    out_lower.compare(out_lower.size() - sl, sl, sfx) == 0)
                    return true;
            }
            return false;
        }
    }

    bool enable_debug_privilege()
    {
        HANDLE token = nullptr;
        if (!LI_ADVAPI(OpenProcessToken)(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token))
            return false;

        bool ok = false;
        LUID luid{};
        if (LI_ADVAPI(LookupPrivilegeValueW)(nullptr, SE_DEBUG_NAME, &luid))
        {
            TOKEN_PRIVILEGES tp{};
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            const BOOL adjusted = LI_ADVAPI(AdjustTokenPrivileges)(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
            const DWORD err = LI_KERNEL(GetLastError)();
            ok = adjusted && err != ERROR_NOT_ALL_ASSIGNED;
        }

        LI_KERNEL(CloseHandle)(token);
        return ok;
    }

    DWORD find_fivem_pid(std::wstring& out_name)
    {
        DWORD pid = 0;

        HANDLE snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
        if (snapshot != INVALID_HANDLE_VALUE)
        {
            PROCESSENTRY32W pe{};
            pe.dwSize = sizeof(pe);

            if (LI_KERNEL(Process32FirstW)(snapshot, &pe))
            {
                do
                {
                    std::wstring lower;
                    if (match_fivem_name(pe.szExeFile, lower))
                    {
                        pid = pe.th32ProcessID;
                        out_name.assign(pe.szExeFile);
                        break;
                    }
                } while (LI_KERNEL(Process32NextW)(snapshot, &pe));
            }
            LI_KERNEL(CloseHandle)(snapshot);
        }

        if (pid)
            return pid;

        DWORD pids[1024]{};
        DWORD needed = 0;
        if (!K32EnumProcesses(pids, sizeof(pids), &needed))
            return 0;

        const DWORD count = needed / sizeof(DWORD);
        for (DWORD i = 0; i < count && !pid; ++i)
        {
            if (pids[i] == 0 || pids[i] == 4)
                continue;

            HANDLE h = LI_KERNEL(OpenProcess)(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pids[i]);
            if (!h)
                continue;

            wchar_t path[MAX_PATH * 2]{};
            DWORD len = _countof(path);
            if (LI_KERNEL(QueryFullProcessImageNameW)(h, 0, path, &len) && len > 0)
            {
                const wchar_t* base = wcsrchr(path, L'\\');
                base = base ? base + 1 : path;

                std::wstring lower;
                if (match_fivem_name(base, lower))
                {
                    pid = pids[i];
                    out_name.assign(base);
                }
            }
            LI_KERNEL(CloseHandle)(h);
        }

        return pid;
    }

    uint64_t remote_module_base(DWORD pid, const std::wstring& exe_name, uint64_t* out_size)
    {
        uint64_t base = 0;

        HANDLE snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snapshot == INVALID_HANDLE_VALUE)
            return 0;

        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);

        if (LI_KERNEL(Module32FirstW)(snapshot, &me))
        {
            do
            {
                if (_wcsicmp(me.szModule, exe_name.c_str()) == 0)
                {
                    base = reinterpret_cast<uint64_t>(me.modBaseAddr);
                    if (out_size)
                        *out_size = me.modBaseSize;
                    break;
                }
            } while (LI_KERNEL(Module32NextW)(snapshot, &me));
        }

        LI_KERNEL(CloseHandle)(snapshot);
        return base;
    }

    int parse_build_number(const std::wstring& exe_name)
    {
        const wchar_t* p = wcsstr(exe_name.c_str(), XSW(L"_b"));
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

        return digits > 0 ? value : -1;
    }

    uint64_t pattern_scan(HANDLE process,
                          uint64_t base,
                          uint64_t size,
                          const uint8_t* signature,
                          const char* mask)
    {
        constexpr size_t chunk_size = 0x40000;

        std::vector<uint8_t> buffer(chunk_size);
        const size_t pattern_len = strlen(mask);

        for (uint64_t offset = 0; offset + pattern_len < size; offset += chunk_size - pattern_len)
        {
            SIZE_T got = 0;
            const SIZE_T to_read = (offset + chunk_size <= size) ? chunk_size : static_cast<SIZE_T>(size - offset);

            if (!LI_KERNEL(ReadProcessMemory)(process, reinterpret_cast<LPCVOID>(base + offset), buffer.data(), to_read, &got))
                continue;

            if (got < pattern_len)
                continue;

            for (size_t i = 0; i + pattern_len <= got; ++i)
            {
                bool matched = true;
                for (size_t j = 0; j < pattern_len; ++j)
                {
                    if (mask[j] == 'x' && buffer[i + j] != signature[j])
                    {
                        matched = false;
                        break;
                    }
                }
                if (matched)
                    return base + offset + i;
            }
        }
        return 0;
    }
}
