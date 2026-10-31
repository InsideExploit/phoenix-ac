#include "streamproof.hpp"
#include "detections/modules/modules.hpp"
#include "vendor/lazy_importer.hpp"
#include <TlHelp32.h>
#include <unordered_set>
#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

namespace detections::streamproof
{
    namespace
    {
        bool get_exe_for_pid(DWORD pid, wchar_t* out, size_t out_chars)
        {
            if (!out || out_chars == 0)
                return false;
            out[0] = L'\0';

            HANDLE snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
            if (snapshot == INVALID_HANDLE_VALUE)
                return false;

            PROCESSENTRY32W pe{};
            pe.dwSize = sizeof(pe);
            bool found = false;

            if (LI_KERNEL(Process32FirstW)(snapshot, &pe))
            {
                do
                {
                    if (pe.th32ProcessID == pid)
                    {
                        wcsncpy_s(out, out_chars, pe.szExeFile, _TRUNCATE);
                        found = true;
                        break;
                    }
                } while (LI_KERNEL(Process32NextW)(snapshot, &pe));
            }

            LI_KERNEL(CloseHandle)(snapshot);
            return found;
        }

        struct scan_context
        {
            DWORD fivem_pid;
            DWORD self_pid;
            std::unordered_set<DWORD>* seen;
            std::vector<hit>* results;
        };

        BOOL CALLBACK enum_windows_proc(HWND window, LPARAM lparam)
        {
            auto* ctx = reinterpret_cast<scan_context*>(lparam);

            DWORD affinity = 0;
            if (!LI_USER32(GetWindowDisplayAffinity)(window, &affinity))
                return TRUE;
            if (affinity == 0)
                return TRUE;

            DWORD pid = 0;
            LI_USER32(GetWindowThreadProcessId)(window, &pid);
            if (!pid || pid == ctx->fivem_pid || pid == ctx->self_pid || pid == 4)
                return TRUE;

            if (ctx->seen->count(pid))
                return TRUE;

            if (detections::modules::is_allowed_pid(pid))
                return TRUE;

            hit h{};
            h.pid      = pid;
            h.window   = window;
            h.affinity = affinity;
            get_exe_for_pid(pid, h.process_name, 260);

            ctx->seen->insert(pid);
            ctx->results->push_back(h);
            return TRUE;
        }
    }

    std::vector<hit> scan(DWORD fivem_pid, DWORD self_pid)
    {
        std::vector<hit> results;
        std::unordered_set<DWORD> seen;

        scan_context ctx{ fivem_pid, self_pid, &seen, &results };
        LI_USER32(EnumWindows)(enum_windows_proc, reinterpret_cast<LPARAM>(&ctx));
        return results;
    }
}