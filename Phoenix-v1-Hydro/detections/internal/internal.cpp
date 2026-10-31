#include "internal.hpp"
#include "vendor/lazy_importer.hpp"
#include "vendor/xor_string.hpp"
#include <TlHelp32.h>
#include <winternl.h>
namespace detections::internal_scan
{
    namespace
    {
        using nt_query_information_thread_t = NTSTATUS (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

        nt_query_information_thread_t nt_query_information_thread()
        {
            static nt_query_information_thread_t fn = reinterpret_cast<nt_query_information_thread_t>(
                LI_KERNEL(GetProcAddress)(LI_KERNEL(GetModuleHandleA)(XS("ntdll.dll")),   
                               XS("NtQueryInformationThread")));
            return fn;
        }

        bool is_executable(DWORD protect)
        {
            protect &= 0xFF;
            return protect == PAGE_EXECUTE
                || protect == PAGE_EXECUTE_READ
                || protect == PAGE_EXECUTE_READWRITE
                || protect == PAGE_EXECUTE_WRITECOPY;
        }
    }

    std::vector<hit> scan(DWORD fivem_pid, HANDLE fivem_handle, uint64_t module_base, int build)
    {
        (void)module_base;
        (void)build;

        std::vector<hit> out;

        auto nt_qit = nt_query_information_thread();

        HANDLE snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return out;

        THREADENTRY32 te{};
        te.dwSize = sizeof(te);

        if (LI_KERNEL(Thread32First)(snapshot, &te))
        {
            do
            {
                if (te.th32OwnerProcessID != fivem_pid)
                    continue;

                HANDLE thread = LI_KERNEL(OpenThread)(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (!thread)
                    continue;

                PVOID start_address = nullptr;
                if (nt_qit)
                    nt_qit(thread, 9, &start_address, sizeof(start_address), nullptr);
                LI_KERNEL(CloseHandle)(thread);

                if (!start_address)
                    continue;

                MEMORY_BASIC_INFORMATION mbi{};
                if (!LI_KERNEL(VirtualQueryEx)(fivem_handle, start_address, &mbi, sizeof(mbi)))
                    continue;

                if (mbi.State == MEM_COMMIT
                    && mbi.Type == MEM_PRIVATE
                    && is_executable(mbi.Protect))
                {
                    hit h{};
                    h.type    = hit_type::injected_thread;
                    h.tid     = te.th32ThreadID;
                    h.address = reinterpret_cast<uint64_t>(start_address);
                    out.push_back(h);
                }
            } while (LI_KERNEL(Thread32Next)(snapshot, &te));
        }

        LI_KERNEL(CloseHandle)(snapshot);
        return out;
    }
}