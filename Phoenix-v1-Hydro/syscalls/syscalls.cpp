#include "syscalls.hpp"
#include "vendor/lazy_importer.hpp"
#include "vendor/xor_string.hpp"
#include <Windows.h>
#include <cstring>
#include <mutex>
namespace syscalls
{
    nt_query_information_process_t nt_query_information_process = nullptr;
    nt_query_system_information_t  nt_query_system_information  = nullptr;
    nt_set_information_thread_t    nt_set_information_thread    = nullptr;
    nt_close_t                     nt_close                     = nullptr;
    nt_get_context_thread_t        nt_get_context_thread        = nullptr;
    nt_query_object_t              nt_query_object              = nullptr;

    namespace
    {
        constexpr size_t k_stub_page_size = 4096;
        constexpr size_t k_stub_size      = 21;

        PVOID       g_stub_page   = nullptr;
        size_t      g_stub_offset = 0;
        std::mutex  g_stub_mutex;

        PVOID find_syscall_gadget(HMODULE ntdll)
        {
            auto get_proc_address = LI_KERNEL(GetProcAddress);
            BYTE* p = reinterpret_cast<BYTE*>(get_proc_address(ntdll, XS("NtClose")));
            if (!p)
            {
                return nullptr;
            }

            for (int i = 0; i < 32; ++i)
            {
                if (p[i] == 0x0F && p[i + 1] == 0x05)
                {
                    return p + i;
                }
            }
            return nullptr;
        }

        DWORD extract_ssn(BYTE* fn)
        {
            if (!fn)
                return 0;
            if (fn[0] != 0x4C || fn[1] != 0x8B || fn[2] != 0xD1)
                return 0;
            if (fn[3] != 0xB8)
                return 0;

            DWORD ssn = 0;
            std::memcpy(&ssn, fn + 4, 4);
            return ssn;
        }

        PVOID emit_stub(DWORD ssn, PVOID gadget)
        {
            std::lock_guard<std::mutex> lock(g_stub_mutex);

            if (!g_stub_page)
            {
                auto virtual_alloc = LI_KERNEL(VirtualAlloc);
                g_stub_page = virtual_alloc(nullptr, k_stub_page_size,
                                            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (!g_stub_page)
                {
                    return nullptr;
                }
            }

            if (g_stub_offset + k_stub_size > k_stub_page_size)
                return nullptr;

            BYTE* target = static_cast<BYTE*>(g_stub_page) + g_stub_offset;
            BYTE stub[k_stub_size] = {
                0x4C, 0x8B, 0xD1,
                0xB8, 0,0,0,0,
                0x49, 0xBB, 0,0,0,0,0,0,0,0,
                0x41, 0xFF, 0xE3
            };
            std::memcpy(stub + 4,  &ssn,    4);
            std::memcpy(stub + 10, &gadget, 8);
            std::memcpy(target, stub, sizeof(stub));

            g_stub_offset += sizeof(stub);
            return target;
        }
    }

    bool init()
    {
        auto get_module_handle = LI_KERNEL(GetModuleHandleW);
        HMODULE ntdll = get_module_handle(XSW(L"ntdll.dll"));
        if (!ntdll)
        {
            return false;
        }

        PVOID gadget = find_syscall_gadget(ntdll);
        if (!gadget)
        {
            return false;
        }

        auto get_proc_address = LI_KERNEL(GetProcAddress);

        auto resolve = [&](const char* name) -> PVOID {
            BYTE* fn = reinterpret_cast<BYTE*>(get_proc_address(ntdll, name));
            DWORD ssn = extract_ssn(fn);
            if (!ssn)
                return nullptr;
            return emit_stub(ssn, gadget);
        };

        nt_query_information_process = reinterpret_cast<nt_query_information_process_t>(resolve(XS("NtQueryInformationProcess")));
        nt_query_system_information  = reinterpret_cast<nt_query_system_information_t> (resolve(XS("NtQuerySystemInformation")));
        nt_set_information_thread    = reinterpret_cast<nt_set_information_thread_t>   (resolve(XS("NtSetInformationThread")));
        nt_close                     = reinterpret_cast<nt_close_t>                    (resolve(XS("NtClose")));
        nt_get_context_thread        = reinterpret_cast<nt_get_context_thread_t>       (resolve(XS("NtGetContextThread")));
        nt_query_object              = reinterpret_cast<nt_query_object_t>             (resolve(XS("NtQueryObject")));

        DWORD old_protect = 0;
        auto virtual_protect = LI_KERNEL(VirtualProtect);
        virtual_protect(g_stub_page, k_stub_page_size, PAGE_EXECUTE_READ, &old_protect);

        const bool ok = nt_query_information_process
            && nt_query_system_information
            && nt_set_information_thread
            && nt_close
            && nt_get_context_thread
            && nt_query_object;
        return ok;
    }
}
