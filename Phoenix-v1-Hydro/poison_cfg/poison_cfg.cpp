#include "poison_cfg.hpp"
#include "vendor/lazy_importer.hpp"
#include "vendor/xor_string.hpp"
#include <Windows.h>
namespace poison_cfg
{
    namespace
    {
        uint32_t extract_ssn(BYTE* stub)
        {
            if (!stub)
                return 0;

            if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8)
                return *reinterpret_cast<uint32_t*>(stub + 4);

            for (int i = 0; i < 24; ++i)
            {
                if (stub[i] == 0xB8 && stub[i + 5] == 0x0F && stub[i + 6] == 0x05)
                    return *reinterpret_cast<uint32_t*>(stub + i + 1);
            }

            return 0;
        }
    }

    syscall_numbers resolve_syscall_numbers()
    {
        syscall_numbers out{};

        HMODULE ntdll = LI_KERNEL(GetModuleHandleW)(XSW(L"ntdll.dll"));
        if (!ntdll)
            return out;

        out.nt_read_virtual_memory       = extract_ssn(reinterpret_cast<BYTE*>(LI_KERNEL(GetProcAddress)(ntdll, XS("NtReadVirtualMemory"))));
        out.nt_query_information_process = extract_ssn(reinterpret_cast<BYTE*>(LI_KERNEL(GetProcAddress)(ntdll, XS("NtQueryInformationProcess"))));

        return out;
    }
}