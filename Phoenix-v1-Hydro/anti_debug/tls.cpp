#include "anti_debug.hpp"
#include "vendor/lazy_importer.hpp"
#include "vendor/xor_string.hpp"
#include <Windows.h>
#include <winternl.h>
namespace
{
    inline PPEB current_peb()
    {
        return reinterpret_cast<PPEB>(__readgsqword(0x60));
    }

    void NTAPI early_tls_check(PVOID, DWORD reason, PVOID)
    {
#ifndef _DEBUG
        if (reason != DLL_PROCESS_ATTACH)
            return;

        PPEB peb = current_peb();
        bool kill = false;

        if (peb->BeingDebugged)
            kill = true;

        if (!kill)
        {
            const ULONG nt_global_flag = *reinterpret_cast<ULONG*>(reinterpret_cast<BYTE*>(peb) + 0xBC);
            if (nt_global_flag & 0x70)
                kill = true;
        }

        if (kill)
            LI_KERNEL(TerminateProcess)(LI_KERNEL(GetCurrentProcess)(), 0xDEADC0DE);
#else
        (void)reason;
#endif
    }
}

extern "C"
{
    #pragma section(".CRT$XLB", long, read)
    __declspec(allocate(".CRT$XLB"))
    PIMAGE_TLS_CALLBACK __ptls_early_check = early_tls_check;
}

#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:__ptls_early_check")