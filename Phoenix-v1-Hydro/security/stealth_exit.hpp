#pragma once

#include "vendor/xorstr.hpp"

#include <Windows.h>
#include <winternl.h>
#include <werapi.h>
#include <cstdint>
#include <cstdlib>

#pragma comment(lib, "wer.lib")

namespace security::stealth_exit
{
    using nt_terminate_process_t = NTSTATUS (NTAPI*)(HANDLE, NTSTATUS);

    inline void suppress_error_dialogs()
    {
        const UINT prev = SetErrorMode(SEM_FAILCRITICALERRORS
                                       | SEM_NOGPFAULTERRORBOX
                                       | SEM_NOOPENFILEERRORBOX
                                       | SEM_NOALIGNMENTFAULTEXCEPT);
        SetErrorMode(prev | SEM_FAILCRITICALERRORS
                          | SEM_NOGPFAULTERRORBOX
                          | SEM_NOOPENFILEERRORBOX);

        wchar_t host_path[MAX_PATH] = {};
        const DWORD length = GetModuleFileNameW(nullptr, host_path, MAX_PATH);
        if (length > 0 && length < MAX_PATH)
            WerAddExcludedApplication(host_path, FALSE);

        WerSetFlags(WER_FAULT_REPORTING_NO_UI | WER_FAULT_REPORTING_FLAG_QUEUE_UPLOAD);
        _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    }

    [[noreturn]] inline void now()
    {
        suppress_error_dialogs();

        TerminateProcess(GetCurrentProcess(), 0);

        if (HMODULE ntdll = GetModuleHandleW(xorstr(L"ntdll.dll")))
        {
            auto nt_terminate = reinterpret_cast<nt_terminate_process_t>(
                GetProcAddress(ntdll, xorstr("NtTerminateProcess")));
            if (nt_terminate)
                nt_terminate(reinterpret_cast<HANDLE>(static_cast<LONG_PTR>(-1)), 0);
        }

        ExitProcess(0);
        for (;;)
            Sleep(INFINITE);
    }
}
