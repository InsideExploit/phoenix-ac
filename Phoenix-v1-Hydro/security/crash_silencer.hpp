#pragma once

#include <Windows.h>
#include <werapi.h>
#include <csignal>
#include <cstdint>
#include <cstdlib>

#pragma comment(lib, "wer.lib")

namespace security::crash_silencer
{
    inline LONG WINAPI silent_filter(EXCEPTION_POINTERS*)
    {
        TerminateProcess(GetCurrentProcess(), 0);
        return EXCEPTION_EXECUTE_HANDLER;
    }

    inline void invalid_parameter_handler(const wchar_t*, const wchar_t*, const wchar_t*, unsigned int, uintptr_t)
    {
        TerminateProcess(GetCurrentProcess(), 0);
    }

    inline void purecall_handler()
    {
        TerminateProcess(GetCurrentProcess(), 0);
    }

    inline void signal_handler(int)
    {
        TerminateProcess(GetCurrentProcess(), 0);
    }

    inline void install()
    {
        SetErrorMode(SEM_FAILCRITICALERRORS
                     | SEM_NOGPFAULTERRORBOX
                     | SEM_NOOPENFILEERRORBOX
                     | SEM_NOALIGNMENTFAULTEXCEPT);

        WerSetFlags(WER_FAULT_REPORTING_NO_UI | WER_FAULT_REPORTING_FLAG_QUEUE_UPLOAD);

        wchar_t host_path[MAX_PATH] = {};
        const DWORD length = GetModuleFileNameW(nullptr, host_path, MAX_PATH);
        if (length > 0 && length < MAX_PATH)
            WerAddExcludedApplication(host_path, FALSE);

        SetUnhandledExceptionFilter(silent_filter);
        _set_invalid_parameter_handler(invalid_parameter_handler);
        _set_purecall_handler(purecall_handler);
        _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);

        signal(SIGABRT, signal_handler);
        signal(SIGFPE,  signal_handler);
        signal(SIGILL,  signal_handler);
        signal(SIGSEGV, signal_handler);
    }
}
