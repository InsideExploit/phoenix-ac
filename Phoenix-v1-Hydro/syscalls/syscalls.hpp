#pragma once

#include <Windows.h>
#include <winternl.h>

namespace syscalls
{
    using nt_query_information_process_t = NTSTATUS (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    using nt_query_system_information_t  = NTSTATUS (NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    using nt_set_information_thread_t    = NTSTATUS (NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
    using nt_close_t                     = NTSTATUS (NTAPI*)(HANDLE);
    using nt_get_context_thread_t        = NTSTATUS (NTAPI*)(HANDLE, PCONTEXT);
    using nt_query_object_t              = NTSTATUS (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

    extern nt_query_information_process_t nt_query_information_process;
    extern nt_query_system_information_t  nt_query_system_information;
    extern nt_set_information_thread_t    nt_set_information_thread;
    extern nt_close_t                     nt_close;
    extern nt_get_context_thread_t        nt_get_context_thread;
    extern nt_query_object_t              nt_query_object;

    bool init();
}
