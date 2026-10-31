#pragma once

#include "security/detonator.hpp"
#include "vendor/xorstr.hpp"

#include <Windows.h>
#include <TlHelp32.h>
#include <atomic>
#include <chrono>
#include <intrin.h>
#include <thread>

namespace security::harden
{
    inline std::atomic<bool> g_halt{ false };
    inline std::atomic<bool> g_tripped{ false };

    inline bool is_running_under_vm()
    {
        int cpu_info[4] = {};
        __cpuid(cpu_info, 1);
        if ((cpu_info[2] & (1 << 31)) != 0)
            return true;

        __cpuid(cpu_info, 0x40000000);
        char vendor[13] = {};
        memcpy(vendor + 0, &cpu_info[1], 4);
        memcpy(vendor + 4, &cpu_info[2], 4);
        memcpy(vendor + 8, &cpu_info[3], 4);

        const char* known[] = {
            "KVMKVMKVM\0\0",
            "Microsoft Hv",
            "VMwareVMware",
            "XenVMMXenVMM",
            "prl hyperv  ",
            "VBoxVBoxVBox",
            "TCGTCGTCGTCG",
        };
        for (const char* v : known)
        {
            if (memcmp(vendor, v, 12) == 0)
                return true;
        }
        return false;
    }

    inline bool has_hardware_breakpoints()
    {
        const DWORD self_pid = GetCurrentProcessId();
        const DWORD self_tid = GetCurrentThreadId();

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return false;

        bool found = false;
        THREADENTRY32 te{};
        te.dwSize = sizeof(te);

        if (Thread32First(snapshot, &te))
        {
            do
            {
                if (te.th32OwnerProcessID != self_pid)
                    continue;
                if (te.th32ThreadID == self_tid)
                    continue;

                HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                                           FALSE, te.th32ThreadID);
                if (!thread)
                    continue;

                CONTEXT ctx{};
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

                SuspendThread(thread);
                if (GetThreadContext(thread, &ctx))
                {
                    if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3)
                        found = true;
                }
                ResumeThread(thread);
                CloseHandle(thread);

                if (found)
                    break;
            } while (Thread32Next(snapshot, &te));
        }

        CloseHandle(snapshot);
        return found;
    }

    inline void watchdog()
    {
        while (!g_halt.load(std::memory_order_relaxed))
        {
            if (has_hardware_breakpoints() && !g_tripped.exchange(true))
            {
                security::detonator::trigger(
                    xorstr("Harden"),
                    xorstr("hardware breakpoint detected"));
                return;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        }
    }

    inline void start()
    {
        std::thread(watchdog).detach();
    }

    inline void stop()
    {
        g_halt.store(true, std::memory_order_relaxed);
    }
}
