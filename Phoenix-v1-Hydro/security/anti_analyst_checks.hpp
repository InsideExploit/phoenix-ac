#pragma once

#include "security/detonator.hpp"
#include "security/target_kill.hpp"
#include "vendor/xorstr.hpp"

#include <Windows.h>
#include <TlHelp32.h>
#include <atomic>
#include <chrono>
#include <cstring>
#include <string>
#include <thread>

namespace security::anti_analyst
{
    inline std::atomic<bool> g_halt{ false };
    inline std::atomic<bool> g_tripped{ false };

    inline const wchar_t* const k_analyst_processes[] = {
        L"x64dbg.exe", L"x32dbg.exe", L"x96dbg.exe",
        L"ollydbg.exe", L"immunitydebugger.exe",
        L"windbg.exe", L"windbgx.exe",
        L"ida.exe", L"ida64.exe", L"idaq.exe", L"idaq64.exe",
        L"ghidra.exe", L"binaryninja.exe",
        L"dnspy.exe", L"dnspy-x86.exe",
        L"processhacker.exe", L"systeminformer.exe",
        L"procexp.exe", L"procexp64.exe",
        L"procmon.exe", L"procmon64.exe",
        L"cheatengine.exe", L"cheatengine-x86_64.exe", L"cheatengine-i386.exe",
        L"reclass.exe", L"reclass.net.exe",
        L"scylla.exe", L"scyllahide.exe",
        L"pe-bear.exe", L"die.exe", L"hxd.exe",
        L"frida.exe", L"frida-server.exe", L"frida-trace.exe",
        L"ksdumper.exe",
    };

    inline DWORD find_analyst_process()
    {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return 0;

        DWORD pid = 0;
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);

        if (Process32FirstW(snapshot, &pe))
        {
            do
            {
                for (const wchar_t* name : k_analyst_processes)
                {
                    if (_wcsicmp(pe.szExeFile, name) == 0)
                    {
                        pid = pe.th32ProcessID;
                        break;
                    }
                }
                if (pid)
                    break;
            } while (Process32NextW(snapshot, &pe));
        }

        CloseHandle(snapshot);
        return pid;
    }

    inline bool debugger_class_present()
    {
        static const wchar_t* const k_classes[] = {
            L"OLLYDBG", L"GBDYLLO",
            L"WinDbgFrameClass",
            L"Zeta Debugger", L"Rock Debugger",
            L"ObsidianGUI",
            L"ImmunityDebuggerForm",
            L"x64dbgFrame", L"x32dbgFrame",
        };
        for (const wchar_t* cls : k_classes)
        {
            if (FindWindowW(cls, nullptr))
                return true;
        }
        return false;
    }

    inline void detonate(DWORD pid, const std::wstring& name)
    {
        char ascii[260] = {};
        WideCharToMultiByte(CP_UTF8, 0, name.c_str(), -1,
                            ascii, sizeof(ascii) - 1, nullptr, nullptr);

        std::string reason = "analyst: ";
        reason += ascii;

        if (pid != 0)
            security::target_kill::kill_process(pid);

        security::detonator::trigger(xorstr("AntiAnalyst"), reason);
    }

    inline void watchdog()
    {
        while (!g_halt.load(std::memory_order_relaxed))
        {
            if (const DWORD pid = find_analyst_process())
            {
                std::wstring path, name;
                security::target_kill::query_target(pid, path, name);
                if (!g_tripped.exchange(true))
                {
                    detonate(pid, name.empty() ? std::wstring(L"?") : name);
                    return;
                }
            }

            if (debugger_class_present() && !g_tripped.exchange(true))
            {
                detonate(0, L"debugger_window");
                return;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(600));
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
