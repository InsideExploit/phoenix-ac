#pragma once

#include "security/detonator.hpp"
#include "security/target_kill.hpp"
#include "vendor/xorstr.hpp"

#include <Windows.h>
#include <TlHelp32.h>
#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>

namespace security::analyst_guard
{
    inline std::atomic<bool> g_halt{ false };
    inline std::atomic<bool> g_tripped{ false };

    inline const wchar_t* const k_analyst_modules[] = {
        L"scyllahide.dll",
        L"titanhide.dll",
        L"hyperhide.dll",
        L"vehdebugger.dll",
        L"x64dbg.dll",
        L"x32dbg.dll",
        L"snxhk.dll",
        L"sbiedll.dll",
        L"cuckoomon.dll",
        L"api_log.dll",
        L"dir_watch.dll",
        L"vmcheck.dll",
    };

    inline bool suspicious_module_loaded(std::wstring& out_name)
    {
        for (const wchar_t* name : k_analyst_modules)
        {
            if (GetModuleHandleW(name))
            {
                out_name = name;
                return true;
            }
        }
        return false;
    }

    inline bool parent_is_debugger()
    {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return false;

        DWORD self_pid   = GetCurrentProcessId();
        DWORD parent_pid = 0;
        std::wstring parent_name;

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);

        if (Process32FirstW(snapshot, &pe))
        {
            do
            {
                if (pe.th32ProcessID == self_pid)
                {
                    parent_pid = pe.th32ParentProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &pe));
        }

        if (parent_pid)
        {
            pe.dwSize = sizeof(pe);
            if (Process32FirstW(snapshot, &pe))
            {
                do
                {
                    if (pe.th32ProcessID == parent_pid)
                    {
                        parent_name = pe.szExeFile;
                        break;
                    }
                } while (Process32NextW(snapshot, &pe));
            }
        }

        CloseHandle(snapshot);

        const wchar_t* const k_debugger_parents[] = {
            L"x64dbg.exe", L"x32dbg.exe", L"windbg.exe", L"windbgx.exe",
            L"ollydbg.exe", L"immunitydebugger.exe",
            L"ida.exe", L"ida64.exe",
        };
        for (const wchar_t* candidate : k_debugger_parents)
        {
            if (_wcsicmp(parent_name.c_str(), candidate) == 0)
                return true;
        }
        return false;
    }

    inline void watchdog()
    {
        while (!g_halt.load(std::memory_order_relaxed))
        {
            std::wstring module_name;
            if (suspicious_module_loaded(module_name) && !g_tripped.exchange(true))
            {
                char ascii[128] = {};
                WideCharToMultiByte(CP_UTF8, 0, module_name.c_str(), -1,
                                    ascii, sizeof(ascii) - 1, nullptr, nullptr);
                security::detonator::trigger(xorstr("AnalystGuard"),
                                             std::string("module: ") + ascii);
                return;
            }

            if (parent_is_debugger() && !g_tripped.exchange(true))
            {
                security::detonator::trigger(xorstr("AnalystGuard"),
                                             xorstr("parent is debugger"));
                return;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(750));
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
