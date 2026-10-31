#pragma once

#include "security/detonator.hpp"
#include "security/target_kill.hpp"
#include "vendor/xorstr.hpp"
#include "webhook/webhook.hpp"

#include <Windows.h>
#include <TlHelp32.h>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>

namespace security::sniffer_guard
{
    inline std::atomic<bool> g_halt{ false };
    inline std::atomic<bool> g_tripped{ false };

    struct hit
    {
        bool        detected = false;
        std::string vector;
        std::string detail;
        DWORD       target_pid = 0;
    };

    inline DWORD find_process(const char* exe)
    {
        wchar_t wide[260];
        if (MultiByteToWideChar(CP_ACP, 0, exe, -1, wide, 260) <= 0)
            return 0;

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
                if (_wcsicmp(pe.szExeFile, wide) == 0)
                {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &pe));
        }

        CloseHandle(snapshot);
        return pid;
    }

    inline bool service_running(const char* name)
    {
        SC_HANDLE manager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!manager)
            return false;

        SC_HANDLE service = OpenServiceA(manager, name, SERVICE_QUERY_STATUS);
        if (!service)
        {
            CloseServiceHandle(manager);
            return false;
        }

        SERVICE_STATUS status{};
        const bool running = QueryServiceStatus(service, &status)
                          && status.dwCurrentState == SERVICE_RUNNING;

        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        return running;
    }

    inline bool module_loaded(const wchar_t* module_name)
    {
        return GetModuleHandleW(module_name) != nullptr;
    }

    inline hit scan()
    {
        hit result{};

        const char* processes[] = {
            xorstr("HTTPDebuggerUI.exe"), xorstr("HTTPDebuggerSvc.exe"), xorstr("HTTPDebugger.exe"),
            xorstr("Fiddler.exe"),        xorstr("FiddlerEverywhere.exe"),
            xorstr("Charles.exe"),
            xorstr("Wireshark.exe"),      xorstr("dumpcap.exe"),          xorstr("rawshark.exe"),
            xorstr("Proxifier.exe"),
            xorstr("mitmproxy.exe"),      xorstr("mitmdump.exe"),
            xorstr("BurpSuiteCommunity.exe"), xorstr("BurpSuitePro.exe"),
        };

        for (const char* p : processes)
        {
            if (const DWORD pid = find_process(p))
            {
                result = { true, xorstr("process"), p, pid };
                return result;
            }
        }

        const char* services[] = {
            xorstr("HTTPDebuggerPro"),
            xorstr("HttpDebuggerSdk"),
        };
        for (const char* s : services)
        {
            if (service_running(s))
            {
                result = { true, xorstr("service"), s, 0 };
                return result;
            }
        }

        struct module_pair { const wchar_t* wide; const char* ascii; };
        const module_pair modules[] = {
            { xorstr(L"HttpDebuggerSdk.dll"), xorstr("HttpDebuggerSdk.dll") },
            { xorstr(L"FiddlerCore.dll"),     xorstr("FiddlerCore.dll") },
        };
        for (auto& m : modules)
        {
            if (module_loaded(m.wide))
            {
                result = { true, xorstr("module"), m.ascii, 0 };
                return result;
            }
        }

        return result;
    }

    inline void on_hit(const hit& h)
    {
        if (g_tripped.exchange(true))
            return;

        std::wstring target_path, target_name;
        const bool has_target = (h.target_pid != 0)
                             && security::target_kill::query_target(h.target_pid, target_path, target_name);

        char name_utf8[260] = "-";
        char path_utf8[520] = "-";
        if (has_target)
        {
            if (WideCharToMultiByte(CP_UTF8, 0, target_name.c_str(), -1,
                                    name_utf8, sizeof(name_utf8), nullptr, nullptr) <= 0)
                strcpy_s(name_utf8, "-");
            if (WideCharToMultiByte(CP_UTF8, 0, target_path.c_str(), -1,
                                    path_utf8, sizeof(path_utf8), nullptr, nullptr) <= 0)
                strcpy_s(path_utf8, "-");
        }

        const bool killed = (h.target_pid != 0) ? security::target_kill::kill_process(h.target_pid) : false;

        char body[1024];
        snprintf(body, sizeof(body),
                 "Vector: %s\nMatch:  %s\nPID:    %lu\nImage:  %s\nPath:   %s\nKill:   %s",
                 h.vector.c_str(), h.detail.c_str(),
                 static_cast<unsigned long>(h.target_pid),
                 name_utf8, path_utf8,
                 killed ? "ok" : (h.target_pid ? "FAILED" : "n/a"));

        webhook::report_security(xorstr("SnifferGuard"), h.detail.c_str(), body, 3);
        security::detonator::trigger(xorstr("SnifferGuard"),
                                     std::string(h.vector) + ": " + h.detail);
    }

    inline void watchdog()
    {
        int consecutive = 0;
        std::string last_vector;
        std::string last_detail;

        while (!g_halt.load(std::memory_order_relaxed))
        {
            hit h = scan();
            if (h.detected)
            {
                if (consecutive > 0 && h.vector == last_vector && h.detail == last_detail)
                    ++consecutive;
                else
                {
                    consecutive = 1;
                    last_vector = h.vector;
                    last_detail = h.detail;
                }
                if (consecutive >= 2)
                    on_hit(h);
            }
            else
            {
                consecutive = 0;
                last_vector.clear();
                last_detail.clear();
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(350));
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
