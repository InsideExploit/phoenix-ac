#include "anti_dumper.hpp"

#include "vendor/lazy_importer.hpp"
#include "vendor/oreans/include/VirtualizerSDK.h"
#pragma auto_inline(off)
#include "vendor/xor_string.hpp"
#include "webhook/webhook.hpp"

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <winternl.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <random>
#include <thread>
#include <vector>

namespace anti_dumper
{
    namespace
    {
        std::atomic<bool> g_alive{ false };
        std::atomic<bool> g_armed{ false };
        std::thread       g_thread;

        constexpr uint32_t fnv1a(const char* s, uint32_t h = 2166136261u)
        {
            return *s ? fnv1a(s + 1, (h ^ static_cast<uint8_t>(*s)) * 16777619u) : h;
        }

        bool iequals_wide(const wchar_t* a, const wchar_t* b)
        {
            return _wcsicmp(a, b) == 0;
        }

        __declspec(noinline) bool scan_bad_processes(const wchar_t** out_name)
        {
            VIRTUALIZER_START;
            static const wchar_t* const k_bad_procs[] = {
                XSW(L"x64dbg.exe"), XSW(L"x32dbg.exe"), XSW(L"ollydbg.exe"), XSW(L"immunitydebugger.exe"),
                XSW(L"windbg.exe"), XSW(L"windbgx.exe"), XSW(L"dnspy.exe"), XSW(L"dnspy-x86.exe"),
                XSW(L"ida.exe"), XSW(L"ida64.exe"), XSW(L"idaq.exe"), XSW(L"idaq64.exe"),
                XSW(L"ghidra.exe"), XSW(L"ghidraRun.bat"), XSW(L"binaryninja.exe"),
                XSW(L"procexp.exe"), XSW(L"procexp64.exe"), XSW(L"processhacker.exe"), XSW(L"systeminformer.exe"),
                XSW(L"procmon.exe"), XSW(L"procmon64.exe"), XSW(L"apimonitor.exe"), XSW(L"apimonitor-x64.exe"),
                XSW(L"cheatengine.exe"), XSW(L"cheatengine-x86_64.exe"), XSW(L"cheatengine-i386.exe"),
                XSW(L"ksdumper.exe"), XSW(L"pe-bear.exe"), XSW(L"die.exe"), XSW(L"detect it easy.exe"),
                XSW(L"hxd.exe"), XSW(L"reclass.exe"), XSW(L"reclass.net.exe"),
                XSW(L"scylla.exe"), XSW(L"scyllahide.exe"), XSW(L"x96dbg.exe"),
                XSW(L"fiddler.exe"), XSW(L"wireshark.exe"), XSW(L"httpdebuggerui.exe"),
                XSW(L"ollyice.exe"), XSW(L"lordpe.exe"), XSW(L"resourcehacker.exe"),
                XSW(L"frida.exe"), XSW(L"frida-server.exe"), XSW(L"frida-trace.exe"),
                XSW(L"qemu-system-x86_64.exe"), XSW(L"vboxservice.exe"),
            };

            HANDLE snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
            if (snapshot == INVALID_HANDLE_VALUE)
                return false;

            PROCESSENTRY32W pe{};
            pe.dwSize = sizeof(pe);
            bool found = false;
            static thread_local wchar_t hit_name[64];

            if (LI_KERNEL(Process32FirstW)(snapshot, &pe))
            {
                do
                {
                    for (const wchar_t* candidate : k_bad_procs)
                    {
                        if (iequals_wide(pe.szExeFile, candidate))
                        {
                            wcsncpy_s(hit_name, pe.szExeFile, _TRUNCATE);
                            if (out_name)
                                *out_name = hit_name;
                            found = true;
                            break;
                        }
                    }
                    if (found)
                        break;
                } while (LI_KERNEL(Process32NextW)(snapshot, &pe));
            }

            LI_KERNEL(CloseHandle)(snapshot);
            VIRTUALIZER_END;
            return found;
        }

        __declspec(noinline) bool being_debugged_via_peb()
        {
            VIRTUALIZER_START;
        #ifdef _M_X64
            auto peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
        #else
            auto peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
        #endif
            if (!peb)
                return false;
            volatile bool r = peb->BeingDebugged != 0;
            VIRTUALIZER_END;
            return r;
        }

        __declspec(noinline) bool being_debugged_via_ntqip()
        {
            VIRTUALIZER_START;
            using nt_qip_t = NTSTATUS (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
            auto nt_qip = reinterpret_cast<nt_qip_t>(
                ::li::ntdll_fn<LI_HASH("NtQueryInformationProcess"), nt_qip_t>::get());
            if (!nt_qip)
                return false;

            DWORD_PTR debug_port = 0;
            if (nt_qip(LI_KERNEL(GetCurrentProcess)(), 7, &debug_port, sizeof(debug_port), nullptr) == 0
                && debug_port != 0)
                return true;

            VIRTUALIZER_END;
            return false;
        }

        __declspec(noinline) void detonate(const char* tag, const char* reason, uint32_t code)
        {
            VIRTUALIZER_START;
            bool expected = false;
            if (!g_armed.compare_exchange_strong(expected, true))
                return;

            webhook::report_detonator(tag, reason, code);
            webhook::flush(1500);

            std::random_device rd;
            std::mt19937 rng(rd());
            std::uniform_int_distribution<int> distribution(3000, 7000);
            const int delay_ms = distribution(rng);
            VIRTUALIZER_END;
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));

            __fastfail(7);
        }

        void scan_loop()
        {
            while (g_alive.load(std::memory_order_acquire))
            {
                if (g_armed.load(std::memory_order_acquire))
                    break;

                if (being_debugged_via_peb())
                {
                    detonate(XS("PEB"), XS("BeingDebugged set"), fnv1a("PEB"));
                    break;
                }
                if (being_debugged_via_ntqip())
                {
                    detonate(XS("DbgPort"), XS("ProcessDebugPort != 0"), fnv1a("DbgPort"));
                    break;
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(1500));
            }
        }
    }

    __declspec(noinline) void start()
    {
        VIRTUALIZER_START;
        bool expected = false;
        if (!g_alive.compare_exchange_strong(expected, true))
            return;
        g_thread = std::thread(scan_loop);
        VIRTUALIZER_END;
    }

    void stop()
    {
        g_alive.store(false, std::memory_order_release);
        if (g_thread.joinable())
            g_thread.join();
    }

    bool is_running()
    {
        return g_alive.load();
    }
}
