#include "anti_debug.hpp"

#include "security/security_core.hpp"
#include "syscalls/syscalls.hpp"
#include "vendor/lazy_importer.hpp"
#include "vendor/oreans/include/VirtualizerSDK.h"
#pragma auto_inline(off)
#include "vendor/xor_string.hpp"

#include <Windows.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <winternl.h>

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <intrin.h>

namespace anti_debug
{
    namespace
    {
        constexpr ULONG k_info_debug_port          = 7;
        constexpr ULONG k_info_debug_object_handle = 30;
        constexpr ULONG k_thread_hide_from_debugger = 0x11;
        constexpr ULONG k_info_kernel_debugger     = 35;
        constexpr ULONG k_info_extended_handles    = 64;
        constexpr ULONG k_status_info_length_mismatch = 0xC0000004u;

        struct handle_table_entry
        {
            PVOID     object;
            ULONG_PTR unique_process_id;
            ULONG_PTR handle_value;
            ULONG     granted_access;
            USHORT    creator_back_trace_index;
            USHORT    object_type_index;
            ULONG     handle_attributes;
            ULONG     reserved;
        };

        struct handle_info_ex
        {
            ULONG_PTR          number_of_handles;
            ULONG_PTR          reserved;
            handle_table_entry handles[1];
        };

        struct kernel_debugger_info
        {
            BOOLEAN kernel_debugger_enabled;
            BOOLEAN kernel_debugger_not_present;
        };

        struct watchdog_shared_state
        {
            volatile ULONG64 last_tick;
            volatile ULONG   sequence;
            volatile DWORD   parent_pid;
            volatile DWORD   armed;
        };

        std::atomic<bool>       g_trigger_fired{ false };
        volatile HANDLE         g_watchdog_handle   = nullptr;
        volatile bool           g_watchdog_attached = false;
        volatile DWORD          g_watchdog_pid      = 0;
        HANDLE                  g_shm_handle        = nullptr;
        watchdog_shared_state*  g_shm               = nullptr;

        const wchar_t* shm_name()
        {
            return XSW(L"Local\\Module_WD_HB");
        }

        [[noreturn]] void fast_terminate(DWORD code)
        {
            __fastfail(code);
        }

        void trigger_layer(int layer)
        {
            g_trigger_fired.store(true, std::memory_order_relaxed);
            LI_KERNEL(Sleep)(200);
            security::core::kill_layer(static_cast<unsigned int>(layer));
            fast_terminate(0xDEAD0000u | static_cast<DWORD>(layer));
        }

        PPEB current_peb()
        {
            return reinterpret_cast<PPEB>(__readgsqword(0x60));
        }

        __declspec(noinline) bool check_peb_being_debugged()
        {
            VIRTUALIZER_START;
            volatile bool r = current_peb()->BeingDebugged != 0;
            VIRTUALIZER_END;
            return r;
        }

        __declspec(noinline) bool check_peb_nt_global_flag()
        {
            VIRTUALIZER_START;
            const ULONG flag = *reinterpret_cast<ULONG*>(reinterpret_cast<BYTE*>(current_peb()) + 0xBC);
            volatile bool r = (flag & 0x70) != 0;
            VIRTUALIZER_END;
            return r;
        }

        __declspec(noinline) bool check_debug_port()
        {
            VIRTUALIZER_START;
            HANDLE port = nullptr;
            const NTSTATUS status = syscalls::nt_query_information_process(
                reinterpret_cast<HANDLE>(-1), k_info_debug_port,
                &port, sizeof(port), nullptr);
            volatile bool r = status >= 0 && port != nullptr;
            VIRTUALIZER_END;
            return r;
        }

        __declspec(noinline) bool check_debug_object()
        {
            VIRTUALIZER_START;
            HANDLE handle = nullptr;
            const NTSTATUS status = syscalls::nt_query_information_process(
                reinterpret_cast<HANDLE>(-1), k_info_debug_object_handle,
                &handle, sizeof(handle), nullptr);
            volatile bool r = status >= 0 && handle != nullptr;
            VIRTUALIZER_END;
            return r;
        }

        bool check_remote_debugger()
        {
            BOOL debugged = FALSE;
            CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged);
            return debugged != FALSE;
        }

        bool check_ntclose_exception()
        {
            __try
            {
                syscalls::nt_close(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(0xDEADBEEFu)));
                return false;
            }
            __except (GetExceptionCode() == 0xC0000008
                          ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
            {
                return true;
            }
        }

        bool check_hardware_breakpoints()
        {
            const DWORD self_pid = LI_KERNEL(GetCurrentProcessId)();
            const DWORD self_tid = LI_KERNEL(GetCurrentThreadId)();

            HANDLE snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPTHREAD, 0);
            if (snapshot == INVALID_HANDLE_VALUE)
            {
                return false;
            }

            bool found = false;
            THREADENTRY32 te{};
            te.dwSize = sizeof(te);

            for (BOOL ok = LI_KERNEL(Thread32First)(snapshot, &te); ok && !found; ok = LI_KERNEL(Thread32Next)(snapshot, &te))
            {
                if (te.th32OwnerProcessID != self_pid)
                    continue;
                if (te.th32ThreadID == self_tid)
                    continue;

                HANDLE thread = LI_KERNEL(OpenThread)(THREAD_GET_CONTEXT, FALSE, te.th32ThreadID);
                if (!thread)
                    continue;

                CONTEXT ctx{};
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

                if (syscalls::nt_get_context_thread(thread, &ctx) >= 0)
                {
                    if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3)
                        found = true;
                }
                LI_KERNEL(CloseHandle)(thread);
            }

            LI_KERNEL(CloseHandle)(snapshot);
            return found;
        }

        __declspec(noinline) bool check_kernel_debugger()
        {
            VIRTUALIZER_START;
            kernel_debugger_info info{};
            const NTSTATUS status = syscalls::nt_query_system_information(
                k_info_kernel_debugger, &info, sizeof(info), nullptr);
            volatile bool r = status >= 0
                && info.kernel_debugger_enabled
                && !info.kernel_debugger_not_present;
            VIRTUALIZER_END;
            return r;
        }

        bool check_debugger_module_loaded()
        {
            const wchar_t* const suspicious[] = {
                XSW(L"scyllahide.dll"), XSW(L"scyllahidex64.dll"),
                XSW(L"titanhide.dll"),  XSW(L"hyperhide.dll"),
                XSW(L"vehdebugger.dll"),
                XSW(L"x64dbg.dll"), XSW(L"x32dbg.dll"),
                XSW(L"snxhk.dll"),
                XSW(L"sbiedll.dll"),
                XSW(L"cuckoomon.dll"),
                XSW(L"api_log.dll"),
                XSW(L"dir_watch.dll"),
                XSW(L"vmcheck.dll"),
            };

            HMODULE modules[1024];
            DWORD needed = 0;
            HANDLE process = LI_KERNEL(GetCurrentProcess)();

            if (!K32EnumProcessModulesEx(process, modules, sizeof(modules), &needed, LIST_MODULES_ALL))
            {
                return false;
            }

            const DWORD count = needed / sizeof(HMODULE);
            for (DWORD i = 0; i < count; ++i)
            {
                wchar_t name[MAX_PATH];
                if (!K32GetModuleBaseNameW(process, modules[i], name, MAX_PATH))
                    continue;
                for (const wchar_t* candidate : suspicious)
                {
                    if (_wcsicmp(name, candidate) == 0)
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        __declspec(noinline) bool is_system_process(const wchar_t* name)
        {
            VIRTUALIZER_START;
            static const wchar_t* const k_system[] = {
                XSW(L"System"), XSW(L"Registry"), XSW(L"smss.exe"), XSW(L"csrss.exe"), XSW(L"wininit.exe"),
                XSW(L"services.exe"), XSW(L"lsass.exe"), XSW(L"winlogon.exe"), XSW(L"dwm.exe"),
                XSW(L"svchost.exe"), XSW(L"fontdrvhost.exe"), XSW(L"taskhostw.exe"),
                XSW(L"MsMpEng.exe"), XSW(L"SecurityHealthService.exe"), XSW(L"SearchIndexer.exe"),
                XSW(L"NisSrv.exe"), XSW(L"audiodg.exe"), XSW(L"conhost.exe"),
                XSW(L"explorer.exe"), XSW(L"RuntimeBroker.exe"),
            };
            for (const wchar_t* s : k_system)
            {
                if (_wcsicmp(name, s) == 0)
                    return true;
            }
            VIRTUALIZER_END;
            return false;
        }

        __declspec(noinline) bool pid_to_name(DWORD pid, wchar_t* out, DWORD out_chars)
        {
            VIRTUALIZER_START;
            HANDLE process = LI_KERNEL(OpenProcess)(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!process)
            {
                return false;
            }

            wchar_t path[MAX_PATH];
            DWORD size = MAX_PATH;
            auto query_name = LI_KERNEL(QueryFullProcessImageNameW);
            const BOOL ok = query_name(process, 0, path, &size);
            LI_KERNEL(CloseHandle)(process);
            if (!ok)
            {
                return false;
            }

            const wchar_t* slash = wcsrchr(path, L'\\');
            const wchar_t* name  = slash ? slash + 1 : path;
            wcsncpy_s(out, out_chars, name, _TRUNCATE);
            VIRTUALIZER_END;
            return true;
        }

        bool check_external_reader()
        {
            const DWORD self_pid = LI_KERNEL(GetCurrentProcessId)();
            ULONG buf_size = 1024 * 1024;
            BYTE* buffer = nullptr;
            NTSTATUS status = 0;

            for (int attempt = 0; attempt < 6; ++attempt)
            {
                if (buffer)
                    free(buffer);
                buffer = static_cast<BYTE*>(malloc(buf_size));
                if (!buffer)
                {
                    return false;
                }

                ULONG returned = 0;
                status = syscalls::nt_query_system_information(
                    k_info_extended_handles, buffer, buf_size, &returned);
                if (status >= 0)
                    break;
                if (static_cast<ULONG>(status) == k_status_info_length_mismatch)
                {
                    buf_size *= 2;
                    if (buf_size > 64u * 1024u * 1024u)
                    {
                        free(buffer);
                        return false;
                    }
                    continue;
                }
                free(buffer);
                return false;
            }

            if (status < 0)
            {
                if (buffer)
                    free(buffer);
                return false;
            }

            auto* info = reinterpret_cast<handle_info_ex*>(buffer);
            bool found = false;
            constexpr ULONG k_suspicious_access = PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
            const DWORD watchdog_pid = g_watchdog_pid;
            auto open_process = LI_KERNEL(OpenProcess);
            auto duplicate_handle = LI_KERNEL(DuplicateHandle);
            auto get_current_process = LI_KERNEL(GetCurrentProcess);
            auto get_process_id = LI_KERNEL(GetProcessId);
            auto close_handle = LI_KERNEL(CloseHandle);

            for (ULONG_PTR i = 0; i < info->number_of_handles && !found; ++i)
            {
                auto& entry = info->handles[i];
                const DWORD source_pid = static_cast<DWORD>(entry.unique_process_id);

                if (source_pid == self_pid || source_pid == 0 || source_pid == 4)
                    continue;
                if (watchdog_pid && source_pid == watchdog_pid)
                    continue;
                if (!(entry.granted_access & k_suspicious_access))
                    continue;

                HANDLE source_process = open_process(PROCESS_DUP_HANDLE, FALSE, source_pid);
                if (!source_process)
                    continue;

                HANDLE duplicate = nullptr;
                if (duplicate_handle(source_process, reinterpret_cast<HANDLE>(entry.handle_value),
                                     get_current_process(), &duplicate, 0, FALSE,
                                     DUPLICATE_SAME_ACCESS))
                {
                    if (get_process_id(duplicate) == self_pid)
                    {
                        wchar_t name[MAX_PATH] = {};
                        const bool has_name = pid_to_name(source_pid, name, MAX_PATH);
                        if (!has_name || !is_system_process(name))
                            found = true;
                    }
                    close_handle(duplicate);
                }
                close_handle(source_process);
            }

            free(buffer);
            return found;
        }

        bool check_debugger_parent()
        {
            const DWORD self_pid = LI_KERNEL(GetCurrentProcessId)();
            HANDLE snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
            if (snapshot == INVALID_HANDLE_VALUE)
            {
                return false;
            }

            PROCESSENTRY32W pe{};
            pe.dwSize = sizeof(pe);
            DWORD parent = 0;

            for (BOOL ok = LI_KERNEL(Process32FirstW)(snapshot, &pe); ok; ok = LI_KERNEL(Process32NextW)(snapshot, &pe))
            {
                if (pe.th32ProcessID == self_pid)
                {
                    parent = pe.th32ParentProcessID;
                    break;
                }
            }

            if (!parent)
            {
                LI_KERNEL(CloseHandle)(snapshot);
                return false;
            }

            bool bad_parent = false;
            pe.dwSize = sizeof(pe);
            for (BOOL ok = LI_KERNEL(Process32FirstW)(snapshot, &pe); ok; ok = LI_KERNEL(Process32NextW)(snapshot, &pe))
            {
                if (pe.th32ProcessID != parent)
                    continue;

                static const wchar_t* const k_bad_parents[] = {
                    XSW(L"x64dbg.exe"),  XSW(L"x32dbg.exe"),
                    XSW(L"windbg.exe"),  XSW(L"windbgx.exe"),
                    XSW(L"ida.exe"),     XSW(L"ida64.exe"), XSW(L"idaq.exe"), XSW(L"idaq64.exe"),
                    XSW(L"ollydbg.exe"), XSW(L"immunitydebugger.exe"),
                    XSW(L"devenv.exe"),
                    XSW(L"radare2.exe"), XSW(L"r2.exe"), XSW(L"cutter.exe"),
                    XSW(L"cheatengine.exe"), XSW(L"cheatengine-x86_64.exe"), XSW(L"cheatengine-i386.exe"),
                    XSW(L"pe-sieve64.exe"), XSW(L"pe-sieve32.exe"),
                    XSW(L"reclass.exe"), XSW(L"reclass.net.exe"),
                    XSW(L"binaryninja.exe"), XSW(L"binja.exe"),
                };

                for (const wchar_t* b : k_bad_parents)
                {
                    if (_wcsicmp(pe.szExeFile, b) == 0)
                    {
                        bad_parent = true;
                        break;
                    }
                }
                break;
            }

            LI_KERNEL(CloseHandle)(snapshot);
            return bad_parent;
        }

#pragma optimize("", off)
        __declspec(noinline) bool heartbeat_stale()
        {
            VIRTUALIZER_START;
            if (!g_shm || !g_watchdog_attached || !g_shm->armed)
                return false;

            const ULONG64 now  = GetTickCount64();
            const ULONG64 last = g_shm->last_tick;
            if (last == 0)
                return false;

            bool r = now > last && (now - last) > 2500;
            VIRTUALIZER_END;
            return r;
        }
#pragma optimize("", on)

        __declspec(noinline) void run_all_scans()
        {
            VIRTUALIZER_START;
            if (check_peb_being_debugged()) trigger_layer(0);
            if (check_debug_port())         trigger_layer(3);
            if (check_debug_object())       trigger_layer(4);
            if (check_remote_debugger())    trigger_layer(6);
            if (check_ntclose_exception())  trigger_layer(7);
            if (check_peb_nt_global_flag())     trigger_layer(1);
            if (check_hardware_breakpoints())   trigger_layer(8);
            if (check_kernel_debugger())        trigger_layer(9);
            if (check_debugger_module_loaded()) trigger_layer(12);
            if (check_debugger_parent())        trigger_layer(13);
            if (check_external_reader())        trigger_layer(20);
            VIRTUALIZER_END;
        }

        __declspec(noinline) DWORD WINAPI watcher_thread(LPVOID)
        {
            VIRTUALIZER_START;
            if (syscalls::nt_set_information_thread)
                syscalls::nt_set_information_thread(GetCurrentThread(),
                                                    k_thread_hide_from_debugger, nullptr, 0);

            uint32_t seed = static_cast<uint32_t>(GetTickCount()) ^ 0x9E3779B9u
                          ^ static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&watcher_thread));
            VIRTUALIZER_END;

            for (;;)
            {
                seed = seed * 1664525u + 1013904223u;
                const DWORD sleep_ms = 250 + (seed % 750);
                LI_KERNEL(Sleep)(sleep_ms);

                run_all_scans();

                if (g_watchdog_attached && g_watchdog_handle)
                {
                    DWORD code = 0;
                    auto get_exit_code = LI_KERNEL(GetExitCodeProcess);
                    if (get_exit_code(g_watchdog_handle, &code) && code != STILL_ACTIVE)
                        trigger_layer(18);
                }
                if (heartbeat_stale())
                    trigger_layer(21);
            }
        }

        __declspec(noinline) bool enable_debug_priv()
        {
            VIRTUALIZER_START;
            HANDLE token = nullptr;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
            {
                return false;
            }

            LUID luid{};
            if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid))
            {
                LI_KERNEL(CloseHandle)(token);
                return false;
            }

            TOKEN_PRIVILEGES tp{};
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            const BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
            const DWORD last_error = GetLastError();
            LI_KERNEL(CloseHandle)(token);
            const bool r = ok && last_error == ERROR_SUCCESS;
            VIRTUALIZER_END;
            return r;
        }

        __declspec(noinline) bool init_shared_memory()
        {
            VIRTUALIZER_START;
            auto create_file_mapping = LI_KERNEL(CreateFileMappingW);
            g_shm_handle = create_file_mapping(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
                                               0, sizeof(watchdog_shared_state), shm_name());
            if (!g_shm_handle)
            {
                return false;
            }

            auto map_view = LI_KERNEL(MapViewOfFile);
            g_shm = static_cast<watchdog_shared_state*>(
                map_view(g_shm_handle, FILE_MAP_READ | FILE_MAP_WRITE,
                         0, 0, sizeof(watchdog_shared_state)));
            if (!g_shm)
            {
                LI_KERNEL(CloseHandle)(g_shm_handle);
                g_shm_handle = nullptr;
                return false;
            }

            g_shm->last_tick  = GetTickCount64();
            g_shm->sequence   = 0;
            g_shm->parent_pid = LI_KERNEL(GetCurrentProcessId)();
            g_shm->armed      = 0;
            VIRTUALIZER_END;
            return true;
        }

        __declspec(noinline) void spawn_watchdog()
        {
            VIRTUALIZER_START;
            wchar_t self_path[MAX_PATH]{};
            if (!LI_KERNEL(GetModuleFileNameW)(nullptr, self_path, MAX_PATH))
            {
                return;
            }

            init_shared_memory();

            HANDLE ready_event = CreateEventW(nullptr, TRUE, FALSE, XSW(L"Local\\Module_WD_Ready"));

            wchar_t command[MAX_PATH + 64];
            swprintf_s(command, XSW(L"\"%s\" --watchdog %lu"),
                       self_path, LI_KERNEL(GetCurrentProcessId)());

            STARTUPINFOW si{};
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;

            PROCESS_INFORMATION pi{};
            auto create_process = LI_KERNEL(CreateProcessW);
            if (!create_process(nullptr, command, nullptr, nullptr, FALSE,
                                CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
            {
                if (ready_event)
                    LI_KERNEL(CloseHandle)(ready_event);
                return;
            }

            LI_KERNEL(CloseHandle)(pi.hThread);
            g_watchdog_handle = pi.hProcess;
            g_watchdog_pid    = pi.dwProcessId;

            if (ready_event)
            {
                if (WaitForSingleObject(ready_event, 5000) == WAIT_OBJECT_0)
                    g_watchdog_attached = true;
                LI_KERNEL(CloseHandle)(ready_event);
            }
            VIRTUALIZER_END;
        }

        DWORD WINAPI heartbeat_thread(LPVOID arg)
        {
            auto* state = static_cast<watchdog_shared_state*>(arg);
            for (;;)
            {
                state->last_tick = GetTickCount64();
                InterlockedIncrement(&state->sequence);
                LI_KERNEL(Sleep)(500);
            }
        }
    }

    __declspec(noinline) void start()
    {
        VIRTUALIZER_START;
        if (!syscalls::init())
        {
            return;
        }

#ifndef _DEBUG
        run_all_scans();

        spawn_watchdog();

        auto create_thread = LI_KERNEL(CreateThread);
        if (HANDLE thread = create_thread(nullptr, 0, watcher_thread, nullptr, 0, nullptr))
        {
            LI_KERNEL(CloseHandle)(thread);
        }
        else
        {
        }
#else
#endif
        VIRTUALIZER_END;
    }

    __declspec(noinline) int run_watchdog(DWORD parent_pid)
    {
        VIRTUALIZER_START;

        HANDLE ready_event = OpenEventW(EVENT_MODIFY_STATE, FALSE, XSW(L"Local\\Module_WD_Ready"));

        HANDLE shm_handle = OpenFileMappingW(FILE_MAP_WRITE, FALSE, shm_name());
        watchdog_shared_state* shm = nullptr;
        if (shm_handle)
        {
            shm = static_cast<watchdog_shared_state*>(
                LI_KERNEL(MapViewOfFile)(shm_handle, FILE_MAP_WRITE, 0, 0, sizeof(watchdog_shared_state)));
        }

        HANDLE parent = LI_KERNEL(OpenProcess)(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                                    FALSE, parent_pid);
        if (!parent)
        {
            if (shm)         LI_KERNEL(UnmapViewOfFile)(shm);
            if (shm_handle)  LI_KERNEL(CloseHandle)(shm_handle);
            if (ready_event) LI_KERNEL(CloseHandle)(ready_event);
            return 1;
        }

        if (shm)
        {
            shm->last_tick = GetTickCount64();
            shm->armed = 1;
            if (HANDLE hb_thread = LI_KERNEL(CreateThread)(nullptr, 0, heartbeat_thread, shm, 0, nullptr))
                LI_KERNEL(CloseHandle)(hb_thread);
        }

        if (ready_event)
        {
            SetEvent(ready_event);
            LI_KERNEL(CloseHandle)(ready_event);
        }
        VIRTUALIZER_END;

        for (;;)
        {
            if (WaitForSingleObject(parent, 1000) == WAIT_OBJECT_0)
                break;
        }

        LI_KERNEL(CloseHandle)(parent);
        return 0;
    }
}
