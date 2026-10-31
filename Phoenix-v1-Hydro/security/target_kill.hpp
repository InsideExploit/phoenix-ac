#pragma once

#include "vendor/xorstr.hpp"

#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <cstdint>
#include <string>

namespace security::target_kill
{
    using nt_terminate_process_t = NTSTATUS (NTAPI*)(HANDLE, NTSTATUS);

    inline bool query_target(DWORD pid, std::wstring& out_path, std::wstring& out_name)
    {
        out_path.clear();
        out_name.clear();

        if (HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid))
        {
            wchar_t buffer[MAX_PATH] = {};
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageNameW(process, 0, buffer, &size))
            {
                out_path = buffer;
                const wchar_t* slash = wcsrchr(buffer, L'\\');
                out_name = slash ? (slash + 1) : buffer;
            }
            CloseHandle(process);
        }

        if (out_name.empty())
        {
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot != INVALID_HANDLE_VALUE)
            {
                PROCESSENTRY32W pe{};
                pe.dwSize = sizeof(pe);
                if (Process32FirstW(snapshot, &pe))
                {
                    do
                    {
                        if (pe.th32ProcessID == pid)
                        {
                            out_name = pe.szExeFile;
                            break;
                        }
                    } while (Process32NextW(snapshot, &pe));
                }
                CloseHandle(snapshot);
            }
        }

        return !out_name.empty();
    }

    inline bool kill_process(DWORD pid)
    {
        if (pid == 0 || pid == GetCurrentProcessId() || pid == 4)
            return false;

        bool killed = false;

        if (HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, pid))
        {
            killed = TerminateProcess(process, 1) != FALSE;
            CloseHandle(process);
        }

        if (!killed)
        {
            if (HMODULE ntdll = GetModuleHandleW(xorstr(L"ntdll.dll")))
            {
                auto nt_terminate = reinterpret_cast<nt_terminate_process_t>(
                    GetProcAddress(ntdll, xorstr("NtTerminateProcess")));
                if (HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, pid))
                {
                    if (nt_terminate)
                        killed = nt_terminate(process, 1) >= 0;
                    CloseHandle(process);
                }
            }
        }

        return killed;
    }

    inline DWORD pid_from_hwnd(HWND window)
    {
        DWORD pid = 0;
        if (window)
            GetWindowThreadProcessId(window, &pid);
        return pid;
    }
}
