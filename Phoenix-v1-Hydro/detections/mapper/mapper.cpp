#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <winsvc.h>
#include <psapi.h>

#include "mapper.hpp"
#include "vendor/lazy_importer.hpp"
#include "vendor/xor_string.hpp"

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <fstream>
#include <string>


namespace detections::mapper
{
    namespace
    {
        constexpr SIZE_T k_min_exec_size = 0x1000;
        constexpr int    k_host_proc_count = 4;

        struct host_process { const wchar_t* name; };

        host_process host_proc(int i)
        {
            switch (i)
            {
            case 0: return { XSW(L"ctfmon.exe") };
            case 1: return { XSW(L"RuntimeBroker.exe") };
            case 2: return { XSW(L"SecurityHealthSystray.exe") };
            case 3: return { XSW(L"shellhost.exe") };
            }
            return { nullptr };
        }

        bool read_pe_headers_from_disk(const std::wstring& path,
                                       IMAGE_DOS_HEADER& dos,
                                       IMAGE_NT_HEADERS64& nt)
        {
            std::ifstream file(path, std::ios::binary);
            if (!file.is_open())
                return false;

            file.read(reinterpret_cast<char*>(&dos), sizeof(dos));
            if (!file || dos.e_magic != IMAGE_DOS_SIGNATURE)
                return false;

            file.seekg(dos.e_lfanew, std::ios::beg);
            file.read(reinterpret_cast<char*>(&nt), sizeof(nt));
            if (!file || nt.Signature != IMAGE_NT_SIGNATURE)
                return false;

            return true;
        }

        bool pe_matches_disk(HANDLE process, uintptr_t base)
        {
            if (!process || !base)
                return false;

            wchar_t mapped[MAX_PATH]{};
            const DWORD got = K32GetMappedFileNameW(process, reinterpret_cast<LPVOID>(base),
                                                 mapped, MAX_PATH);
            if (got == 0)
                return false;

            wchar_t dos_path[MAX_PATH]{};
            wcsncpy_s(dos_path, XSW(L"\\\\?\\GLOBALROOT"), _TRUNCATE);
            wcsncat_s(dos_path, mapped, _TRUNCATE);

            IMAGE_DOS_HEADER file_dos{};
            IMAGE_NT_HEADERS64 file_nt{};
            if (!read_pe_headers_from_disk(dos_path, file_dos, file_nt))
                return false;

            IMAGE_DOS_HEADER mem_dos{};
            SIZE_T read = 0;
            if (!LI_KERNEL(ReadProcessMemory)(process, reinterpret_cast<LPCVOID>(base),
                                   &mem_dos, sizeof(mem_dos), &read)
                || read != sizeof(mem_dos))
                return false;

            if (mem_dos.e_magic  != file_dos.e_magic)   return false;
            if (mem_dos.e_lfanew != file_dos.e_lfanew)  return false;

            IMAGE_NT_HEADERS64 mem_nt{};
            if (!LI_KERNEL(ReadProcessMemory)(process,
                                   reinterpret_cast<LPCVOID>(base + mem_dos.e_lfanew),
                                   &mem_nt, sizeof(mem_nt), &read)
                || read != sizeof(mem_nt))
                return false;

            if (mem_nt.Signature                       != file_nt.Signature)                       return false;
            if (mem_nt.FileHeader.Machine              != file_nt.FileHeader.Machine)              return false;
            if (mem_nt.FileHeader.NumberOfSections     != file_nt.FileHeader.NumberOfSections)     return false;
            if (mem_nt.OptionalHeader.Magic            != file_nt.OptionalHeader.Magic)            return false;
            if (mem_nt.OptionalHeader.SizeOfImage      != file_nt.OptionalHeader.SizeOfImage)      return false;
            return true;
        }

        bool path_in_system32(const wchar_t* path)
        {
            if (!path || !*path)
                return false;

            wchar_t lower[MAX_PATH * 2]{};
            wcsncpy_s(lower, path, MAX_PATH * 2 - 1);
            for (wchar_t* p = lower; *p; ++p)
                *p = towlower(*p);

            static const wchar_t* const k_subs[] = { XSW(L"\\system32\\"), XSW(L"\\syswow64\\") };
            for (auto sub : k_subs)
            {
                if (wcsstr(lower, sub) != nullptr)
                    return true;
            }
            return false;
        }

        void enumerate_pids_by_name(const wchar_t* name, DWORD* out_pids, int cap, int* out_count)
        {
            *out_count = 0;

            HANDLE snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
            if (snapshot == INVALID_HANDLE_VALUE)
                return;

            PROCESSENTRY32W pe{};
            pe.dwSize = sizeof(pe);
            if (LI_KERNEL(Process32FirstW)(snapshot, &pe))
            {
                do
                {
                    if (_wcsicmp(pe.szExeFile, name) == 0 && *out_count < cap)
                        out_pids[(*out_count)++] = pe.th32ProcessID;
                } while (LI_KERNEL(Process32NextW)(snapshot, &pe));
            }
            LI_KERNEL(CloseHandle)(snapshot);
        }

        bool peek_region(HANDLE process, LPCVOID base, void* out_buffer, SIZE_T size)
        {
            SIZE_T got = 0;
            if (!LI_KERNEL(ReadProcessMemory)(process, base, out_buffer, size, &got))
                return false;
            return got == size;
        }

        bool region_looks_like_pe(HANDLE process, LPCVOID base, SIZE_T region_size)
        {
            if (region_size < 0x200)
                return false;

            uint8_t header[0x100]{};
            const SIZE_T peek_size = (region_size < sizeof(header)) ? region_size : sizeof(header);
            if (!peek_region(process, base, header, peek_size))
                return false;

            if (header[0] != 'M' || header[1] != 'Z')
                return false;

            const LONG lfanew = *reinterpret_cast<const LONG*>(header + 0x3C);
            if (lfanew <= 0 || static_cast<SIZE_T>(lfanew) >= region_size - 4)
                return false;

            uint8_t pe_marker[4]{};
            if (!peek_region(process,
                             reinterpret_cast<const uint8_t*>(base) + lfanew,
                             pe_marker, sizeof(pe_marker)))
                return false;

            return pe_marker[0] == 'P' && pe_marker[1] == 'E' && pe_marker[2] == 0 && pe_marker[3] == 0;
        }

        bool add_hit(hit* out_buffer, int cap, int* count,
                     hit_type type, uint64_t address,
                     uint32_t region_size, uint32_t pid,
                     const wchar_t* format, ...)
        {
            if (*count >= cap)
                return false;

            hit& entry = out_buffer[*count];
            entry.type        = type;
            entry.address     = address;
            entry.region_size = region_size;
            entry.pid         = pid;

            va_list args;
            va_start(args, format);
            _vsnwprintf_s(entry.detail, _countof(entry.detail), _TRUNCATE, format, args);
            va_end(args);

            (*count)++;
            return true;
        }

        void check_mapper_mutex(hit* out_buffer, int cap, int* count)
        {
            HANDLE mutex = LI_KERNEL(OpenMutexW)(SYNCHRONIZE, FALSE, XSW(L"Global\\ApplicationFrameHost_64"));
            if (!mutex)
                return;
            LI_KERNEL(CloseHandle)(mutex);
            add_hit(out_buffer, cap, count, hit_type::mapper_mutex,
                    0, 0, 0,
                    XSW(L"mutex found: Global\\ApplicationFrameHost_64"));
        }

        void check_diag_track_service(hit* out_buffer, int cap, int* count)
        {
            SC_HANDLE manager = LI_ADVAPI(OpenSCManagerW)(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (!manager)
                return;

            SC_HANDLE service = LI_ADVAPI(OpenServiceW)(manager, XSW(L"DiagTrack"), SERVICE_QUERY_CONFIG);
            LI_ADVAPI(CloseServiceHandle)(manager);
            if (!service)
                return;

            DWORD needed = 0;
            LI_ADVAPI(QueryServiceConfigW)(service, nullptr, 0, &needed);
            if (needed > 0 && needed <= 8192)
            {
                auto* buffer = static_cast<QUERY_SERVICE_CONFIGW*>(
                    HeapAlloc(GetProcessHeap(), 0, needed));
                if (buffer)
                {
                    if (LI_ADVAPI(QueryServiceConfigW)(service, buffer, needed, &needed))
                    {
                        const wchar_t* binary_path = buffer->lpBinaryPathName;
                        if (binary_path && *binary_path)
                        {
                            wchar_t lower[MAX_PATH * 2]{};
                            wcsncpy_s(lower, binary_path, MAX_PATH * 2 - 1);
                            for (wchar_t* p = lower; *p; ++p)
                                *p = towlower(*p);

                            if (wcsstr(lower, XSW(L"svchost")) == nullptr)
                            {
                                add_hit(out_buffer, cap, count,
                                        hit_type::diagtrack_fake,
                                        0, 0, 0,
                                        XSW(L"DiagTrack BinaryPath='%.140s'"), binary_path);
                            }
                        }
                    }
                    HeapFree(GetProcessHeap(), 0, buffer);
                }
            }
            LI_ADVAPI(CloseServiceHandle)(service);

            HKEY key = nullptr;
            const LSTATUS open = LI_ADVAPI(RegOpenKeyExW)(HKEY_LOCAL_MACHINE,
                XSW(L"SYSTEM\\CurrentControlSet\\Services\\DiagTrack\\Parameters"),
                0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key);
            if (open != ERROR_SUCCESS)
                return;

            wchar_t dll[MAX_PATH * 2]{};
            DWORD type = 0;
            DWORD size = sizeof(dll) - sizeof(wchar_t);
            const LSTATUS query = LI_ADVAPI(RegQueryValueExW)(key, XSW(L"ServiceDll"), nullptr, &type,
                                                   reinterpret_cast<LPBYTE>(dll), &size);
            LI_ADVAPI(RegCloseKey)(key);
            if (query != ERROR_SUCCESS)
                return;
            if (type != REG_EXPAND_SZ && type != REG_SZ)
                return;

            wchar_t expanded[MAX_PATH * 2]{};
            LI_KERNEL(ExpandEnvironmentStringsW)(dll, expanded, _countof(expanded));

            wchar_t lower[MAX_PATH * 2]{};
            wcsncpy_s(lower, expanded, _countof(lower) - 1);
            for (wchar_t* p = lower; *p; ++p)
                *p = towlower(*p);

            const bool in_system32 = (wcsstr(lower, XSW(L"\\system32\\")) != nullptr);
            const bool is_diagtrack = (wcsstr(lower, XSW(L"diagtrack.dll")) != nullptr);

            if (!in_system32 || !is_diagtrack)
            {
                add_hit(out_buffer, cap, count,
                        hit_type::diagtrack_service_dll,
                        0, 0, 0,
                        XSW(L"DiagTrack ServiceDll='%.140s'"), expanded);
            }
        }

        void check_svchost_service_dlls(hit* out_buffer, int cap, int* count)
        {
            SC_HANDLE manager = LI_ADVAPI(OpenSCManagerW)(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
            if (!manager)
                return;

            DWORD needed = 0;
            DWORD returned = 0;
            DWORD resume = 0;
            LI_ADVAPI(EnumServicesStatusExW)(manager, SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32_SHARE_PROCESS, SERVICE_STATE_ALL,
                nullptr, 0, &needed, &returned, &resume, nullptr);
            if (needed == 0 || needed > 1024 * 1024)
            {
                LI_ADVAPI(CloseServiceHandle)(manager);
                return;
            }

            auto* buffer = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), 0, needed));
            if (!buffer)
            {
                LI_ADVAPI(CloseServiceHandle)(manager);
                return;
            }

            resume = 0;
            if (!LI_ADVAPI(EnumServicesStatusExW)(manager, SC_ENUM_PROCESS_INFO,
                    SERVICE_WIN32_SHARE_PROCESS, SERVICE_STATE_ALL,
                    buffer, needed, &needed, &returned, &resume, nullptr))
            {
                HeapFree(GetProcessHeap(), 0, buffer);
                LI_ADVAPI(CloseServiceHandle)(manager);
                return;
            }

            auto* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer);
            for (DWORD i = 0; i < returned && *count < cap; ++i)
            {
                const wchar_t* svc_name = services[i].lpServiceName;
                if (!svc_name)
                    continue;

                wchar_t reg_path[256]{};
                swprintf_s(reg_path,
                           XSW(L"SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters"),
                           svc_name);

                HKEY key = nullptr;
                if (LI_ADVAPI(RegOpenKeyExW)(HKEY_LOCAL_MACHINE, reg_path, 0,
                                  KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
                    continue;

                wchar_t dll[MAX_PATH * 2]{};
                DWORD type = 0;
                DWORD size = sizeof(dll) - sizeof(wchar_t);
                const LSTATUS query = LI_ADVAPI(RegQueryValueExW)(key, XSW(L"ServiceDll"), nullptr, &type,
                                                       reinterpret_cast<LPBYTE>(dll), &size);
                LI_ADVAPI(RegCloseKey)(key);

                if (query != ERROR_SUCCESS)
                    continue;
                if (type != REG_EXPAND_SZ && type != REG_SZ)
                    continue;

                wchar_t expanded[MAX_PATH * 2]{};
                LI_KERNEL(ExpandEnvironmentStringsW)(dll, expanded, _countof(expanded));

                if (!path_in_system32(expanded))
                {
                    add_hit(out_buffer, cap, count,
                            hit_type::svchost_svc_dll_hijack,
                            0, 0, 0,
                            XSW(L"svc='%s' ServiceDll='%.100s'"), svc_name, expanded);
                }
            }

            HeapFree(GetProcessHeap(), 0, buffer);
            LI_ADVAPI(CloseServiceHandle)(manager);
        }

        void scan_host_process(const wchar_t* proc_name, DWORD pid,
                               hit* out_buffer, int cap, int* count)
        {
            HANDLE process = LI_KERNEL(OpenProcess)(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
            if (!process)
                return;

            int pe_hits = 0;
            int shellcode_hits = 0;
            int generic_hits = 0;

            LPVOID address = nullptr;
            MEMORY_BASIC_INFORMATION mbi{};

            while (LI_KERNEL(VirtualQueryEx)(process, address, &mbi, sizeof(mbi)) == sizeof(mbi))
            {
                constexpr DWORD exec_mask = PAGE_EXECUTE | PAGE_EXECUTE_READ
                                          | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

                const bool is_priv_exec = mbi.State == MEM_COMMIT
                                       && mbi.Type == MEM_PRIVATE
                                       && (mbi.Protect & exec_mask);

                if (is_priv_exec)
                {
                    const uint64_t base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
                    const uint32_t size = static_cast<uint32_t>(mbi.RegionSize);

                    if ((mbi.Protect & PAGE_EXECUTE_READWRITE)
                        && mbi.RegionSize >= 0x1000
                        && mbi.RegionSize <= 0x10000
                        && shellcode_hits < 2)
                    {
                        add_hit(out_buffer, cap, count,
                                hit_type::shellcode_region,
                                base, size, pid,
                                XSW(L"%s pid=%lu RWX base=0x%llX size=0x%lX (loader/shellcode)"),
                                proc_name,
                                static_cast<unsigned long>(pid),
                                static_cast<unsigned long long>(base),
                                static_cast<unsigned long>(size));
                        ++shellcode_hits;
                    }

                    if (mbi.RegionSize >= k_min_exec_size
                        && region_looks_like_pe(process, mbi.BaseAddress, mbi.RegionSize)
                        && !pe_matches_disk(process, reinterpret_cast<uintptr_t>(mbi.BaseAddress))
                        && pe_hits < 3)
                    {
                        add_hit(out_buffer, cap, count,
                                hit_type::host_process_mapped_pe,
                                base, size, pid,
                                XSW(L"%s pid=%lu PE@0x%llX size=0x%lX (manual mapped DLL)"),
                                proc_name,
                                static_cast<unsigned long>(pid),
                                static_cast<unsigned long long>(base),
                                static_cast<unsigned long>(size));
                        ++pe_hits;
                    }

                    if (mbi.RegionSize >= k_min_exec_size && generic_hits < 4)
                    {
                        const hit_type type = (_wcsicmp(proc_name, XSW(L"ctfmon.exe")) == 0)
                                              ? hit_type::ctfmon_exec_mem
                                              : hit_type::host_process_priv_exec;

                        add_hit(out_buffer, cap, count, type, base, size, pid,
                                XSW(L"%s pid=%lu base=0x%llX size=0x%lX prot=0x%lX"),
                                proc_name,
                                static_cast<unsigned long>(pid),
                                static_cast<unsigned long long>(base),
                                static_cast<unsigned long>(size),
                                static_cast<unsigned long>(mbi.Protect));
                        ++generic_hits;
                    }
                }

                if (mbi.RegionSize == 0)
                    break;
                address = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
            }

            LI_KERNEL(CloseHandle)(process);
        }

        void check_host_processes_memory(hit* out_buffer, int cap, int* count)
        {
            for (int j = 0; j < k_host_proc_count; ++j)
            {
                host_process hp = host_proc(j);
                DWORD pids[8] = {};
                int found = 0;
                enumerate_pids_by_name(hp.name, pids, 8, &found);
                for (int i = 0; i < found && *count < cap; ++i)
                    scan_host_process(hp.name, pids[i], out_buffer, cap, count);
            }
        }

        bool is_private_or_loopback(DWORD ip_network_order)
        {
            uint8_t b[4];
            std::memcpy(b, &ip_network_order, 4);

            if (b[0] == 127) return true;
            if (b[0] == 10)  return true;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
            if (b[0] == 192 && b[1] == 168) return true;
            if (b[0] == 169 && b[1] == 254) return true;
            if (b[0] == 0)   return true;
            return false;
        }

        void check_host_processes_network(hit* out_buffer, int cap, int* count)
        {
            struct watch_entry { DWORD pid; const wchar_t* name; };
            watch_entry watch[32] = {};
            int watch_count = 0;

            for (int j = 0; j < k_host_proc_count; ++j)
            {
                host_process hp = host_proc(j);
                DWORD pids[4] = {};
                int found = 0;
                enumerate_pids_by_name(hp.name, pids, 4, &found);
                for (int i = 0; i < found && watch_count < 32; ++i)
                    watch[watch_count++] = { pids[i], hp.name };
            }

            if (watch_count == 0)
                return;

            DWORD size = 0;
            if (LI_IPHLPAPI(GetExtendedTcpTable)(nullptr, &size, FALSE, AF_INET,
                                    TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
                return;
            if (size == 0 || size > 4 * 1024 * 1024)
                return;

            auto* buffer = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), 0, size));
            if (!buffer)
                return;

            const DWORD status = LI_IPHLPAPI(GetExtendedTcpTable)(buffer, &size, FALSE, AF_INET,
                                                     TCP_TABLE_OWNER_PID_ALL, 0);
            if (status != NO_ERROR)
            {
                HeapFree(GetProcessHeap(), 0, buffer);
                return;
            }

            auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer);
            for (DWORD i = 0; i < table->dwNumEntries && *count < cap; ++i)
            {
                const auto& row = table->table[i];

                if (row.dwState != MIB_TCP_STATE_ESTAB && row.dwState != MIB_TCP_STATE_SYN_SENT)
                    continue;
                if (is_private_or_loopback(row.dwRemoteAddr))
                    continue;

                for (int w = 0; w < watch_count; ++w)
                {
                    if (watch[w].pid != row.dwOwningPid)
                        continue;

                    uint8_t ip[4];
                    std::memcpy(ip, &row.dwRemoteAddr, 4);
                    const USHORT port = ntohs(static_cast<u_short>(row.dwRemotePort));

                    add_hit(out_buffer, cap, count,
                            hit_type::host_process_net_io,
                            0, 0, row.dwOwningPid,
                            XSW(L"%s pid=%lu TCP->%u.%u.%u.%u:%u"),
                            watch[w].name,
                            static_cast<unsigned long>(row.dwOwningPid),
                            ip[0], ip[1], ip[2], ip[3], port);
                    break;
                }
            }
            HeapFree(GetProcessHeap(), 0, buffer);
        }

        bool is_globally_whitelisted(const wchar_t* proc_name)
        {
            static const wchar_t* const k_whitelist[] = {
                XSW(L"System"), XSW(L"Registry"), XSW(L"smss.exe"), XSW(L"csrss.exe"), XSW(L"wininit.exe"),
                XSW(L"winlogon.exe"), XSW(L"services.exe"), XSW(L"lsass.exe"), XSW(L"svchost.exe"),
                XSW(L"MsMpEng.exe"), XSW(L"NisSrv.exe"), XSW(L"SecurityHealthService.exe"),
                XSW(L"SearchIndexer.exe"), XSW(L"MsSense.exe"), XSW(L"SenseIR.exe"),
                XSW(L"WmiPrvSE.exe"), XSW(L"dllhost.exe"), XSW(L"conhost.exe"), XSW(L"ShellExperienceHost.exe"),
                XSW(L"chrome.exe"), XSW(L"msedge.exe"), XSW(L"firefox.exe"), XSW(L"brave.exe"), XSW(L"opera.exe"),
                XSW(L"Discord.exe"), XSW(L"Code.exe"), XSW(L"devenv.exe"), XSW(L"MSBuild.exe"),
                XSW(L"ServiceHub.Host.exe"), XSW(L"ServiceHub.Host.netfx.x86.exe"),
                XSW(L"ServiceHub.IdentityHost.exe"), XSW(L"ServiceHub.Host.AnyCPU.exe"),
                XSW(L"ServiceHub.SettingsHost.exe"), XSW(L"ServiceHub.RoslynCodeAnalysisService.exe"),
                XSW(L"PerfWatson2.exe"), XSW(L"powershell.exe"), XSW(L"pwsh.exe"),
                XSW(L"FiveM.exe"), XSW(L"FiveM_GTAProcess.exe"), XSW(L"FiveM_b2944_GTAProcess.exe"),
                XSW(L"FiveM_ChromeBrowser.exe"), XSW(L"module.exe"),
            };
            for (auto w : k_whitelist)
            {
                if (_wcsicmp(proc_name, w) == 0)
                    return true;
            }
            return false;
        }

        bool is_private_non_shared(HANDLE process, LPCVOID base)
        {
            PSAPI_WORKING_SET_EX_INFORMATION wsi{};
            wsi.VirtualAddress = const_cast<LPVOID>(base);
            if (!K32QueryWorkingSetEx(process, &wsi, sizeof(wsi)))
                return false;
            if (!wsi.VirtualAttributes.Valid)
                return false;
            if (wsi.VirtualAttributes.Shared)
                return false;
            return true;
        }

        bool looks_like_erased_mapped_dll(HANDLE process, LPCVOID base, SIZE_T region_size)
        {
            if (region_size < 0x1000)
                return false;
            if (!is_private_non_shared(process, base))
                return false;

            uint8_t buffer[128]{};
            SIZE_T got = 0;
            if (!LI_KERNEL(ReadProcessMemory)(process, base, buffer, sizeof(buffer), &got) || got < 16)
                return false;

            for (SIZE_T i = 0; i + 3 < got; ++i)
            {
                if (buffer[i] && buffer[i + 1] && buffer[i + 2] && buffer[i + 3])
                    return true;
            }
            return false;
        }

        [[maybe_unused]] void scan_process_global(const wchar_t* proc_name, DWORD pid,
                                                  hit* out_buffer, int cap, int* count)
        {
            HANDLE process = LI_KERNEL(OpenProcess)(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (!process)
                return;

            HMODULE modules[1024];
            DWORD needed = 0;
            int module_count = 0;

            struct mod_range { uintptr_t base, end; };
            mod_range mod_ranges[1024];

            if (K32EnumProcessModules(process, modules, sizeof(modules), &needed))
            {
                const DWORD count_mods = needed / sizeof(HMODULE);
                for (DWORD i = 0; i < count_mods && module_count < 1024; ++i)
                {
                    MODULEINFO info{};
                    if (K32GetModuleInformation(process, modules[i], &info, sizeof(info)))
                    {
                        mod_ranges[module_count].base = reinterpret_cast<uintptr_t>(info.lpBaseOfDll);
                        mod_ranges[module_count].end  = mod_ranges[module_count].base + info.SizeOfImage;
                        ++module_count;
                    }
                }
            }

            int pe_hits = 0;
            int erased_hits = 0;

            LPVOID address = nullptr;
            MEMORY_BASIC_INFORMATION mbi{};

            while (LI_KERNEL(VirtualQueryEx)(process, address, &mbi, sizeof(mbi)) == sizeof(mbi)
                   && reinterpret_cast<uintptr_t>(address) < 0x00007FFFFFFFFFFFULL)
            {
                if (mbi.State != MEM_COMMIT)
                {
                    if (mbi.RegionSize == 0)
                        break;
                    address = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
                    continue;
                }

                constexpr DWORD exec_mask = PAGE_EXECUTE | PAGE_EXECUTE_READ
                                          | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
                if (!(mbi.Protect & exec_mask) || mbi.RegionSize < 0x5000)
                {
                    if (mbi.RegionSize == 0)
                        break;
                    address = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
                    continue;
                }

                const uintptr_t base_address = reinterpret_cast<uintptr_t>(mbi.BaseAddress);

                bool in_module = false;
                for (int i = 0; i < module_count; ++i)
                {
                    if (base_address >= mod_ranges[i].base && base_address < mod_ranges[i].end)
                    {
                        in_module = true;
                        break;
                    }
                }

                if (!in_module)
                {
                    const uint64_t base = static_cast<uint64_t>(base_address);
                    const uint32_t size = static_cast<uint32_t>(mbi.RegionSize);

                    if (region_looks_like_pe(process, mbi.BaseAddress, mbi.RegionSize)
                        && !pe_matches_disk(process, reinterpret_cast<uintptr_t>(mbi.BaseAddress))
                        && pe_hits < 2)
                    {
                        add_hit(out_buffer, cap, count,
                                hit_type::any_process_mapped_pe,
                                base, size, pid,
                                XSW(L"%s pid=%lu PE@0x%llX size=0x%lX"),
                                proc_name,
                                static_cast<unsigned long>(pid),
                                static_cast<unsigned long long>(base),
                                static_cast<unsigned long>(size));
                        ++pe_hits;
                    }
                    else if (looks_like_erased_mapped_dll(process, mbi.BaseAddress, mbi.RegionSize)
                             && erased_hits < 2)
                    {
                        add_hit(out_buffer, cap, count,
                                hit_type::any_process_erased_pe,
                                base, size, pid,
                                XSW(L"%s pid=%lu erased@0x%llX size=0x%lX"),
                                proc_name,
                                static_cast<unsigned long>(pid),
                                static_cast<unsigned long long>(base),
                                static_cast<unsigned long>(size));
                        ++erased_hits;
                    }
                }

                if (mbi.RegionSize == 0)
                    break;
                address = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
            }

            LI_KERNEL(CloseHandle)(process);
        }

        [[maybe_unused]] void check_all_processes_global(hit* out_buffer, int cap, int* count)
        {
            HANDLE snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
            if (snapshot == INVALID_HANDLE_VALUE)
                return;

            PROCESSENTRY32W pe{};
            pe.dwSize = sizeof(pe);
            if (LI_KERNEL(Process32FirstW)(snapshot, &pe))
            {
                do
                {
                    if (*count >= cap)
                        break;
                    if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4)
                        continue;
                    if (is_globally_whitelisted(pe.szExeFile))
                        continue;
                    if (pe.th32ProcessID == LI_KERNEL(GetCurrentProcessId)())
                        continue;

                    scan_process_global(pe.szExeFile, pe.th32ProcessID, out_buffer, cap, count);
                } while (LI_KERNEL(Process32NextW)(snapshot, &pe));
            }
            LI_KERNEL(CloseHandle)(snapshot);
        }

        bool read_file_dos_nt_headers(const wchar_t* path,
                                      IMAGE_DOS_HEADER* out_dos,
                                      IMAGE_NT_HEADERS* out_nt)
        {
            HANDLE file = CreateFileW(path, GENERIC_READ,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE)
                return false;

            DWORD got = 0;
            if (!ReadFile(file, out_dos, sizeof(*out_dos), &got, nullptr)
                || got != sizeof(*out_dos)
                || out_dos->e_magic != IMAGE_DOS_SIGNATURE)
            {
                LI_KERNEL(CloseHandle)(file);
                return false;
            }

            if (SetFilePointer(file, out_dos->e_lfanew, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
            {
                LI_KERNEL(CloseHandle)(file);
                return false;
            }

            if (!ReadFile(file, out_nt, sizeof(*out_nt), &got, nullptr)
                || got != sizeof(*out_nt)
                || out_nt->Signature != IMAGE_NT_SIGNATURE)
            {
                LI_KERNEL(CloseHandle)(file);
                return false;
            }

            LI_KERNEL(CloseHandle)(file);
            return true;
        }

        void scan_process_modules_integrity(const wchar_t* proc_name, DWORD pid,
                                            hit* out_buffer, int cap, int* count)
        {
            HANDLE process = LI_KERNEL(OpenProcess)(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (!process)
                return;

            HMODULE modules[1024];
            DWORD needed = 0;
            if (!K32EnumProcessModules(process, modules, sizeof(modules), &needed))
            {
                LI_KERNEL(CloseHandle)(process);
                return;
            }

            const DWORD module_count = needed / sizeof(HMODULE);
            int hits = 0;

            for (DWORD i = 0; i < module_count && hits < 2 && *count < cap; ++i)
            {
                wchar_t path[MAX_PATH * 2]{};
                if (!K32GetModuleFileNameExW(process, modules[i], path, MAX_PATH * 2))
                    continue;

                IMAGE_DOS_HEADER mem_dos{};
                IMAGE_NT_HEADERS mem_nt{};
                SIZE_T got = 0;

                if (!LI_KERNEL(ReadProcessMemory)(process, modules[i], &mem_dos, sizeof(mem_dos), &got)
                    || got != sizeof(mem_dos)
                    || mem_dos.e_magic != IMAGE_DOS_SIGNATURE)
                    continue;

                BYTE* nt_address = reinterpret_cast<BYTE*>(modules[i]) + mem_dos.e_lfanew;
                if (!LI_KERNEL(ReadProcessMemory)(process, nt_address, &mem_nt, sizeof(mem_nt), &got)
                    || got != sizeof(mem_nt)
                    || mem_nt.Signature != IMAGE_NT_SIGNATURE)
                    continue;

                IMAGE_DOS_HEADER file_dos{};
                IMAGE_NT_HEADERS file_nt{};
                if (!read_file_dos_nt_headers(path, &file_dos, &file_nt))
                    continue;

                const bool mismatch =
                    (mem_dos.e_lfanew                     != file_dos.e_lfanew)
                 || (mem_nt.FileHeader.Machine            != file_nt.FileHeader.Machine)
                 || (mem_nt.FileHeader.NumberOfSections   != file_nt.FileHeader.NumberOfSections)
                 || (mem_nt.OptionalHeader.Magic          != file_nt.OptionalHeader.Magic)
                 || (mem_nt.OptionalHeader.SizeOfImage    != file_nt.OptionalHeader.SizeOfImage);

                if (mismatch)
                {
                    const wchar_t* slash = wcsrchr(path, L'\\');
                    const wchar_t* base_name = slash ? slash + 1 : path;

                    add_hit(out_buffer, cap, count,
                            hit_type::module_stomped,
                            reinterpret_cast<uint64_t>(modules[i]),
                            mem_nt.OptionalHeader.SizeOfImage, pid,
                            XSW(L"%s pid=%lu mod='%s' mem(secs=%u img=0x%lX) file(secs=%u img=0x%lX)"),
                            proc_name,
                            static_cast<unsigned long>(pid),
                            base_name,
                            static_cast<unsigned>(mem_nt.FileHeader.NumberOfSections),
                            static_cast<unsigned long>(mem_nt.OptionalHeader.SizeOfImage),
                            static_cast<unsigned>(file_nt.FileHeader.NumberOfSections),
                            static_cast<unsigned long>(file_nt.OptionalHeader.SizeOfImage));
                    ++hits;
                }
            }

            LI_KERNEL(CloseHandle)(process);
        }

        void check_modules_integrity_global(hit* out_buffer, int cap, int* count)
        {
            for (int j = 0; j < k_host_proc_count; ++j)
            {
                host_process hp = host_proc(j);
                DWORD pids[8] = {};
                int found = 0;
                enumerate_pids_by_name(hp.name, pids, 8, &found);
                for (int i = 0; i < found && *count < cap; ++i)
                    scan_process_modules_integrity(hp.name, pids[i], out_buffer, cap, count);
            }
        }

        void check_netsh_helpers(hit* out_buffer, int cap, int* count)
        {
            HKEY key = nullptr;
            if (LI_ADVAPI(RegOpenKeyExW)(HKEY_LOCAL_MACHINE,
                              XSW(L"SOFTWARE\\Microsoft\\NetSh"), 0,
                              KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
                return;

            DWORD index = 0;
            while (*count < cap)
            {
                wchar_t value_name[256]{};
                wchar_t value_data[MAX_PATH * 2]{};
                DWORD name_length = _countof(value_name);
                DWORD data_length = sizeof(value_data) - sizeof(wchar_t);
                DWORD type = 0;

                const LSTATUS status = LI_ADVAPI(RegEnumValueW)(key, index++, value_name, &name_length,
                                                     nullptr, &type,
                                                     reinterpret_cast<LPBYTE>(value_data), &data_length);
                if (status == ERROR_NO_MORE_ITEMS)
                    break;
                if (status != ERROR_SUCCESS)
                    continue;
                if (type != REG_SZ && type != REG_EXPAND_SZ)
                    continue;
                if (data_length == 0 || value_data[0] == L'\0')
                    continue;

                wchar_t expanded[MAX_PATH * 2]{};
                if (type == REG_EXPAND_SZ)
                    LI_KERNEL(ExpandEnvironmentStringsW)(value_data, expanded, _countof(expanded));
                else
                    wcsncpy_s(expanded, value_data, _TRUNCATE);

                wchar_t lower[MAX_PATH * 2]{};
                wcsncpy_s(lower, expanded, _TRUNCATE);
                for (wchar_t* p = lower; *p; ++p)
                    *p = towlower(*p);

                if (wcschr(lower, L'\\') == nullptr)
                    continue;

                const bool in_system = (wcsstr(lower, XSW(L"\\system32\\")) != nullptr)
                                    || (wcsstr(lower, XSW(L"\\syswow64\\")) != nullptr);

                const size_t length = wcslen(lower);
                const bool is_dll = (length >= 4 && wcscmp(lower + length - 4, XSW(L".dll")) == 0);

                if (in_system && is_dll)
                    continue;

                add_hit(out_buffer, cap, count,
                        hit_type::netsh_helper_hijack,
                        0, 0, 0,
                        XSW(L"NetSh value '%s' -> '%.160s'"), value_name, expanded);
            }

            LI_ADVAPI(RegCloseKey)(key);
        }
    }

    void scan(hit* out_buffer, int buffer_capacity, int* out_count)
    {
        *out_count = 0;
        check_mapper_mutex(out_buffer, buffer_capacity, out_count);
        check_diag_track_service(out_buffer, buffer_capacity, out_count);
        check_svchost_service_dlls(out_buffer, buffer_capacity, out_count);
        check_host_processes_memory(out_buffer, buffer_capacity, out_count);
        check_host_processes_network(out_buffer, buffer_capacity, out_count);
        check_modules_integrity_global(out_buffer, buffer_capacity, out_count);
        check_netsh_helpers(out_buffer, buffer_capacity, out_count);
    }
}
