#include "baseline.hpp"
#include "vendor/lazy_importer.hpp"
#include "vendor/xor_string.hpp"
#include <Psapi.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <vector>
namespace detections::baseline
{
    namespace
    {
        constexpr size_t k_tolerance_module_count       = 15;
        constexpr size_t k_tolerance_module_weight      = 50 * 1024 * 1024;
        constexpr size_t k_tolerance_unmapped_regions   = 200;
        constexpr size_t k_tolerance_unmapped_size      = 3 * 1024 * 1024;
        constexpr size_t k_tolerance_exec_regions       = 300;
        constexpr size_t k_tolerance_suspicious_threads = 2;
        constexpr double k_private_usage_multiplier     = 1.5;

        snapshot g_baseline_snapshot{};
        bool     g_have_baseline = false;

        struct module_range
        {
            uintptr_t base;
            uintptr_t end;
        };

        std::vector<module_range> enumerate_modules(DWORD pid, size_t& count, size_t& weight)
        {
            std::vector<module_range> ranges;
            count = 0;
            weight = 0;

            HANDLE snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if (snapshot == INVALID_HANDLE_VALUE)
                return ranges;

            MODULEENTRY32W me{};
            me.dwSize = sizeof(me);

            if (LI_KERNEL(Module32FirstW)(snapshot, &me))
            {
                do
                {
                    ranges.push_back({
                        reinterpret_cast<uintptr_t>(me.modBaseAddr),
                        reinterpret_cast<uintptr_t>(me.modBaseAddr) + me.modBaseSize
                    });
                    ++count;
                    weight += me.modBaseSize;
                } while (LI_KERNEL(Module32NextW)(snapshot, &me));
            }

            LI_KERNEL(CloseHandle)(snapshot);
            return ranges;
        }

        bool address_in_modules(uintptr_t address, const std::vector<module_range>& modules)
        {
            for (auto& m : modules)
            {
                if (address >= m.base && address < m.end)
                    return true;
            }
            return false;
        }

        void scan_exec_memory(HANDLE process,
                              const std::vector<module_range>& modules,
                              size_t& unmapped_count,
                              size_t& unmapped_size,
                              size_t& exec_count)
        {
            unmapped_count = 0;
            unmapped_size = 0;
            exec_count = 0;

            MEMORY_BASIC_INFORMATION mbi{};
            uintptr_t address = 0;

            while (LI_KERNEL(VirtualQueryEx)(process, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)))
            {
                const bool is_exec = (mbi.Protect & PAGE_EXECUTE)
                                  || (mbi.Protect & PAGE_EXECUTE_READ)
                                  || (mbi.Protect & PAGE_EXECUTE_READWRITE)
                                  || (mbi.Protect & PAGE_EXECUTE_WRITECOPY);

                if (is_exec && mbi.State == MEM_COMMIT)
                {
                    ++exec_count;
                    if (!address_in_modules(reinterpret_cast<uintptr_t>(mbi.BaseAddress), modules))
                    {
                        ++unmapped_count;
                        unmapped_size += mbi.RegionSize;
                    }
                }

                const uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
                if (next <= address)
                    break;
                address = next;
            }
        }

        size_t scan_threads(DWORD pid, const std::vector<module_range>& modules)
        {
            using nt_query_information_thread_t = NTSTATUS (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
            static nt_query_information_thread_t nt_qit =
                reinterpret_cast<nt_query_information_thread_t>(
                    LI_KERNEL(GetProcAddress)(LI_KERNEL(GetModuleHandleW)(XSW(L"ntdll.dll")),
                                   XS("NtQueryInformationThread")));
            if (!nt_qit)
                return 0;

            size_t suspicious = 0;
            HANDLE snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPTHREAD, 0);
            if (snapshot == INVALID_HANDLE_VALUE)
                return 0;

            THREADENTRY32 te{};
            te.dwSize = sizeof(te);

            if (LI_KERNEL(Thread32First)(snapshot, &te))
            {
                do
                {
                    if (te.th32OwnerProcessID != pid)
                        continue;

                    HANDLE thread = LI_KERNEL(OpenThread)(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                    if (!thread)
                        continue;

                    PVOID start_address = nullptr;
                    if (nt_qit(thread, 9, &start_address, sizeof(start_address), nullptr) == 0
                        && start_address)
                    {
                        if (!address_in_modules(reinterpret_cast<uintptr_t>(start_address), modules))
                            ++suspicious;
                    }
                    LI_KERNEL(CloseHandle)(thread);
                } while (LI_KERNEL(Thread32Next)(snapshot, &te));
            }

            LI_KERNEL(CloseHandle)(snapshot);
            return suspicious;
        }

        size_t get_private_usage(HANDLE process)
        {
            PROCESS_MEMORY_COUNTERS_EX pmc{};
            if (GetProcessMemoryInfo(process,
                                     reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
                                     sizeof(pmc)))
                return pmc.PrivateUsage;
            return 0;
        }

        snapshot measure(DWORD pid)
        {
            snapshot snap{};
            HANDLE process = LI_KERNEL(OpenProcess)(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (!process)
                return snap;

            auto modules = enumerate_modules(pid, snap.module_count, snap.module_weight);
            scan_exec_memory(process, modules, snap.unmapped_regions, snap.unmapped_size, snap.exec_regions);
            snap.suspicious_threads = scan_threads(pid, modules);
            snap.private_usage = get_private_usage(process);

            LI_KERNEL(CloseHandle)(process);
            return snap;
        }
    }

    void reset()
    {
        g_baseline_snapshot = {};
        g_have_baseline = false;
    }

    bool has_baseline()
    {
        return g_have_baseline;
    }

    const wchar_t* severity_name(severity s)
    {
        switch (s)
        {
        case severity::clean:     return XSW(L"CLEAN");
        case severity::suspect:   return XSW(L"SUSPECT");
        case severity::likely:    return XSW(L"LIKELY");
        case severity::confirmed: return XSW(L"CONFIRMED");
        }
        return XSW(L"?");
    }

    result scan(DWORD fivem_pid)
    {
        result r{};
        if (!fivem_pid)
            return r;

        r.current = measure(fivem_pid);

        if (r.current.module_count == 0 && r.current.exec_regions == 0)
            return r;

        if (!g_have_baseline)
        {
            g_baseline_snapshot = r.current;
            g_have_baseline = true;
            r.baseline = g_baseline_snapshot;
            return r;
        }

        r.baseline = g_baseline_snapshot;
        r.delta_modules            = static_cast<int>(r.current.module_count)     - static_cast<int>(g_baseline_snapshot.module_count);
        r.delta_unmapped_regions   = static_cast<int>(r.current.unmapped_regions) - static_cast<int>(g_baseline_snapshot.unmapped_regions);
        r.delta_unmapped_size      = static_cast<int>(r.current.unmapped_size / 1024)
                                   - static_cast<int>(g_baseline_snapshot.unmapped_size / 1024);
        r.delta_exec_regions       = static_cast<int>(r.current.exec_regions)     - static_cast<int>(g_baseline_snapshot.exec_regions);
        r.delta_suspicious_threads = static_cast<int>(r.current.suspicious_threads) - static_cast<int>(g_baseline_snapshot.suspicious_threads);

        if (r.current.module_count > g_baseline_snapshot.module_count + k_tolerance_module_count)
            r.flags |= flag_module_count;
        if (r.current.module_weight > g_baseline_snapshot.module_weight + k_tolerance_module_weight)
            r.flags |= flag_module_weight;
        if (r.current.unmapped_regions > g_baseline_snapshot.unmapped_regions + k_tolerance_unmapped_regions)
            r.flags |= flag_unmapped_regions;
        if (r.current.unmapped_size > g_baseline_snapshot.unmapped_size + k_tolerance_unmapped_size)
            r.flags |= flag_unmapped_size;
        if (r.current.exec_regions > g_baseline_snapshot.exec_regions + k_tolerance_exec_regions)
            r.flags |= flag_exec_regions;
        if (r.current.suspicious_threads > g_baseline_snapshot.suspicious_threads + k_tolerance_suspicious_threads)
            r.flags |= flag_suspicious_threads;
        if (r.current.private_usage > static_cast<size_t>(static_cast<double>(g_baseline_snapshot.private_usage) * k_private_usage_multiplier))
            r.flags |= flag_private_usage;

        int flag_count = 0;
        for (uint32_t t = r.flags; t; t >>= 1)
            flag_count += (t & 1);

        const bool combo_manual_map = (r.flags & flag_unmapped_regions) && (r.flags & flag_unmapped_size);
        const bool combo_dll_inject = (r.flags & flag_module_count)     && (r.flags & flag_module_weight);

        if (flag_count >= 3 || combo_manual_map || combo_dll_inject)
            r.level = severity::confirmed;
        else if (flag_count == 2)
            r.level = severity::likely;
        else if (flag_count == 1)
            r.level = severity::suspect;
        else
            r.level = severity::clean;

        return r;
    }
}