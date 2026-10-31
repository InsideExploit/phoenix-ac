#include "anchor_sweep.hpp"
#include "vendor/lazy_importer.hpp"
#include <algorithm>
#include <cstdint>
#include <unordered_set>
#include <utility>
#include <vector>
namespace response::anchor_sweep
{
    namespace
    {
        uint64_t read_qword_remote(HANDLE process, uint64_t address)
        {
            uint64_t value = 0;
            SIZE_T got = 0;
            if (!LI_KERNEL(ReadProcessMemory)(process, reinterpret_cast<LPCVOID>(address), &value, 8, &got))
                return 0;
            return got == 8 ? value : 0;
        }

        std::unordered_set<uint64_t> collect_needles(HANDLE fivem_handle,
                                                     uint64_t world,
                                                     uint64_t ped_pool,
                                                     uint64_t blip,
                                                     uint64_t aim,
                                                     uint64_t viewport_runtime)
        {
            std::unordered_set<uint64_t> needles;
            auto add = [&](uint64_t addr) {
                if (!addr)
                    return;
                const uint64_t value = read_qword_remote(fivem_handle, addr);
                if (value > 0x10000)
                    needles.insert(value);
            };
            add(world);
            add(ped_pool);
            add(blip);
            add(aim);

            if (viewport_runtime > 0x10000)
                needles.insert(viewport_runtime);
            return needles;
        }

        std::vector<std::pair<uint64_t, uint64_t>> collect_ranges(HANDLE fivem_handle)
        {
            std::vector<std::pair<uint64_t, uint64_t>> ranges;
            if (!fivem_handle)
                return ranges;

            MEMORY_BASIC_INFORMATION mbi{};
            uint8_t* address = nullptr;

            while (LI_KERNEL(VirtualQueryEx)(fivem_handle, address, &mbi, sizeof(mbi)))
            {
                uint8_t* next = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
                if (mbi.State == MEM_COMMIT &&
                    (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED))
                {
                    const DWORD protect = mbi.Protect & 0xFF;
                    if (protect != 0 && protect != PAGE_NOACCESS && !(mbi.Protect & PAGE_GUARD))
                        ranges.emplace_back(reinterpret_cast<uint64_t>(mbi.BaseAddress),
                                            reinterpret_cast<uint64_t>(next));
                }

                address = next;
                if (!next)
                    break;
            }

            std::sort(ranges.begin(), ranges.end(),
                      [](const std::pair<uint64_t, uint64_t>& a, const std::pair<uint64_t, uint64_t>& b) {
                          return a.first < b.first;
                      });
            return ranges;
        }

        inline bool pointer_in_ranges(uint64_t value,
                                      const std::vector<std::pair<uint64_t, uint64_t>>& ranges)
        {
            if (value < 0x10000)
                return false;

            auto it = std::lower_bound(ranges.begin(), ranges.end(), value,
                [](const std::pair<uint64_t, uint64_t>& range, uint64_t x) {
                    return range.second <= x;
                });
            return it != ranges.end() && value >= it->first && value < it->second;
        }

        int replace_range_matches(HANDLE cheat_handle,
                                  const std::vector<std::pair<uint64_t, uint64_t>>& ranges,
                                  uint64_t replacement)
        {
            if (ranges.empty())
                return 0;

            int total = 0;
            MEMORY_BASIC_INFORMATION mbi{};
            uint8_t* address = nullptr;
            std::vector<uint8_t> buffer;

            while (LI_KERNEL(VirtualQueryEx)(cheat_handle, address, &mbi, sizeof(mbi)))
            {
                uint8_t* next = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
                const bool state_ok = (mbi.State == MEM_COMMIT) && (mbi.Type == MEM_PRIVATE);
                const DWORD protect = mbi.Protect & 0xFF;
                const bool writable = protect == PAGE_READWRITE
                                   || protect == PAGE_EXECUTE_READWRITE
                                   || protect == PAGE_WRITECOPY
                                   || protect == PAGE_EXECUTE_WRITECOPY;
                const bool size_ok = mbi.RegionSize >= 8 && mbi.RegionSize <= 0x40000000;

                if (state_ok && writable && size_ok)
                {
                    if (buffer.size() < mbi.RegionSize)
                        buffer.resize(mbi.RegionSize);

                    SIZE_T got = 0;
                    if (LI_KERNEL(ReadProcessMemory)(cheat_handle, mbi.BaseAddress, buffer.data(),
                                          mbi.RegionSize, &got) && got >= 8)
                    {
                        for (SIZE_T i = 0; i + 8 <= got; i += 8)
                        {
                            const uint64_t value = *reinterpret_cast<uint64_t*>(buffer.data() + i);
                            if (pointer_in_ranges(value, ranges))
                            {
                                SIZE_T written = 0;
                                if (LI_KERNEL(WriteProcessMemory)(cheat_handle,
                                                       reinterpret_cast<LPVOID>(static_cast<uint8_t*>(mbi.BaseAddress) + i),
                                                       &replacement, 8, &written))
                                    ++total;
                            }
                        }
                    }
                }

                address = next;
                if (!next)
                    break;
            }
            return total;
        }

        int replace_needle_matches(HANDLE cheat_handle,
                                   const std::unordered_set<uint64_t>& needles,
                                   uint64_t replacement)
        {
            if (needles.empty())
                return 0;

            int total = 0;
            MEMORY_BASIC_INFORMATION mbi{};
            uint8_t* address = nullptr;
            std::vector<uint8_t> buffer;

            while (LI_KERNEL(VirtualQueryEx)(cheat_handle, address, &mbi, sizeof(mbi)))
            {
                uint8_t* next = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
                const bool state_ok = (mbi.State == MEM_COMMIT) && (mbi.Type == MEM_PRIVATE);
                const DWORD protect = mbi.Protect & 0xFF;
                const bool writable = protect == PAGE_READWRITE
                                   || protect == PAGE_EXECUTE_READWRITE
                                   || protect == PAGE_WRITECOPY
                                   || protect == PAGE_EXECUTE_WRITECOPY;
                const bool size_ok = mbi.RegionSize >= 8 && mbi.RegionSize <= 0x40000000;

                if (state_ok && writable && size_ok)
                {
                    if (buffer.size() < mbi.RegionSize)
                        buffer.resize(mbi.RegionSize);

                    SIZE_T got = 0;
                    if (LI_KERNEL(ReadProcessMemory)(cheat_handle, mbi.BaseAddress, buffer.data(),
                                          mbi.RegionSize, &got) && got >= 8)
                    {
                        for (SIZE_T i = 0; i + 8 <= got; i += 8)
                        {
                            const uint64_t value = *reinterpret_cast<uint64_t*>(buffer.data() + i);
                            if (needles.count(value))
                            {
                                SIZE_T written = 0;
                                if (LI_KERNEL(WriteProcessMemory)(cheat_handle,
                                                       reinterpret_cast<LPVOID>(static_cast<uint8_t*>(mbi.BaseAddress) + i),
                                                       &replacement, 8, &written))
                                    ++total;
                            }
                        }
                    }
                }

                address = next;
                if (!next)
                    break;
            }
            return total;
        }
    }

    bool wipe(DWORD cheat_pid,
              const poison_cfg::payload_config& cfg,
              HANDLE fivem_handle,
              bool full_nuke,
              stats* out_stats)
    {
        if (out_stats)
            *out_stats = {};
        if (!fivem_handle)
            return false;

        HANDLE cheat = LI_KERNEL(OpenProcess)(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                                   FALSE, cheat_pid);
        if (!cheat)
            return false;

        auto needles = collect_needles(fivem_handle, cfg.world, cfg.ped_pool,
                                       cfg.blip_list, cfg.aim, cfg.viewport_runtime);
        const int anchor_hits = replace_needle_matches(cheat, needles, 0);

        int range_hits = 0;
        if (full_nuke)
        {
            auto ranges = collect_ranges(fivem_handle);
            range_hits = replace_range_matches(cheat, ranges, 0);
        }

        LI_KERNEL(CloseHandle)(cheat);

        if (out_stats)
        {
            out_stats->ok           = true;
            out_stats->anchor_hits  = anchor_hits;
            out_stats->range_hits   = range_hits;
            out_stats->needle_count = needles.size();
            out_stats->full_nuke    = full_nuke;
        }
        return true;
    }

    int probe(DWORD cheat_pid,
              const poison_cfg::payload_config& cfg,
              HANDLE fivem_handle,
              int early_exit)
    {
        if (!fivem_handle)
            return 0;

        HANDLE cheat = LI_KERNEL(OpenProcess)(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, cheat_pid);
        if (!cheat)
            return 0;

        auto needles = collect_needles(fivem_handle, cfg.world, cfg.ped_pool,
                                       cfg.blip_list, cfg.aim, cfg.viewport_runtime);
        if (needles.empty())
        {
            LI_KERNEL(CloseHandle)(cheat);
            return 0;
        }

        int hits = 0;
        MEMORY_BASIC_INFORMATION mbi{};
        uint8_t* address = nullptr;
        std::vector<uint8_t> buffer;
        bool early_break = false;

        while (!early_break && LI_KERNEL(VirtualQueryEx)(cheat, address, &mbi, sizeof(mbi)))
        {
            uint8_t* next = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
            const bool state_ok = (mbi.State == MEM_COMMIT) && (mbi.Type == MEM_PRIVATE);
            const DWORD protect = mbi.Protect & 0xFF;
            const bool readable = protect != 0
                               && protect != PAGE_NOACCESS
                               && !(mbi.Protect & PAGE_GUARD)
                               && (protect == PAGE_READWRITE
                                   || protect == PAGE_EXECUTE_READWRITE
                                   || protect == PAGE_WRITECOPY
                                   || protect == PAGE_EXECUTE_WRITECOPY
                                   || protect == PAGE_READONLY
                                   || protect == PAGE_EXECUTE_READ);
            const bool size_ok = mbi.RegionSize >= 8 && mbi.RegionSize <= 0x40000000;

            if (state_ok && readable && size_ok)
            {
                if (buffer.size() < mbi.RegionSize)
                    buffer.resize(mbi.RegionSize);

                SIZE_T got = 0;
                if (LI_KERNEL(ReadProcessMemory)(cheat, mbi.BaseAddress, buffer.data(),
                                      mbi.RegionSize, &got) && got >= 8)
                {
                    for (SIZE_T i = 0; i + 8 <= got; i += 8)
                    {
                        const uint64_t value = *reinterpret_cast<uint64_t*>(buffer.data() + i);
                        if (needles.count(value))
                        {
                            if (++hits >= early_exit)
                            {
                                early_break = true;
                                break;
                            }
                        }
                    }
                }
            }

            address = next;
            if (!next)
                break;
        }

        LI_KERNEL(CloseHandle)(cheat);
        return hits;
    }
}