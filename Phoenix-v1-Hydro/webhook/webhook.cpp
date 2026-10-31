#include "webhook.hpp"
#include "net/wire.hpp"
#include "vendor/lazy_importer.hpp"
#include "vendor/xor_string.hpp"
#include <Windows.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>
namespace webhook
{
    namespace
    {
        constexpr int           k_sweep_flush_sec = 60;
        constexpr size_t        k_queue_capacity  = 256;

        std::string                    g_steam_hex;
        std::queue<std::vector<uint8_t>> g_queue;
        std::mutex                     g_queue_mutex;
        std::condition_variable        g_queue_cv;
        std::atomic<bool>              g_halt{ false };
        std::thread                    g_worker;
        std::atomic<bool>              g_alive{ false };

        std::mutex                        g_dedup_mutex;
        std::unordered_set<uint32_t>      g_dedup_detection;
        std::unordered_set<uint32_t>      g_dedup_overlay;
        std::unordered_set<uint32_t>      g_dedup_mod_fp;
        std::unordered_set<uint32_t>      g_dedup_internal_fivem;
        std::unordered_set<uint64_t>      g_dedup_mapper;
        std::unordered_set<uint64_t>      g_dedup_injection;
        std::unordered_set<uint64_t>      g_dedup_streamproof;
        std::unordered_set<uint64_t>      g_dedup_internal;
        std::unordered_set<uint64_t>      g_dedup_silent_aim;
        std::unordered_set<uint64_t>      g_dedup_baseline;
        std::unordered_set<uint64_t>      g_dedup_security;

        struct sweep_accumulator
        {
            int          anchor_accum = 0;
            int          range_accum  = 0;
            size_t       needle_snap  = 0;
            int          ticks        = 0;
            std::wstring exe_name;
            std::chrono::steady_clock::time_point last_flush;
        };
        std::mutex                                    g_sweep_mutex;
        std::unordered_map<uint32_t, sweep_accumulator> g_sweep;

        std::string wide_to_utf8(const std::wstring& w)
        {
            if (w.empty())
                return {};

            const int required = WideCharToMultiByte(CP_UTF8, 0,
                                                     w.c_str(), static_cast<int>(w.size()),
                                                     nullptr, 0, nullptr, nullptr);
            if (required <= 0)
                return {};

            std::string out;
            out.resize(static_cast<size_t>(required));
            WideCharToMultiByte(CP_UTF8, 0,
                                w.c_str(), static_cast<int>(w.size()),
                                out.data(), required, nullptr, nullptr);
            return out;
        }

        std::string host_name()
        {
            wchar_t name[MAX_COMPUTERNAME_LENGTH + 1] = {};
            DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
            if (!GetComputerNameW(name, &size))
                return "?";
            return wide_to_utf8(name);
        }

        std::vector<uint8_t> build_event(wire::event_kind kind,
                                         uint32_t pid,
                                         const std::wstring& exe,
                                         const std::vector<uint8_t>& payload)
        {
            return wire::pack_event(kind, pid, g_steam_hex, wide_to_utf8(exe), host_name(), payload);
        }

        void enqueue(std::vector<uint8_t>&& body)
        {
            {
                std::lock_guard<std::mutex> lock(g_queue_mutex);
                if (g_queue.size() >= k_queue_capacity)
                    g_queue.pop();
                g_queue.push(std::move(body));
            }
            g_queue_cv.notify_one();
        }

        bool wire_post(const std::vector<uint8_t>& body)
        {
            std::vector<uint8_t> rsp;
            uint32_t opcode = 0;
            if (!wire::transact(static_cast<uint16_t>(wire::opcode::event_req), body, rsp, opcode))
                return false;
            if (opcode != static_cast<uint32_t>(wire::opcode::event_rsp))
                return false;
            return !rsp.empty() && rsp[0] != 0;
        }

        void worker_loop()
        {
            while (!g_halt.load(std::memory_order_acquire))
            {
                std::vector<uint8_t> item;
                {
                    std::unique_lock<std::mutex> lock(g_queue_mutex);
                    g_queue_cv.wait(lock, [] {
                        return g_halt.load(std::memory_order_acquire) || !g_queue.empty();
                    });
                    if (g_halt.load(std::memory_order_acquire) && g_queue.empty())
                        break;
                    item = std::move(g_queue.front());
                    g_queue.pop();
                }
                (void)wire_post(item);
            }
        }
    }

    void set_identity(const std::string& steam_hex)
    {
        g_steam_hex = steam_hex;
    }

    void start(const std::string& steam_hex)
    {
        if (g_alive.exchange(true))
            return;
        g_steam_hex = steam_hex;
        g_halt.store(false, std::memory_order_release);
        g_worker = std::thread(worker_loop);
    }

    void stop()
    {
        if (!g_alive.exchange(false))
            return;
        g_halt.store(true, std::memory_order_release);
        g_queue_cv.notify_all();
        if (g_worker.joinable())
            g_worker.join();
    }

    void report_detection(uint32_t pid,
                          const std::wstring& exe_name,
                          const std::wstring& via,
                          uint64_t hook_addr,
                          uint64_t shellcode_addr)
    {
        if (!g_alive.load())
            return;
        {
            std::lock_guard<std::mutex> lock(g_dedup_mutex);
            if (g_dedup_detection.count(pid))
                return;
            g_dedup_detection.insert(pid);
        }

        std::vector<uint8_t> payload;
        wire::append_string(payload, wide_to_utf8(via));
        wire::append_u64(payload, hook_addr);
        wire::append_u64(payload, shellcode_addr);
        enqueue(build_event(wire::event_kind::detection, pid, exe_name, payload));
    }

    void report_sweep(uint32_t pid,
                      const std::wstring& exe_name,
                      int anchor_hits,
                      int range_hits,
                      size_t needle_count,
                      bool)
    {
        if (!g_alive.load())
            return;
        if (anchor_hits == 0 && range_hits == 0)
            return;

        sweep_accumulator snapshot{};
        bool should_flush = false;

        {
            std::lock_guard<std::mutex> lock(g_sweep_mutex);
            auto& acc = g_sweep[pid];
            if (acc.ticks == 0)
            {
                acc.last_flush = std::chrono::steady_clock::now();
                acc.exe_name   = exe_name;
            }
            acc.anchor_accum += anchor_hits;
            acc.range_accum  += range_hits;
            acc.needle_snap   = needle_count;
            acc.ticks        += 1;

            if (std::chrono::steady_clock::now() - acc.last_flush >= std::chrono::seconds(k_sweep_flush_sec))
            {
                snapshot     = acc;
                should_flush = true;
                acc.anchor_accum = 0;
                acc.range_accum  = 0;
                acc.ticks        = 0;
                acc.last_flush   = std::chrono::steady_clock::now();
            }
        }

        if (!should_flush)
            return;

        std::vector<uint8_t> payload;
        wire::append_u32(payload, static_cast<uint32_t>(snapshot.anchor_accum));
        wire::append_u32(payload, static_cast<uint32_t>(snapshot.range_accum));
        wire::append_u32(payload, static_cast<uint32_t>(snapshot.needle_snap));
        wire::append_u32(payload, static_cast<uint32_t>(snapshot.ticks));
        enqueue(build_event(wire::event_kind::sweep, pid, snapshot.exe_name, payload));
    }

    void report_exit(uint32_t pid,
                     const std::wstring& exe_name,
                     uint64_t total_anchor_hits,
                     uint64_t total_range_hits,
                     uint32_t lifetime_seconds)
    {
        if (!g_alive.load())
            return;

        {
            std::lock_guard<std::mutex> lock(g_sweep_mutex);
            g_sweep.erase(pid);
        }
        {
            std::lock_guard<std::mutex> lock(g_dedup_mutex);
            g_dedup_detection.erase(pid);
            g_dedup_overlay.erase(pid);
        }

        std::vector<uint8_t> payload;
        wire::append_u64(payload, total_anchor_hits);
        wire::append_u64(payload, total_range_hits);
        wire::append_u32(payload, lifetime_seconds);
        enqueue(build_event(wire::event_kind::exit_kind, pid, exe_name, payload));
    }

    void report_overlay(uint32_t pid,
                        const std::wstring& exe_name,
                        const std::wstring& window_class,
                        int score,
                        uint32_t flags,
                        float overlap_pct)
    {
        if (!g_alive.load())
            return;
        {
            std::lock_guard<std::mutex> lock(g_dedup_mutex);
            if (g_dedup_overlay.count(pid))
                return;
            g_dedup_overlay.insert(pid);
        }

        std::vector<uint8_t> payload;
        wire::append_string(payload, wide_to_utf8(window_class));
        wire::append_u32(payload, static_cast<uint32_t>(score));
        wire::append_u32(payload, flags);
        wire::append_u32(payload, static_cast<uint32_t>(overlap_pct * 10000.f));

        enqueue(build_event(wire::event_kind::overlay, pid, exe_name, payload));
    }

    void report_streamproof(uint32_t pid,
                            const std::wstring& exe_name,
                            uint64_t hwnd,
                            uint32_t affinity)
    {
        if (!g_alive.load())
            return;

        const uint64_t key = (static_cast<uint64_t>(pid) << 32) ^ (hwnd & 0xFFFFFFFFu);
        {
            std::lock_guard<std::mutex> lock(g_dedup_mutex);
            if (g_dedup_streamproof.count(key))
                return;
            g_dedup_streamproof.insert(key);
        }

        wchar_t class_name[96];
        swprintf_s(class_name, L"streamproof_WDA_0x%X_hwnd_0x%llX",
                   affinity, static_cast<unsigned long long>(hwnd));
        report_overlay(pid, exe_name, class_name, 10, 0, 0.f);
    }

    void report_internal(uint32_t tid_or_zero,
                         uint64_t addr,
                         const wchar_t* hit_type)
    {
        if (!g_alive.load())
            return;

        const uint64_t key = (static_cast<uint64_t>(tid_or_zero) << 32) ^ (addr & 0xFFFFFFFFu);
        {
            std::lock_guard<std::mutex> lock(g_dedup_mutex);
            if (g_dedup_internal.count(key))
                return;
            g_dedup_internal.insert(key);
        }

        std::vector<uint8_t> payload;
        wire::append_u32(payload, tid_or_zero);
        wire::append_u64(payload, addr);
        wire::append_string(payload, wide_to_utf8(hit_type ? hit_type : L""));
        enqueue(build_event(wire::event_kind::internal_kind, 0, std::wstring{}, payload));
    }

    void report_baseline(uint32_t flags, uint8_t severity, const wchar_t* detail)
    {
        if (!g_alive.load())
            return;

        const uint64_t key = (static_cast<uint64_t>(severity) << 56) ^ flags;
        {
            std::lock_guard<std::mutex> lock(g_dedup_mutex);
            if (g_dedup_baseline.count(key))
                return;
            g_dedup_baseline.insert(key);
        }

        wchar_t full_tag[256];
        swprintf_s(full_tag, L"Baseline [sev=%u flags=0x%X] %s",
                   static_cast<unsigned>(severity), flags,
                   detail ? detail : L"");
        report_internal((static_cast<uint32_t>(severity) << 24) | flags, 0, full_tag);
    }

    void report_silent_aim(uint8_t kind, uint64_t addr, const wchar_t* tag)
    {
        if (!g_alive.load())
            return;

        const uint64_t key = (static_cast<uint64_t>(kind) << 56) ^ addr;
        {
            std::lock_guard<std::mutex> lock(g_dedup_mutex);
            if (g_dedup_silent_aim.count(key))
                return;
            g_dedup_silent_aim.insert(key);
        }

        wchar_t full_tag[128];
        swprintf_s(full_tag, L"SilentAim %s", tag ? tag : L"");
        report_internal(static_cast<uint32_t>(kind) << 24, addr, full_tag);
    }

    void report_mapper(uint8_t hit_type,
                       uint64_t addr,
                       uint32_t region_size,
                       uint32_t pid,
                       const wchar_t* detail)
    {
        if (!g_alive.load())
            return;

        const uint64_t key = (static_cast<uint64_t>(hit_type) << 56)
                           ^ (static_cast<uint64_t>(pid) << 32)
                           ^ (addr & 0xFFFFFFFFULL);
        {
            std::lock_guard<std::mutex> lock(g_dedup_mutex);
            if (g_dedup_mapper.count(key))
                return;
            g_dedup_mapper.insert(key);
        }

        std::vector<uint8_t> payload;
        payload.push_back(hit_type);
        wire::append_u64(payload, addr);
        wire::append_u32(payload, region_size);
        wire::append_string(payload, wide_to_utf8(detail ? detail : L""));
        enqueue(build_event(wire::event_kind::mapper, pid, std::wstring{}, payload));
    }

    void report_injection(uint8_t hit_type,
                          uint64_t addr,
                          uint32_t region_size,
                          const wchar_t* detail)
    {
        if (!g_alive.load())
            return;
        {
            std::lock_guard<std::mutex> lock(g_dedup_mutex);
            if (g_dedup_injection.count(addr))
                return;
            g_dedup_injection.insert(addr);
        }

        std::vector<uint8_t> payload;
        payload.push_back(hit_type);
        wire::append_u64(payload, addr);
        wire::append_u32(payload, region_size);
        wire::append_string(payload, wide_to_utf8(detail ? detail : L""));
        enqueue(build_event(wire::event_kind::injection, 0, std::wstring{}, payload));
    }

    void report_mod_fingerprint(uint32_t pid,
                                const std::wstring& exe_name,
                                int hits,
                                const std::wstring& module_list)
    {
        if (!g_alive.load())
            return;
        {
            std::lock_guard<std::mutex> lock(g_dedup_mutex);
            if (g_dedup_mod_fp.count(pid))
                return;
            g_dedup_mod_fp.insert(pid);
        }

        std::vector<uint8_t> payload;
        wire::append_u32(payload, static_cast<uint32_t>(hits));
        wire::append_string(payload, wide_to_utf8(module_list));
        enqueue(build_event(wire::event_kind::modfingerprint, pid, exe_name, payload));
    }

    void report_internal_fivem(uint32_t pid,
                               const std::wstring& exe_name,
                               const std::wstring& module_list)
    {
        if (!g_alive.load())
            return;
        {
            std::lock_guard<std::mutex> lock(g_dedup_mutex);
            if (g_dedup_internal_fivem.count(pid))
                return;
            g_dedup_internal_fivem.insert(pid);
        }

        std::vector<uint8_t> payload;
        wire::append_string(payload, "Internal Cheat FiveM Detected");
        wire::append_string(payload, wide_to_utf8(module_list));
        enqueue(build_event(wire::event_kind::internal_fivem, pid, exe_name, payload));
    }

    void report_security(const char* category,
                         const char* label,
                         const char* body,
                         uint8_t severity)
    {
        if (!category || !label)
            return;

        uint64_t hash = 14695981039346656037ULL;
        for (const char* x = category; *x; ++x) { hash ^= static_cast<uint8_t>(*x); hash *= 1099511628211ULL; }
        hash ^= '|'; hash *= 1099511628211ULL;
        for (const char* x = label; *x; ++x) { hash ^= static_cast<uint8_t>(*x); hash *= 1099511628211ULL; }

        {
            std::lock_guard<std::mutex> lock(g_dedup_mutex);
            if (g_dedup_security.count(hash))
                return;
            g_dedup_security.insert(hash);
        }

        std::vector<uint8_t> payload;
        wire::append_string(payload, category);
        wire::append_string(payload, label);
        payload.push_back(severity);
        wire::append_string(payload, body && *body ? std::string(body) : std::string());
        wire::append_u32(payload, 0);
        wire::append_string(payload, std::string());

        const auto event = build_event(wire::event_kind::security, 0, std::wstring{}, payload);
        if (!g_alive.load())
        {
            (void)wire_post(event);
            return;
        }
        enqueue(std::vector<uint8_t>(event));
    }

    void report_detonator(const char* tag, const char* reason, uint32_t fnv_code)
    {
        std::vector<uint8_t> payload;
        wire::append_string(payload, "Detonator");
        wire::append_string(payload, tag ? tag : "?");
        payload.push_back(3);
        wire::append_string(payload, std::string());
        wire::append_u32(payload, fnv_code);
        wire::append_string(payload, reason ? reason : "?");

        const auto event = build_event(wire::event_kind::security, 0, std::wstring{}, payload);
        (void)wire_post(event);
    }

    void flush(unsigned int max_ms)
    {
        if (!g_alive.load())
            return;

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(max_ms);
        for (;;)
        {
            {
                std::lock_guard<std::mutex> lock(g_queue_mutex);
                if (g_queue.empty())
                    return;
            }
            if (std::chrono::steady_clock::now() >= deadline)
                return;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
}