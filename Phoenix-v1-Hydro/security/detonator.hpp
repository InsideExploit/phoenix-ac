#pragma once

#include "security/stealth_exit.hpp"
#include "vendor/xorstr.hpp"
#include "webhook/webhook.hpp"

#include <Windows.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>

namespace security::detonator
{
    using corrupt_callback_t = void (*)();

    inline std::atomic<bool>                g_detonated{ false };
    inline std::atomic<corrupt_callback_t>  g_callback{ nullptr };
    inline std::atomic<uint32_t>            g_cookie{ 0xCAFEBABEu };
    inline std::atomic<uint64_t>            g_hit_count{ 0 };
    inline std::atomic<uint64_t>            g_baseline_hash{ 0 };
    inline std::atomic<bool>                g_guard_running{ false };

    constexpr int k_prologue_bytes = 64;

    inline bool is_detonated() noexcept
    {
        return g_detonated.load(std::memory_order_acquire)
            || g_cookie.load(std::memory_order_acquire) != 0xCAFEBABEu
            || g_hit_count.load(std::memory_order_acquire) != 0;
    }

    inline void mark_detonated() noexcept
    {
        g_cookie.store(0xDEADC0DEu, std::memory_order_release);
        g_hit_count.fetch_add(1, std::memory_order_acq_rel);
        g_detonated.store(true, std::memory_order_release);
    }

    inline void register_corrupt_callback(corrupt_callback_t callback)
    {
        g_callback.store(callback, std::memory_order_release);
    }

    inline DWORD invoke_corrupt_callback()
    {
        corrupt_callback_t cb = g_callback.load(std::memory_order_acquire);
        if (!cb)
            return 0;

        __try
        {
            cb();
            return 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return GetExceptionCode();
        }
    }

    inline void terminate_via_exit()
    {
        ExitProcess(0);
    }

    inline void terminate_via_kernel()
    {
        TerminateProcess(GetCurrentProcess(), 0);
    }

    inline void terminate_via_bad_write()
    {
        const uintptr_t bad_address = static_cast<uintptr_t>(0x9CEFu ^ 0x4242u);
        *reinterpret_cast<volatile int*>(bad_address) = static_cast<int>(0xACDBu ^ 0x1234u);
    }

    inline void terminate_via_stack_flood()
    {
        for (;;)
        {
            volatile char scratch[65536] = {};
            (void)scratch;
        }
    }

    inline void terminate_via_raise()
    {
        RaiseException(0xC0000008u, EXCEPTION_NONCONTINUABLE, 0, nullptr);
    }

    inline void final_terminate_sequence()
    {
        using terminate_fn = void (*)();

        uint32_t seed = static_cast<uint32_t>(GetTickCount() ^ reinterpret_cast<uintptr_t>(&final_terminate_sequence));

        terminate_fn hard[2] = { &terminate_via_exit, &terminate_via_kernel };
        for (int i = 1; i > 0; --i)
        {
            seed = seed * 1103515245u + 12345u;
            const int j = static_cast<int>(seed % static_cast<uint32_t>(i + 1));
            terminate_fn tmp = hard[i];
            hard[i] = hard[j];
            hard[j] = tmp;
        }
        for (int i = 0; i < 2; ++i)
            hard[i]();

        terminate_fn soft[3] = { &terminate_via_bad_write, &terminate_via_stack_flood, &terminate_via_raise };
        for (int i = 2; i > 0; --i)
        {
            seed = seed * 1103515245u + 12345u;
            const int j = static_cast<int>(seed % static_cast<uint32_t>(i + 1));
            terminate_fn tmp = soft[i];
            soft[i] = soft[j];
            soft[j] = tmp;
        }
        for (int i = 0; i < 3; ++i)
            soft[i]();
    }

    inline uint32_t fnv32(const std::string& s)
    {
        uint32_t h = 0x811C9DC5u;
        for (unsigned char c : s)
        {
            h ^= c;
            h *= 0x01000193u;
        }
        return h;
    }

    inline uint64_t hash_prologue(const uint8_t* address)
    {
        uint64_t h = 14695981039346656037ULL;
        __try
        {
            for (int i = 0; i < k_prologue_bytes; ++i)
            {
                h ^= address[i];
                h *= 1099511628211ULL;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }
        return h;
    }

    inline void trigger(const std::string& tag, const std::string& reason);

    inline DWORD WINAPI guard_thread(LPVOID)
    {
        Sleep(2000);

        const auto address = reinterpret_cast<const uint8_t*>(&trigger);
        const uint64_t baseline = hash_prologue(address);
        if (baseline == 0)
            return 1;

        g_baseline_hash.store(baseline, std::memory_order_release);

        for (;;)
        {
            const DWORD jitter = GetTickCount() % 8000;
            Sleep(5000 + jitter);

            const uint64_t current = hash_prologue(address);
            if (current == 0)
                continue;
            if (current != baseline)
            {
                security::stealth_exit::now();
                return 0;
            }
        }
    }

    inline void start_guard()
    {
        if (g_guard_running.exchange(true))
            return;

        if (HANDLE thread = CreateThread(nullptr, 0, guard_thread, nullptr, 0, nullptr))
            CloseHandle(thread);
    }

    inline void trigger(const std::string& tag, const std::string& reason)
    {
        const bool was_detonated = is_detonated();
        mark_detonated();
        if (was_detonated)
            return;

        const uint32_t code = fnv32(tag + ":" + reason);
        webhook::report_detonator(tag.c_str(), reason.c_str(), code);
        webhook::flush(800);

        std::thread([]{
            const DWORD t1 = static_cast<DWORD>(GetTickCount64());
            Sleep(1000 + (t1 & 0x7FF));

            invoke_corrupt_callback();

            const DWORD t2 = static_cast<DWORD>(GetTickCount64());
            Sleep(2000 + (t2 & 0xBFF));

            final_terminate_sequence();

            TerminateProcess(GetCurrentProcess(), 0);
            ExitProcess(0);
            for (;;)
                Sleep(INFINITE);
        }).detach();
    }
}
