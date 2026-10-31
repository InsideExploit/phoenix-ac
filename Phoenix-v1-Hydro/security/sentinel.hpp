#pragma once

#include "security/baselines.hpp"
#include "security/detonator.hpp"
#include "vendor/xorstr.hpp"

#include <Windows.h>
#include <atomic>
#include <chrono>
#include <thread>

namespace security::sentinel
{
    inline std::atomic<bool> g_halt{ false };
    inline std::atomic<bool> g_running{ false };

    inline void watchdog()
    {
        while (!g_halt.load(std::memory_order_relaxed))
        {
            if (!security::baselines::check_all())
            {
                security::detonator::trigger(
                    xorstr("Sentinel"),
                    xorstr("syscall prologue mismatch"));
                return;
            }

            std::this_thread::sleep_for(std::chrono::seconds(4));
        }
    }

    inline void start()
    {
        if (g_running.exchange(true))
            return;
        std::thread(watchdog).detach();
    }

    inline void stop()
    {
        g_halt.store(true, std::memory_order_relaxed);
    }
}
