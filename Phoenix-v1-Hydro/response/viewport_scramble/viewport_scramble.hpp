#pragma once

#include <Windows.h>
#include <atomic>
#include <cstdint>

namespace response::viewport_scramble
{
    extern std::atomic<bool>     g_halt;
    extern std::atomic<uint64_t> g_viewport;
    extern std::atomic<DWORD>    g_pid;

    void start();
}
