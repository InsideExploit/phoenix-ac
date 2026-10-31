#pragma once

#include <Windows.h>

namespace anti_debug
{
    void start();

    int run_watchdog(DWORD parent_pid);
}
