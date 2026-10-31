#pragma once

#include <Windows.h>
#include <vector>

namespace detections::streamproof
{
    struct hit
    {
        DWORD   pid;
        HWND    window;
        DWORD   affinity;
        wchar_t process_name[260];
    };

    std::vector<hit> scan(DWORD fivem_pid, DWORD self_pid);
}
