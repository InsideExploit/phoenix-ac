#pragma once

#include <Windows.h>
#include <cstdint>
#include <vector>

namespace detections::injection
{
    enum class hit_type : uint8_t
    {
        stomped_module   = 0,
        private_exec_pe  = 1,
        headless_exec    = 2,
    };

    struct hit
    {
        hit_type type;
        uint64_t address;
        uint32_t region_size;
        wchar_t  detail[128];
    };

    std::vector<hit> scan(DWORD fivem_pid, HANDLE fivem_handle);
}
