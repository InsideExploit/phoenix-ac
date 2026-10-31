#pragma once

#include <Windows.h>
#include <cstdint>
#include <vector>

namespace detections::internal_scan
{
    enum class hit_type : uint8_t
    {
        injected_thread = 0,
        swapchain_hook  = 1,
    };

    struct hit
    {
        hit_type type;
        uint32_t tid;
        uint64_t address;
        uint64_t vtable_slot_address;
    };

    std::vector<hit> scan(DWORD fivem_pid, HANDLE fivem_handle, uint64_t module_base, int build);
}
