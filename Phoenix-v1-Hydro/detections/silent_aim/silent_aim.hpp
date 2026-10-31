#pragma once

#include <Windows.h>
#include <cstdint>
#include <vector>

namespace detections::silent_aim
{
    enum class hit_kind : uint8_t
    {
        none              = 0,
        v1_jmp_hook       = 1,
        v1_mov_hook       = 2,
        v1_indirect       = 3,
        v1_integrity      = 4,
        v2_jmp_hook       = 5,
        v2_integrity      = 6,
        v2_payload        = 7,
        v2_payload_alt    = 8,
    };

    struct hit
    {
        hit_kind kind    = hit_kind::none;
        uint64_t address = 0;
    };

    bool init(HANDLE fivem_handle, uint64_t module_base, size_t module_size);
    void reset();
    bool is_ready();
    bool was_tried();

    std::vector<hit> scan(HANDLE fivem_handle);
}
