#pragma once

#include <Windows.h>
#include <cstdint>

namespace offsets
{
    struct pack
    {
        uint64_t world;
        uint64_t viewport;
        uint64_t cam;
        uint64_t blip;
        uint64_t ped_pool;
        uint64_t aim;
    };

    pack resolve(int build);

    uint64_t find_ped_pool(HANDLE process, uint64_t base, uint64_t size);

    uint64_t find_viewport(HANDLE process,
                           uint64_t module_base,
                           uint64_t module_size,
                           uint64_t fallback_global);
}
