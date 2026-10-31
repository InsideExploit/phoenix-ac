#pragma once

#include <Windows.h>
#include <cstdint>
#include <vector>

namespace detections::lua_script
{
    struct hit
    {
        uint64_t address;
        uint32_t size;
        wchar_t  pattern[64];
    };

    std::vector<hit> scan(HANDLE fivem_handle);
}
