#pragma once

#include <Windows.h>
#include <cstdint>
#include <vector>

namespace detections::rtss
{
    enum flag : uint32_t
    {
        flag_suspicious_owner = 1u << 0,
        flag_sample_owner     = 1u << 1,
        flag_esp_format_tags  = 1u << 2,
        flag_game_hooked      = 1u << 3,
    };

    struct hit
    {
        uint32_t flags = 0;
        int      score = 0;
        char     owner[256]{};
        char     osd_preview[128]{};
    };

    struct config
    {
        DWORD fivem_pid = 0;
        int   min_score = 2;
    };

    std::vector<hit> scan(const config& cfg, bool* out_game_hooked = nullptr);

    bool is_running();
}
