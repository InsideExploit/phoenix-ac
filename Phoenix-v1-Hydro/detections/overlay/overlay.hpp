#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace detections::overlay
{
    enum flag : uint32_t
    {
        flag_layered          = 1u << 0,
        flag_transparent      = 1u << 1,
        flag_popup            = 1u << 2,
        flag_topmost          = 1u << 3,
        flag_aligned_game     = 1u << 4,
        flag_game_owner       = 1u << 5,
        flag_suspicious_class = 1u << 6,
        flag_graphics_stack   = 1u << 7,
        flag_empty_title      = 1u << 8,
        flag_cloaked          = 1u << 9,
        flag_low_alpha        = 1u << 10,
        flag_esp_combo        = 1u << 11,
    };

    struct hit
    {
        DWORD    pid          = 0;
        HWND     window       = nullptr;
        int      score        = 0;
        uint32_t flags        = 0;
        float    overlap      = 0.f;
        wchar_t  window_class[128]{};
        wchar_t  process_name[260]{};
    };

    struct config
    {
        DWORD fivem_pid  = 0;
        DWORD ignore_pid = 0;
        int   min_score  = 60;
    };

    std::vector<hit> scan(const config& cfg);
    std::vector<DWORD> detect_overlay_pids(DWORD fivem_pid, DWORD ignore_pid, int min_score = 60);

    DWORD find_fivem_gta_pid(std::wstring* out_exe_name = nullptr);
    HWND  find_fivem_game_window(DWORD fivem_pid);

    bool is_allowlisted_process(DWORD pid);
    bool is_allowlisted_exe(const wchar_t* exe_file);
}
