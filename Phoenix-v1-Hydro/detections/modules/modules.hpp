#pragma once

#include <Windows.h>
#include <string>
#include <vector>

namespace detections::modules
{
    bool is_allowed_pid(DWORD pid);
    bool is_allowed_name(const wchar_t* exe_name);

    bool is_safe_pid(DWORD pid);
    bool is_safe_name(const wchar_t* exe_name);

    int  highest_fivem_build();

    std::vector<DWORD> fingerprint_scan(DWORD self_pid, DWORD fivem_pid);

    struct gta_cheat_hit
    {
        DWORD        pid;
        std::wstring exe_name;
        std::wstring modules;
    };

    bool find_gta_internal_cheat(gta_cheat_hit& out_hit);
}
