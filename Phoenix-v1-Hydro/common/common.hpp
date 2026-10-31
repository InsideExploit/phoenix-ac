#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>

namespace common
{
    bool enable_debug_privilege();

    DWORD find_fivem_pid(std::wstring& out_name);

    uint64_t remote_module_base(DWORD pid, const std::wstring& exe_name, uint64_t* out_size);

    int parse_build_number(const std::wstring& exe_name);

    uint64_t pattern_scan(HANDLE process,
                          uint64_t base,
                          uint64_t size,
                          const uint8_t* signature,
                          const char* mask);
}
