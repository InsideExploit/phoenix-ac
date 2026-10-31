#pragma once

#include <Windows.h>
#include <cstdint>

namespace detections::baseline
{
    enum flag : uint32_t
    {
        flag_module_count       = 1u << 0,
        flag_module_weight      = 1u << 1,
        flag_unmapped_regions   = 1u << 2,
        flag_unmapped_size      = 1u << 3,
        flag_exec_regions       = 1u << 4,
        flag_suspicious_threads = 1u << 5,
        flag_private_usage      = 1u << 6,
    };

    enum class severity : uint8_t
    {
        clean     = 0,
        suspect   = 1,
        likely    = 2,
        confirmed = 3,
    };

    struct snapshot
    {
        size_t module_count     = 0;
        size_t module_weight    = 0;
        size_t unmapped_regions = 0;
        size_t unmapped_size    = 0;
        size_t exec_regions     = 0;
        size_t suspicious_threads = 0;
        size_t private_usage    = 0;
    };

    struct result
    {
        uint32_t flags     = 0;
        severity level     = severity::clean;
        snapshot current{};
        snapshot baseline{};
        int delta_modules          = 0;
        int delta_unmapped_regions = 0;
        int delta_unmapped_size    = 0;
        int delta_exec_regions     = 0;
        int delta_suspicious_threads = 0;
    };

    void reset();
    bool has_baseline();
    result scan(DWORD fivem_pid);
    const wchar_t* severity_name(severity s);
}
