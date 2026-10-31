#pragma once

#include <Windows.h>
#include <cstdint>

namespace detections::mapper
{
    enum class hit_type : uint8_t
    {
        mapper_mutex           = 0,
        ctfmon_exec_mem        = 1,
        diagtrack_fake         = 2,
        diagtrack_service_dll  = 3,
        svchost_svc_dll_hijack = 4,
        host_process_priv_exec = 5,
        host_process_mapped_pe = 6,
        shellcode_region       = 7,
        host_process_net_io    = 8,
        any_process_mapped_pe  = 9,
        any_process_erased_pe  = 10,
        module_stomped         = 11,
        netsh_helper_hijack    = 12,
    };

    struct hit
    {
        hit_type type;
        uint64_t address;
        uint32_t region_size;
        uint32_t pid;
        wchar_t  detail[160];
    };

    void scan(hit* out_buffer, int buffer_capacity, int* out_count);
}
