#pragma once

#include <cstdint>

namespace poison_cfg
{
    struct syscall_numbers
    {
        uint32_t nt_read_virtual_memory;
        uint32_t nt_query_information_process;
    };

    struct payload_config
    {
        uint64_t viewport;
        uint64_t viewport_end;
        uint64_t cam_dir;
        uint64_t cam_end;
        uint64_t world;
        uint64_t ped_pool;
        uint64_t blip_list;
        uint64_t aim;

        uint64_t viewport_runtime;
        uint32_t fivem_pid;
        uint32_t ssn_nt_read_virtual_memory;
        uint32_t ssn_nt_query_information_process;
    };

    syscall_numbers resolve_syscall_numbers();
}
