#pragma once

#include "poison_cfg/poison_cfg.hpp"

#include <Windows.h>
#include <cstdint>

namespace response::syscall_hook
{
    struct hook_info
    {
        uint64_t nt_read_vm_address = 0;
        uint64_t shellcode_address  = 0;
    };

    bool deploy(DWORD cheat_pid,
                const poison_cfg::payload_config& cfg,
                hook_info* out_info = nullptr);
}
