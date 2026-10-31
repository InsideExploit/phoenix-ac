#pragma once

#include "poison_cfg/poison_cfg.hpp"

#include <Windows.h>
#include <cstddef>

namespace response::anchor_sweep
{
    struct stats
    {
        bool   ok           = false;
        int    anchor_hits  = 0;
        int    range_hits   = 0;
        size_t needle_count = 0;
        bool   full_nuke    = false;
    };

    bool wipe(DWORD cheat_pid,
              const poison_cfg::payload_config& cfg,
              HANDLE fivem_handle,
              bool full_nuke,
              stats* out_stats = nullptr);

    int probe(DWORD cheat_pid,
              const poison_cfg::payload_config& cfg,
              HANDLE fivem_handle,
              int early_exit = 3);
}
