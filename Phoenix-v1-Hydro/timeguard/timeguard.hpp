#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>

namespace timeguard
{
    uint64_t resolve_target(HANDLE process, uint64_t module_base, uint64_t module_size);

    uint32_t make_token_public(const std::string& steam_hex);

    void stamp(HANDLE process, uint64_t target_addr, const std::string& steam_hex);
}
