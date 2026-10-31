#pragma once

#include <string>

namespace auth
{
    struct result
    {
        bool ok            = false;
        bool anticheat_required = false;
        int  ttl_seconds   = 300;
    };

    bool get_steam_id_hex(std::string& out_hex);
    bool is_steam_running();
    bool get_disk_id(std::string& out_id);

    bool check_authorization(const std::string& steam_hex, result& out_result);
}
