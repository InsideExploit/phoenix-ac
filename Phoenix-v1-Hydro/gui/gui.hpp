#pragma once

#include <Windows.h>

namespace gui
{
    enum class state : int
    {
        waiting_for_fivem = 0,
        running           = 1,
        error             = 2,
        closing           = 3,
    };

    struct security_flags
    {
        bool checked     = false;
        bool tpm20       = false;
        bool secure_boot = false;
        bool hvci        = false;
    };

    bool create(HINSTANCE instance);
    void set_status(state new_state);
    void set_detail(const wchar_t* text);
    void set_security(security_flags flags);
    int  run_loop();
    void request_close();
}
