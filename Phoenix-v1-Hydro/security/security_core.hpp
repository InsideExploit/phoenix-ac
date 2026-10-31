#pragma once

#include "security/analyst_guard.hpp"
#include "security/anti_analyst_checks.hpp"
#include "security/baselines.hpp"
#include "security/crash_silencer.hpp"
#include "security/detonator.hpp"
#include "security/harden.hpp"
#include "security/sentinel.hpp"
#include "security/sniffer_guard.hpp"
#include "security/stealth_exit.hpp"
#include "vendor/xorstr.hpp"
#include "webhook/webhook.hpp"

#include <cstdio>
#include <string>

namespace security::core
{
    inline void init()
    {
        crash_silencer::install();
        baselines::capture();
        detonator::start_guard();
        sentinel::start();
        harden::start();
        anti_analyst::start();
        sniffer_guard::start();
        analyst_guard::start();
    }

    inline void shutdown()
    {
        harden::stop();
        anti_analyst::stop();
        sniffer_guard::stop();
        analyst_guard::stop();
        sentinel::stop();
    }

    inline const char* layer_name(unsigned int layer)
    {
        switch (layer)
        {
        case 0:  return xorstr("PEB.BeingDebugged");
        case 1:  return xorstr("PEB.NtGlobalFlag");
        case 3:  return xorstr("ProcessDebugPort");
        case 4:  return xorstr("ProcessDebugObjectHandle");
        case 6:  return xorstr("CheckRemoteDebuggerPresent");
        case 7:  return xorstr("NtClose(invalid) -> INVALID_HANDLE exception");
        case 8:  return xorstr("HardwareBreakpoints (Dr0-Dr3)");
        case 9:  return xorstr("KernelDebuggerEnabled");
        case 11: return xorstr("DebuggerWindow class match");
        case 12: return xorstr("DebuggerModule loaded");
        case 13: return xorstr("ParentProcess is debugger");
        case 18: return xorstr("Watchdog exited unexpectedly");
        case 19: return xorstr("Dumper process running");
        case 20: return xorstr("ExternalReader (handle scan)");
        case 21: return xorstr("Watchdog heartbeat stale");
        default: return xorstr("unknown");
        }
    }

    inline void kill_layer(unsigned int layer)
    {
        const char* name = layer_name(layer);

        char body[256];
        snprintf(body, sizeof(body),
                 xorstr("Vector: anti_debug_layer\nLayer:  %u\nCheck:  %s\nAction: AC suicide via Detonator"),
                 layer, name);

        webhook::report_security(xorstr("AntiDebug"), name, body, 3);
        webhook::flush(500);

        char tag[96];
        snprintf(tag, sizeof(tag), xorstr("AntiDebug/%s"), name);
        detonator::trigger(tag, std::string(xorstr("layer=")) + std::to_string(layer));
    }
}
