#include "bootstrap.hpp"
#include <windows.h>

#include "shared.hpp"
#include "service/service.hpp"
#include "util/util.hpp"
#include "ui/ui.hpp"
#include "agentui/agentui.hpp"
#include "net/proto.hpp"
#include "../dbg.hpp"
#include "pxstr.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

#define KG_PROBE_HOST KG_BACKEND_HOST_STR
#define KG_PROBE_PORT KG_BACKEND_PORT_STR
#define KG_PROBE_CONNECT_TIMEOUT_MS 3000
#define KG_PROBE_IO_TIMEOUT_MS      3000

static
bool
ProbeBackend()
{
    BRKIDA;
    if (!NetInit())
        return false;

    SOCKET s = NetDial(pxenc(KG_PROBE_HOST), pxenc(KG_PROBE_PORT),
                       KG_PROBE_CONNECT_TIMEOUT_MS, KG_PROBE_IO_TIMEOUT_MS);
    bool ok = (s != INVALID_SOCKET);
    if (ok)
        NetClose(s);

    NetShutdown();
    return ok;
}

static
void
TeardownDriver()
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END
    DriverStop();
    DriverUninstall();
}

#define KG_STOP_EVENT_NAME L"Global\\PhoenixAC.Stop"

int
RunStop()
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END
    if (!IsElevated())
        return Fail(pxenc(L"admin required"));

    HANDLE stopEvent = LI_KERNEL(OpenEventW)(EVENT_MODIFY_STATE, FALSE,
                                             pxenc(KG_STOP_EVENT_NAME));
    if (stopEvent) {
        LI_KERNEL(SetEvent)(stopEvent);
        LI_KERNEL(CloseHandle)(stopEvent);
        LI_KERNEL(Sleep)(500);
    }

    TeardownDriver();
    return 0;
}

int
RunBootstrap()
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END
    KGDBG(L"[*] bootstrap enter\n");

    if (!IsSteamRunning()) {
        ShowNoSteamBox();
        return Fail(pxenc(L"steam not running"));
    }

    if (!IsElevated())
        return Fail(pxenc(L"admin required"));

    if (!ProbeBackend()) {
        ShowNoConnectionBox();
        return Fail(pxenc(L"backend unreachable"));
    }

    int rc = AgentUiRun();

    TeardownDriver();
    return rc;
}
