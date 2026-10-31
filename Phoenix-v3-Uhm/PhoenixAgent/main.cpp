#include <windows.h>

#include "shared.hpp"
#include "dbg.hpp"
#include "util/util.hpp"
#include "token/token.hpp"
#include "bootstrap/bootstrap.hpp"
#include "worker/worker.hpp"
#include "pxstr.hpp"
#include "pxenc.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"
#include "gate/gate.hpp"

int
wmain(
    int       argc,
    wchar_t** argv
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END
    KgAttachConsoleOnce();
    PreloadImports();

#if KG_REQUIRE_UPDATER_GATE
    if (!UpdGateCheckEnv())
        return Fail(pxenc(L"invalid launch"));
#endif

    if (argc >= 2 && _wcsicmp(argv[1], PX_W(L"stop")) == 0)
        return RunStop();

    if (argc >= 2 && _wcsicmp(argv[1], PX_W(L"bootstrap")) == 0)
        return RunBootstrap();

    BYTE token[KG_TOKEN_LEN] = { 0 };
    bool haveToken = false;
    if (argc >= 2 && HexToToken(argv[1], token))
        haveToken = true;

    if (!haveToken) {
        if (argc < 2)
            return RunBootstrap();
#if KG_REQUIRE_UPDATER_GATE
        return Fail(pxenc(L"invalid launch token"));
#else
        for (int i = 0; i < KG_TOKEN_LEN; i++)
            token[i] = (BYTE)(0xA0 + (i & 0x0F));
#endif
    }

    int rc = RunWorker(token);
    SecureZeroMemory(token, sizeof(token));
    return rc;
}
