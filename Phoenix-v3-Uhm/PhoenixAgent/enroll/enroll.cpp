#include "enroll.hpp"
#include <stdio.h>
#include <string.h>
#include "../net/proto.hpp"
#include "../dbg.hpp"
#include "pxstr.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

#define KG_BACKEND_HOST KG_BACKEND_HOST_STR
#define KG_BACKEND_PORT KG_BACKEND_PORT_STR

#define KG_CONNECT_TIMEOUT_MS 4000
#define KG_IO_TIMEOUT_MS      5000

__declspec(noinline)
bool
CheckSteamRequired(
    UINT64 SteamId64,
    bool*  Required
)
{
    BRKIDA;
    if (!Required)
        return false;

    *Required = false;

    KGDBG(L"[enroll] probe start steam=0x%016llX\n", SteamId64);

    if (!NetInit())
        return false;

    auto fmtHex = PX_A("%llx");

    char steamStr[24];
    int n = _snprintf_s(steamStr, _TRUNCATE, fmtHex, SteamId64);
    if (n <= 0) {
        NetShutdown();
        return false;
    }

    VIRTUALIZER_START
    bool   ok = false;
    SOCKET s  = NetDial(pxenc(KG_BACKEND_HOST), pxenc(KG_BACKEND_PORT),
                        KG_CONNECT_TIMEOUT_MS, KG_IO_TIMEOUT_MS);
    VIRTUALIZER_END

    if (s != INVALID_SOCKET) {
        KG_SESSION_KEYS keys;
        UINT16          slen     = (UINT16)n;
        BYTE            reqBody[64];
        UINT16          rspOp    = 0;
        BYTE            rspBody[64];
        ULONG           rspLen   = sizeof(rspBody);
        BYTE            required = 0;
        volatile int    _vm_seal = 0;

        VIRTUALIZER_START
        if (NetHandshake(s, &keys)) {
            reqBody[0] = (BYTE)(slen >> 8);
            reqBody[1] = (BYTE)slen;
            memcpy(reqBody + 2, steamStr, slen);

            if (NetSendEncrypted(s, &keys, KG_OP_ENROLLMENT_QUERY, reqBody, 2 + slen) &&
                NetRecvEncrypted(s, &keys, &rspOp, rspBody, &rspLen) &&
                rspOp == KG_OP_ENROLLMENT_RESULT && rspLen >= 1) {
                required = rspBody[0];
                ok       = true;
            }
        }
        VIRTUALIZER_END
        _vm_seal = 1;
        (void)_vm_seal;

        if (ok) {
            *Required = required != 0;
            KGDBG(L"[enroll] required=%d\n", (int)*Required);
        } else KGDBG(L"[enroll] failed rspOp=%u rspLen=%lu\n", rspOp, rspLen);
    } else KGDBG(L"[enroll] dial failed\n");

    NetClose(s);
    NetShutdown();
    return ok;
}
