#pragma once
#include <windows.h>
#include <string.h>
#include "brkida.hpp"
#include "lazy_importer.hpp"
#include "pxenc.hpp"
#include "pxstr.hpp"

#ifndef VIRTUALIZER_START
#define VIRTUALIZER_START
#endif
#ifndef VIRTUALIZER_END
#define VIRTUALIZER_END
#endif

#define UPD_GATE_ENV_NAME       L"PHOENIX_UPDATER_GATE"
#define UPD_GATE_LABEL          "phoenixac/gate/v1"
#define UPD_GATE_LABEL_LEN      17
#define UPD_GATE_BUCKET_SECONDS 60
#define UPD_GATE_HEX_LEN        64

static const BYTE UPD_GATE_SECRET[32] = { 0 }; // REDACTED

bool HmacSha256(const BYTE*, ULONG, const BYTE*, ULONG, BYTE[32]);

static __declspec(noinline)
UINT64
UpdGateNowBucket()
{
    FILETIME ft;
    LI_KERNEL(GetSystemTimeAsFileTime)(&ft);
    UINT64 ft64 = ((UINT64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    return ((ft64 - 116444736000000000ULL) / 10000000ULL) / UPD_GATE_BUCKET_SECONDS;
}

static __declspec(noinline)
bool
UpdGateComputeTag(UINT64 bucket, BYTE tag[32])
{
    BYTE msg[UPD_GATE_LABEL_LEN + 8];
    memcpy(msg, PX_A(UPD_GATE_LABEL), UPD_GATE_LABEL_LEN);
    for (int i = 0; i < 8; i++)
        msg[UPD_GATE_LABEL_LEN + i] = (BYTE)(bucket >> (56 - i * 8));
    return HmacSha256(UPD_GATE_SECRET, 32, msg, sizeof(msg), tag);
}

static __declspec(noinline)
void
UpdGateHex(const BYTE tag[32], wchar_t out[UPD_GATE_HEX_LEN + 1])
{
    for (int i = 0; i < 32; i++) {
        BYTE hi = (BYTE)(tag[i] >> 4);
        BYTE lo = (BYTE)(tag[i] & 0xf);
        out[i * 2]     = (wchar_t)(hi < 10 ? (L'0' + hi) : (L'a' + hi - 10));
        out[i * 2 + 1] = (wchar_t)(lo < 10 ? (L'0' + lo) : (L'a' + lo - 10));
    }
    out[UPD_GATE_HEX_LEN] = 0;
}

static __declspec(noinline)
bool
UpdGateSetEnv()
{
    VIRTUALIZER_START
    BRKIDA;
    BYTE tag[32];
    if (!UpdGateComputeTag(UpdGateNowBucket(), tag))
        return false;
    wchar_t hex[UPD_GATE_HEX_LEN + 1];
    UpdGateHex(tag, hex);
    BOOL ok = LI_KERNEL(SetEnvironmentVariableW)(pxenc(UPD_GATE_ENV_NAME), hex);
    SecureZeroMemory(tag, sizeof(tag));
    SecureZeroMemory(hex, sizeof(hex));
    VIRTUALIZER_END
    return ok != 0;
}

static __declspec(noinline)
int
UpdGateHexNyb(wchar_t c)
{
    if (c >= L'0' && c <= L'9') return c - L'0';
    if (c >= L'a' && c <= L'f') return c - L'a' + 10;
    if (c >= L'A' && c <= L'F') return c - L'A' + 10;
    return -1;
}

static __declspec(noinline)
bool
UpdGateCheckEnv()
{
    VIRTUALIZER_START
    BRKIDA;
    wchar_t hex[UPD_GATE_HEX_LEN + 4];
    DWORD n = LI_KERNEL(GetEnvironmentVariableW)(pxenc(UPD_GATE_ENV_NAME), hex, UPD_GATE_HEX_LEN + 3);
    LI_KERNEL(SetEnvironmentVariableW)(pxenc(UPD_GATE_ENV_NAME), NULL);
    if (n != UPD_GATE_HEX_LEN)
        return false;

    BYTE got[32];
    for (int i = 0; i < 32; i++) {
        int hi = UpdGateHexNyb(hex[i * 2]);
        int lo = UpdGateHexNyb(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        got[i] = (BYTE)((hi << 4) | lo);
    }
    SecureZeroMemory(hex, sizeof(hex));

    UINT64 bucket = UpdGateNowBucket();
    bool match = false;
    for (int off = -1; off <= 1 && !match; off++) {
        BYTE expect[32];
        if (!UpdGateComputeTag(bucket + off, expect))
            continue;
        ULONG diff = 0;
        for (int i = 0; i < 32; i++) diff |= (ULONG)(expect[i] ^ got[i]);
        SecureZeroMemory(expect, sizeof(expect));
        if (diff == 0) match = true;
    }
    SecureZeroMemory(got, sizeof(got));
    VIRTUALIZER_END
    return match;
}
