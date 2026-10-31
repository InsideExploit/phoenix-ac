#pragma once
#include <windows.h>
#include "shared.hpp"

HANDLE
OpenGuard(
);

bool
RegisterGuard(
    HANDLE Device
);

bool
QueryGuardStatus(
    HANDLE            Device,
    KG_STATUS_REPORT* Out
);

bool
ArmRelaunch(
    HANDLE         Device,
    const wchar_t* Basename,
    const BYTE     Token[KG_TOKEN_LEN]
);

bool
AttestGuard(
    HANDLE     Device,
    const BYTE Token[KG_TOKEN_LEN]
);

bool
QuerySteamId(
    HANDLE  Device,
    UINT64* Out
);

bool
ShutdownGuard(
    HANDLE Device
);

bool
QueryLastBlock(
    HANDLE         Device,
    KG_LAST_BLOCK* Out
);

bool
KillTrustedGuard(
    HANDLE Device
);

bool
QueryTrustedCount(
    HANDLE  Device,
    UINT32* Out
);

bool
QueryModuleInfo(
    HANDLE  Device,
    UINT32  Pid,
    UINT64* Base,
    UINT32* Size
);

bool
ScanPattern(
    HANDLE       Device,
    UINT32       Pid,
    UINT64       RangeStart,
    UINT64       RangeSize,
    const UINT8* Pattern,
    const UINT8* Mask,
    UINT32       Len,
    UINT64*      Hit
);

bool
ReadMem(
    HANDLE Device,
    UINT32 Pid,
    UINT64 Address,
    void*  Dest,
    UINT32 Size
);

bool
WriteMem(
    HANDLE      Device,
    UINT32      Pid,
    UINT64      Address,
    const void* Source,
    UINT32      Size
);

bool
QueryHwid(
    HANDLE          Device,
    KG_HWID_RESULT* Out
);

bool
UncloakWindow(
    HANDLE Device,
    HWND   Window,
    UINT32 Value
);
