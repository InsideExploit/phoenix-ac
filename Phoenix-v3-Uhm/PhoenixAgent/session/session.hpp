#pragma once
#include <windows.h>

bool
SessionStart(
    UINT64 SteamId64,
    HANDLE Device,
    HANDLE StopEvent,
    HANDLE ReadyEvent
);

void
SessionSetHwid(
    const char* HashHex,
    const char* Json,
    ULONG       JsonLen
);

void
SessionStop(
);

void
SessionGetSlotKey(
    BYTE Out[32]
);

bool
SessionSendDetection(
    const char*    Type,
    const char*    Reason,
    const wchar_t* Path,
    BYTE           Severity,
    const BYTE*    Payload    = nullptr,
    ULONG          PayloadLen = 0
);

UINT64
SessionGetSteamId(
);

bool
SessionIsAllowlisted(
);

typedef struct _KG_ALT_ENTRY {
    BYTE        Kind;
    const char* ExternalId;
    const char* Username;
    const char* Avatar;
} KG_ALT_ENTRY;

bool
SessionSendAltAccounts(
    const KG_ALT_ENTRY* Entries,
    ULONG               Count
);
