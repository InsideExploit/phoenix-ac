#pragma once

#include <ntifs.h>

#include "shared.hpp"

extern volatile PVOID g_ProtectedOwner;

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
RegisterProtection(
    VOID
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
UnregisterProtection(
    VOID
);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
ProcessNotifyInstall(
    VOID
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
ProcessNotifyRemove(
    VOID
);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
ArmRelaunch(
    _In_ HANDLE       Creator,
    _In_reads_bytes_(BasenameLenBytes) const WCHAR* Basename,
    _In_ USHORT       BasenameLenBytes,
    _In_reads_bytes_(KG_TOKEN_LEN) const UINT8* Token
);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
AttestOwner(
    _In_ HANDLE       Caller,
    _In_reads_bytes_(KG_TOKEN_LEN) const UINT8* Token
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
DisableProtection(
    VOID
);

_IRQL_requires_max_(APC_LEVEL)
HANDLE
ProtectedOwnerId(
    VOID
);

_IRQL_requires_max_(APC_LEVEL)
VOID
GetLastBlock(
    _Out_ KG_LAST_BLOCK* Out
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
KillAllTrusted(
    VOID
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
KillAllProtected(
    VOID
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
KillAllProtectedExceptCaller(
    VOID
);

_IRQL_requires_max_(APC_LEVEL)
UINT32
TrustedCount(
    VOID
);

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
TrustedContains(
    _In_ HANDLE Pid
);

_IRQL_requires_max_(APC_LEVEL)
UINT32
TrustedSnapshot(
    _Out_writes_to_(MaxPids, return) HANDLE* Pids,
    _In_ UINT32 MaxPids
);
