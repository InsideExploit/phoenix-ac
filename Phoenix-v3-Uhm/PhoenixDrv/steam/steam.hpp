#pragma once

#include <ntifs.h>

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
ReadActiveSteamId64(
    _Out_ UINT64* Out
);
