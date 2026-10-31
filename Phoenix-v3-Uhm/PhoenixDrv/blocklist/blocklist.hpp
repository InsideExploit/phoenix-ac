#pragma once

#include <ntifs.h>

typedef struct _KG_BLOCKED_HIT {
    WCHAR Reason[64];
} KG_BLOCKED_HIT, *PKG_BLOCKED_HIT;

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
BlocklistMatchByPath(
    _In_  PCUNICODE_STRING  ImagePath,
    _Out_ PKG_BLOCKED_HIT   Out
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
BlocklistSweepRunning(
    VOID
);
