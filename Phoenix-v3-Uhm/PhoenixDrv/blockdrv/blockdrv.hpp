#pragma once

#include <ntifs.h>

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
BlockdrvInstall(
    VOID
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
BlockdrvUninstall(
    VOID
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
BlockdrvScanLoadedAsync(
    VOID
);
