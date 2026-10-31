#pragma once

#include <ntifs.h>

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
RegFilterInstall(
    VOID
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
RegFilterUninstall(
    VOID
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
RegFilterScanNvStreamProof(
    VOID
);
