#pragma once

#include <ntifs.h>

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
IntegrityStart(
    VOID
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
IntegrityStop(
    VOID
);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
IntegrityRegister(
    _In_opt_ PVOID FnAddr
);

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
IntegrityIsPoisoned(
    VOID
);
