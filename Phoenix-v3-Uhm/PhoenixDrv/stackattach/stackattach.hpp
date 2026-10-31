#pragma once

#include <ntifs.h>

#include "shared.hpp"

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
StackAttachStart(
    VOID
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
StackAttachStop(
    VOID
);
