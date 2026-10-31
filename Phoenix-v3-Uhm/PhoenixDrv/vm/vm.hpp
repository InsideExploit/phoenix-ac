#pragma once

#include "shared.hpp"

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
IsRunningInDisallowedVm(
    VOID
);
