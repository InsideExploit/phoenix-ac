#pragma once

#include "shared.hpp"

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
CollectSecurityState(
    _Out_ KG_STATUS_REPORT* Out
);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
PostureMeetsPolicy(
    _In_opt_ const KG_STATUS_REPORT* Report
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
RunHvciSpoofProbeAndReport(
    VOID
);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
IsSystemInsecureBootMode(
    VOID
);
