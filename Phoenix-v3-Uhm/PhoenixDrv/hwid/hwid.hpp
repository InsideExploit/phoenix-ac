#pragma once

#include <ntifs.h>

#include "shared.hpp"

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
HwidCollect(
    _Out_ KG_HWID_RESULT* Out
);
