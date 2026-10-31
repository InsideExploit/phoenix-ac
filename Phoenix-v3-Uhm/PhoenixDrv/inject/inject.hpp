#pragma once

#include <ntifs.h>
#include "shared.hpp"

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
InjectAllocInTarget(
    _In_  HANDLE  TargetPid,
    _In_  SIZE_T  Size,
    _In_  ULONG   Protect,
    _Out_ PVOID*  OutBase
);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
InjectQueueUserApc(
    _In_ HANDLE  TargetPid,
    _In_ HANDLE  TargetTid,
    _In_ PVOID   UserRoutine,
    _In_ PVOID   Arg1,
    _In_ PVOID   Arg2,
    _In_ PVOID   Arg3
);
