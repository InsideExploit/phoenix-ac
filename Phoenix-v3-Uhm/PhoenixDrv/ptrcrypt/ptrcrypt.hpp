#pragma once

#include <ntifs.h>
#include "shared.hpp"

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
PtrCryptArm(
    _In_  HANDLE  Pid,
    _In_  HANDLE  Tid,
    _In_  PVOID   TargetPtrAddr,
    _In_  PVOID   RtlAvehAddr,
    _In_  UINT64  Sentinel,
    _Out_ PVOID*  OutAllocBase,
    _Out_ UINT64* OutRealValue
);
