#pragma once

#include <ntifs.h>

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MmapStart(
    VOID
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
MmapStop(
    VOID
);

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
MmapPop(
    _Out_writes_bytes_to_(OutCap, *BytesReturned) PVOID OutBuf,
    _In_  ULONG   OutCap,
    _Out_ PULONG  BytesReturned
);
