#pragma once

#include <ntifs.h>

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
WfpInstall(
    _In_ PDRIVER_OBJECT Driver
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
WfpUninstall(
    VOID
);

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
NetmonPop(
    _Out_writes_bytes_to_(OutCap, *BytesReturned) PVOID OutBuf,
    _In_  ULONG   OutCap,
    _Out_ PULONG  BytesReturned
);
