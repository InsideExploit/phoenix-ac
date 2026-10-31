#pragma once

#include <ntifs.h>

#include "shared.hpp"

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MemQueryModule(
    _In_  UINT32            Pid,
    _Out_ KG_MODULE_RESULT* Out
);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MemScan(
    _In_  const KG_SCAN_REQUEST* Req,
    _Out_ KG_SCAN_RESULT*        Out
);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MemRead(
    _In_                             UINT32   Pid,
    _In_                             UINT64   Address,
    _Out_writes_bytes_to_(Size, *Copied) PVOID Dest,
    _In_                             SIZE_T   Size,
    _Out_                            SIZE_T*  Copied
);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MemWrite(
    _In_                       UINT32       Pid,
    _In_                       UINT64       Address,
    _In_reads_bytes_(Size)     const VOID*  Source,
    _In_                       SIZE_T       Size,
    _Out_                      SIZE_T*      Copied
);
