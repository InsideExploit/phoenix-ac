#pragma once

#include "shared.hpp"

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
HmacSha256(
    _In_reads_bytes_(KeyLen)  const UINT8* Key,
    _In_                      ULONG        KeyLen,
    _In_reads_bytes_(DataLen) const UINT8* Data,
    _In_                      ULONG        DataLen,
    _Out_writes_bytes_(32)    UINT8        Out[32]
);
