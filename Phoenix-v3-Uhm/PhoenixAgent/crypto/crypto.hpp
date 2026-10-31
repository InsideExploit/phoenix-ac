#pragma once
#include <windows.h>

bool
HmacSha256(
    const BYTE* Key,
    ULONG       KeyLen,
    const BYTE* Data,
    ULONG       DataLen,
    BYTE        Out[32]
);

bool
SecureRandom(
    BYTE* Buffer,
    ULONG Length
);
