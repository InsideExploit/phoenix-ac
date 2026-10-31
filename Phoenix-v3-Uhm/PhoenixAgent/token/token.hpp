#pragma once
#include <windows.h>
#include "shared.hpp"

#define KG_TOKEN_HEX_CHARS (KG_TOKEN_LEN * 2)

void
TokenToHex(
    const BYTE Token[KG_TOKEN_LEN],
    wchar_t    Out[KG_TOKEN_HEX_CHARS + 1]
);

bool
HexToToken(
    const wchar_t* Hex,
    BYTE           Token[KG_TOKEN_LEN]
);
