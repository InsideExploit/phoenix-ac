#pragma once
#include <windows.h>

LONG
SigVerifyTrust(
    const wchar_t* Path
);

bool
SigGetSignerSerialHex(
    const wchar_t* Path,
    char*          Out,
    size_t         OutCap
);

bool
SigIsTrustedWithSerial(
    const wchar_t* Path,
    const char*    ExpectedSerialHex
);
