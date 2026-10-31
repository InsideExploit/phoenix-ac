#pragma once
#include <windows.h>

bool
SysInfoCollectJson(
    char** OutJson,
    ULONG* OutLen
);

void
SysInfoFree(
    char* Json
);
