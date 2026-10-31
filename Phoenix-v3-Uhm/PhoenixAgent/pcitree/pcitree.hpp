#pragma once
#include <windows.h>

bool
PciTreeCollectJson(
    char** OutJson,
    ULONG* OutLen
);

void
PciTreeFree(
    char* Json
);
