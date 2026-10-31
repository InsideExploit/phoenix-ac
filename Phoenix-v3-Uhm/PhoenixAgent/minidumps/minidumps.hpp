#pragma once
#include <windows.h>

bool
MinidumpsCollectJson(
    char** OutJson,
    ULONG* OutLen
);

void
MinidumpsFree(
    char* Json
);

bool
MinidumpsReadOne(
    const char*  RequestedName,
    BYTE**       OutData,
    ULONG*       OutLen
);

void
MinidumpsFreeBlob(
    BYTE* Data
);
