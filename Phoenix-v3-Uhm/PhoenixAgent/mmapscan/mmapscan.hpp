#pragma once
#include <windows.h>

bool
MmapScanStart(
    HANDLE Device,
    HANDLE ReadyEvent
);

void
MmapScanStop(
);
