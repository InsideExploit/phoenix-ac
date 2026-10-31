#pragma once
#include <windows.h>

bool
PciScanStart(
    HANDLE StopEvent
);

void
PciScanStop(
);
