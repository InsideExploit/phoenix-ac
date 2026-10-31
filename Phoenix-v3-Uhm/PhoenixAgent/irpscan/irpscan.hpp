#pragma once
#include <windows.h>

bool
IrpScanStart(
    HANDLE Device,
    HANDLE ReadyEvent
);

void
IrpScanStop(
);
