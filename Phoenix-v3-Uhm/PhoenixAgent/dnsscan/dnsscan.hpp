#pragma once
#include <windows.h>

bool
DnsScanStart(
    HANDLE ReadyEvent
);

void
DnsScanStop(
);
