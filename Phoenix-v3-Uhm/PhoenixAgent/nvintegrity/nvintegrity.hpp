#pragma once
#include <windows.h>

bool
NvIntegrityStart(
    HANDLE Device,
    HANDLE StopEvent
);

void
NvIntegrityStop(
);
