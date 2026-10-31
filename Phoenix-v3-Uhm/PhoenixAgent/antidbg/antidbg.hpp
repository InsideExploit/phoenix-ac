#pragma once
#include <windows.h>

bool
AntiDbgStart(
    HANDLE StopEvent
);

void
AntiDbgStop(
);
