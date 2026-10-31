#pragma once
#include <windows.h>

bool
WdaInspectStart(
    HANDLE StopEvent
);

void
WdaInspectStop(
);
