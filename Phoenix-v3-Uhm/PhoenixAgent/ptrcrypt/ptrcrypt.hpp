#pragma once
#include <windows.h>

bool
PtrCryptStart(
    HANDLE Device,
    HANDLE StopEvent
);

void
PtrCryptStop();
