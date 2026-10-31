#pragma once
#include <windows.h>

bool
SlotStart(
    HANDLE     Device,
    const BYTE SlotKey[32],
    HANDLE     StopEvent
);

void
SlotStop();
