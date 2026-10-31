#pragma once
#include <ntifs.h>

NTSTATUS
Win32kInit(
    VOID
);

NTSTATUS
Win32kUncloakWindow(
    _In_ HANDLE HWnd,
    _In_ ULONG  Value
);
