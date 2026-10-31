#pragma once
#include <windows.h>

#define KG_CAPTURE_AUTO   0
#define KG_CAPTURE_NVIDIA 1
#define KG_CAPTURE_GDI    2

bool
CaptureScreenshot(
    UINT64      SteamId64,
    const char* Reason,
    BYTE**      OutPng,
    ULONG*      OutPngLen,
    wchar_t*    OutPath,
    size_t      OutPathCap,
    int         Method = KG_CAPTURE_AUTO
);

void
CaptureFree(
    BYTE* Png
);
