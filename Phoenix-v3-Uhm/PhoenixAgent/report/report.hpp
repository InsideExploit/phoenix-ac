#pragma once
#include <windows.h>

int
BuildDetectionJson(
    const char*    Type,
    const char*    Reason,
    const wchar_t* OffenderPath,
    const wchar_t* ScreenshotPath,
    const char*    Extras,
    char*          Out,
    size_t         OutCap
);

int
BuildToolExtrasJson(
    const wchar_t* FilePath,
    char*          Out,
    size_t         OutCap
);
