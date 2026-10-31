#pragma once
#include <windows.h>

int
Fail(
    const wchar_t* Msg,
    DWORD          Err = 0
);

bool
IsElevated();

void
PreloadImports();

bool
GetOwnPath(
    wchar_t Out[MAX_PATH]
);

const wchar_t*
BasenameOf(
    const wchar_t* Path
);

bool
IsSteamRunning();
