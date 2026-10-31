#pragma once
#include <windows.h>

bool
FiveMEnsureRoot();

bool
FiveMGetRoot(
    wchar_t Out[MAX_PATH]
);

bool
FiveMGetAppDir(
    wchar_t Out[MAX_PATH]
);

bool
LaunchFiveM();
