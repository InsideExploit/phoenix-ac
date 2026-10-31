#pragma once
#include <windows.h>

bool
EnableLoadDriverPrivilege(
);

bool
LocateDriverBinary(
    wchar_t Out[MAX_PATH]
);

bool
DriverIsPresent(
);

bool
DriverEnsureInstalled(
    const wchar_t* BinaryPath
);

bool
DriverStart(
);

bool
DriverStop(
);

bool
DriverUninstall(
);
