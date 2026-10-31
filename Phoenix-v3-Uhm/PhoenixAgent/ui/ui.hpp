#pragma once
#include <windows.h>

void
ShowPostureBox(
    HANDLE Device
);

void
ShowVmBox(
);

void
ShowIncompatibleFileBox(
    const wchar_t* Path,
    const wchar_t* Reason
);

void
ShowVulnerableDriverBox(
    const wchar_t* Path
);

void
ShowNoSteamBox(
);

void
ShowNoConnectionBox(
);

bool
CommitCriticalVulnDrv(
    HANDLE         Device,
    const wchar_t* Path
);
