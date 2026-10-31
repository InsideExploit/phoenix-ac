#include "ui.hpp"
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include "shared.hpp"
#include "pxstr.hpp"
#include "guard/guard.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

extern "C" {
	NTSTATUS
	NTAPI
	NtRaiseHardError(
	    NTSTATUS   ErrorStatus,
	    ULONG      NumberOfParameters,
	    ULONG      UnicodeStringParameterMask,
	    PULONG_PTR Parameters,
	    ULONG      ResponseOption,
	    PULONG     Response
	);

	NTSTATUS
	NTAPI
	RtlAdjustPrivilege(
	    ULONG    Privilege,
	    BOOLEAN  Enable,
	    BOOLEAN  CurrentThread,
	    PBOOLEAN Enabled
	);
}

#define KG_SE_SHUTDOWN_PRIVILEGE 19
#define KG_HARDERROR_STATUS      ((NTSTATUS)0x50000018L)
#define KG_HARDERROR_MB_FLAGS    (0x00000010 | 0x00001000 | 0x00040000 | 0x00010000)

static
void
BuildPostureText(
    const KG_STATUS_REPORT& r,
    wchar_t*                body,
    size_t                  capacity
)
{
    VIRTUALIZER_START
    BRKIDA;
    wchar_t* p = body;
    size_t remain = capacity;

    int n = _snwprintf_s(p, remain, _TRUNCATE,
        PX_WS(L"You do not meet the following requirements in order to run:\n\n"));
    if (n > 0) { p += n; remain -= n; }

    if (r.SecureBoot != KgStateEnabled) {
        n = _snwprintf_s(p, remain, _TRUNCATE, PX_WS(L"    - UEFI Secure Boot enabled\n"));
        if (n > 0) { p += n; remain -= n; }
    }

    if (r.Hvci != KgStateEnabled) {
        n = _snwprintf_s(p, remain, _TRUNCATE, PX_WS(L"    - HVCI enabled\n"));
        if (n > 0) { p += n; remain -= n; }
    }

    _snwprintf_s(p, remain, _TRUNCATE,
        PX_WS(L"\nEnable the listed features in your system settings and reboot."));
    VIRTUALIZER_END
}

static
bool
RaiseHardError(
    const wchar_t* Body,
    const wchar_t* Title
)
{
    VIRTUALIZER_START
    BRKIDA;
    BOOLEAN oldPriv = FALSE;
    RtlAdjustPrivilege(KG_SE_SHUTDOWN_PRIVILEGE, TRUE, FALSE, &oldPriv);

    UNICODE_STRING us_body, us_title;
    RtlInitUnicodeString(&us_body,  (PWSTR)Body);
    RtlInitUnicodeString(&us_title, (PWSTR)Title);

    ULONG_PTR params[4];
    params[0] = (ULONG_PTR)&us_body;
    params[1] = (ULONG_PTR)&us_title;
    params[2] = KG_HARDERROR_MB_FLAGS;
    params[3] = (ULONG_PTR)-1;

    ULONG response = 0;
    NTSTATUS rc = NtRaiseHardError(KG_HARDERROR_STATUS,
                                   4, 0x00000003, params, 1, &response);
    VIRTUALIZER_END
    return NT_SUCCESS(rc);
}

static
void
FallbackMessageBox(
    const wchar_t* Body,
    const wchar_t* Title
)
{
    VIRTUALIZER_START
    BRKIDA;
    LI_KERNEL(LoadLibraryW)(pxenc(L"user32.dll"));
    typedef int (WINAPI *pMB)(HWND, LPCWSTR, LPCWSTR, UINT);
    pMB mb = (pMB)LI_USER32(MessageBoxW);
    if (mb) mb(NULL, Body, Title,
               MB_OK | MB_ICONERROR | MB_SYSTEMMODAL | MB_TOPMOST);
    VIRTUALIZER_END
}

static
void
NtPathToDos(
    const wchar_t* NtPath,
    wchar_t*       Out,
    size_t         Cap
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    if (!Out || Cap == 0)
        return;

    Out[0] = L'\0';
    if (!NtPath || !*NtPath) return;

    wchar_t drive[3] = { 0, L':', 0 };
    for (wchar_t d = L'A'; d <= L'Z'; ++d) {
        drive[0] = d;
        wchar_t target[256] = { 0 };
        if (QueryDosDeviceW(drive, target, 256) == 0) continue;

        size_t tLen = wcslen(target);
        if (tLen == 0) continue;

        if (_wcsnicmp(NtPath, target, tLen) == 0) {
            _snwprintf_s(Out, Cap, _TRUNCATE, PX_WS(L"%ls%ls"), drive, NtPath + tLen);
            return;
        }
    }

    _snwprintf_s(Out, Cap, _TRUNCATE, PX_WS(L"%ls"), NtPath);
}

void
ShowIncompatibleFileBox(
    const wchar_t* Path,
    const wchar_t* Reason
)
{
    VIRTUALIZER_START
    BRKIDA;
    (void)Reason;
    static wchar_t body[1024];
    auto title = PX_WS(L"PhoenixAC");

    if (Path && Path[0]) {
        _snwprintf_s(body, _TRUNCATE,
            PX_WS(L"We've detected unauthorized third-party software on your system.\n\n"
                 L"    Location: %ls\n\n"
                 L"Usage of third-party software is prohibited.\n\n"
                 L"To play ENVEART you must remove any incompatible software."),
            Path);
    } else {
        _snwprintf_s(body, _TRUNCATE,
            PX_WS(L"We've detected unauthorized third-party software on your system.\n\n"
                 L"Usage of third-party software is prohibited.\n\n"
                 L"To play ENVEART you must remove any incompatible software."));
    }

    VIRTUALIZER_END;
    if (!RaiseHardError(body, title))
        FallbackMessageBox(body, title);
}

void
ShowVmBox(
)
{
    VIRTUALIZER_START
    BRKIDA;
    auto body = PX_WS(
        L"We've detected that you're running inside a virtualized environment.\n\n"
        L"Boot into your bare-metal operating system and try again.");
    auto title = PX_WS(L"PhoenixAC: Virtual Machine");
    VIRTUALIZER_END;
    if (!RaiseHardError(body, title))
        FallbackMessageBox(body, title);
}

void
ShowNoSteamBox(
)
{
    VIRTUALIZER_START
    BRKIDA;
    auto body = PX_WS(
        L"Steam is not currently running on your system.\n\n"
        L"Open Steam and sign in to your account before you can play ENVEART.");
    auto title = PX_WS(L"PhoenixAC: Steam Not Running");
    VIRTUALIZER_END;
    if (!RaiseHardError(body, title))
        FallbackMessageBox(body, title);
}

void
ShowNoConnectionBox(
)
{
    VIRTUALIZER_START
    BRKIDA;
    auto body = PX_WS(
        L"The PhoenixAC backend is unreachable.\n\n"
        L"Check your internet connection and try again in a moment.");
    auto title = PX_WS(L"PhoenixAC: Backend Unreachable");
    VIRTUALIZER_END;
    if (!RaiseHardError(body, title))
        FallbackMessageBox(body, title);
}

void
ShowVulnerableDriverBox(
    const wchar_t* Path
)
{
    VIRTUALIZER_START
    BRKIDA;
    static wchar_t body[1024];
    wchar_t dosPath[512] = { 0 };
    if (Path && Path[0]) NtPathToDos(Path, dosPath, _countof(dosPath));

    auto title = PX_WS(L"PhoenixAC: Vulnerable Driver Detected");

    if (dosPath[0]) {
        _snwprintf_s(body, _TRUNCATE,
            PX_WS(L"A known vulnerable driver was detected on your system.\n\n"
                 L"    Driver: %ls\n\n"
                 L"Please stop and uninstall this driver, then restart your system before playing ENVEART."),
            dosPath);
    } else if (Path && Path[0]) {
        _snwprintf_s(body, _TRUNCATE,
            PX_WS(L"A known vulnerable driver was detected on your system.\n\n"
                 L"    Driver: %ls\n\n"
                 L"Please stop and uninstall this driver, then restart your system before playing ENVEART."),
            Path);
    } else {
        _snwprintf_s(body, _TRUNCATE,
            PX_WS(L"A known vulnerable driver was detected on your system.\n\n"
                 L"Please stop and uninstall it, then restart your system before playing ENVEART."));
    }

    VIRTUALIZER_END;
    if (!RaiseHardError(body, title))
        FallbackMessageBox(body, title);
}

bool
CommitCriticalVulnDrv(
    HANDLE         Device,
    const wchar_t* Path
)
{
    VIRTUALIZER_START
    BRKIDA;
    if (!Device || Device == INVALID_HANDLE_VALUE) return false;

    KG_CRITICAL_COMMIT req = { 0 };

    auto title = PX_WS(L"PhoenixAC: Vulnerable Driver Detected");
    size_t tchars = wcslen(title);
    if (tchars > KG_CRITICAL_TITLE_MAX - 1) tchars = KG_CRITICAL_TITLE_MAX - 1;
    memcpy(req.Title, title, tchars * sizeof(wchar_t));
    req.TitleLen = (UINT16)(tchars * sizeof(wchar_t));

    wchar_t dosPath[512] = { 0 };
    if (Path && Path[0]) NtPathToDos(Path, dosPath, _countof(dosPath));

    wchar_t body[KG_CRITICAL_BODY_MAX];
    if (dosPath[0]) {
        _snwprintf_s(body, _TRUNCATE,
            PX_WS(L"A known vulnerable driver was detected on your system.\n\n"
                 L"    Driver: %ls\n\n"
                 L"All protected processes have been terminated.\n"
                 L"Please stop and uninstall this driver, then restart your system before playing ENVEART."),
            dosPath);
    } else if (Path && Path[0]) {
        _snwprintf_s(body, _TRUNCATE,
            PX_WS(L"A known vulnerable driver was detected on your system.\n\n"
                 L"    Driver: %ls\n\n"
                 L"All protected processes have been terminated.\n"
                 L"Please stop and uninstall this driver, then restart your system before playing ENVEART."),
            Path);
    } else {
        _snwprintf_s(body, _TRUNCATE,
            PX_WS(L"A known vulnerable driver was detected on your system.\n\n"
                 L"All protected processes have been terminated.\n"
                 L"Please stop and uninstall it, then restart your system before playing ENVEART."));
    }

    size_t bchars = wcslen(body);
    if (bchars > KG_CRITICAL_BODY_MAX - 1) bchars = KG_CRITICAL_BODY_MAX - 1;
    memcpy(req.Body, body, bchars * sizeof(wchar_t));
    req.BodyLen = (UINT16)(bchars * sizeof(wchar_t));

    DWORD returned = 0;
    BOOL b = LI_KERNEL(DeviceIoControl)(Device, IOCTL_KG_CRITICAL_COMMIT,
                                        &req, sizeof(req),
                                        NULL, 0, &returned, NULL);
    VIRTUALIZER_END
    return !!b;
}

void
ShowPostureBox(
    HANDLE Device
)
{
    VIRTUALIZER_START
    BRKIDA;
    KG_STATUS_REPORT r = { 0 };
    if (!QueryGuardStatus(Device, &r)) {
        r.SecureBoot = KgStateUnknown;
        r.Hvci       = KgStateUnknown;
    }

    static wchar_t body[512];
    BuildPostureText(r, body, _countof(body));

    auto title = PX_WS(L"PhoenixAC: Restriction");
    VIRTUALIZER_END
    if (!RaiseHardError(body, title))
        FallbackMessageBox(body, title);
}
