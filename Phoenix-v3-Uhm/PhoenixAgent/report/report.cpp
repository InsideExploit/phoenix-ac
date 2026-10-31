#include "report.hpp"
#include <windows.h>
#include <lmcons.h>
#include <stdio.h>
#include <string.h>
#include "pxstr.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

static
void
EscapeJsonUtf8(
    const char* in,
    char*       out,
    size_t      outCap
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END
    size_t o = 0;
    if (!in) {
        if (outCap)
            out[0] = 0;

        return;
    }

    for (size_t i = 0; in[i] && o + 8 < outCap; i++) {
        unsigned char c = (unsigned char)in[i];
        switch (c) {
            case '"':  out[o++] = '\\'; out[o++] = '"'; break;
            case '\\': out[o++] = '\\'; out[o++] = '\\'; break;
            case '\b': out[o++] = '\\'; out[o++] = 'b'; break;
            case '\f': out[o++] = '\\'; out[o++] = 'f'; break;
            case '\n': out[o++] = '\\'; out[o++] = 'n'; break;
            case '\r': out[o++] = '\\'; out[o++] = 'r'; break;
            case '\t': out[o++] = '\\'; out[o++] = 't'; break;
            default:
                if (c < 0x20)
                    o += snprintf(out + o, outCap - o, "\\u%04x", c);
                else
                    out[o++] = (char)c;
        }
    }

    if (o < outCap)
        out[o] = 0;
    else
        out[outCap - 1] = 0;
}

static
void
WideToUtf8(
    const wchar_t* in,
    char*          out,
    size_t         outCap
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END
    if (!in || !outCap) {
        if (outCap)
            out[0] = 0;

        return;
    }

    int r = LI_KERNEL(WideCharToMultiByte)(CP_UTF8, 0, in, -1, out, (int)outCap - 1, NULL, NULL);
    if (r <= 0)
        out[0] = 0;

    out[outCap - 1] = 0;
}

static
void
GetIsoTimestamp(
    char*  out,
    size_t outCap
)
{
    VIRTUALIZER_START
    BRKIDA;
    SYSTEMTIME st;
    LI_KERNEL(GetLocalTime)(&st);
    snprintf(out, outCap, PX_A("%04u-%02u-%02uT%02u:%02u:%02u.%03u"),
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    VIRTUALIZER_END
}

static
void
GetOsBanner(
    char*  out,
    size_t outCap
)
{
    VIRTUALIZER_START
    BRKIDA;
    OSVERSIONINFOEXW v = { 0 };
    v.dwOSVersionInfoSize = sizeof(v);
#pragma warning(push)
#pragma warning(disable: 4996)
    LI_KERNEL(GetVersionExW)((LPOSVERSIONINFOW)&v);
#pragma warning(pop)
    snprintf(out, outCap, PX_A("Windows %lu.%lu.%lu"),
             (unsigned long)v.dwMajorVersion,
             (unsigned long)v.dwMinorVersion,
             (unsigned long)v.dwBuildNumber);
    VIRTUALIZER_END
}

static
void
GetUserBanner(
    char*  out,
    size_t outCap
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END
    LI_KERNEL(LoadLibraryW)(pxenc(L"advapi32.dll"));
    wchar_t nameW[UNLEN + 1] = { 0 };
    DWORD   sz               = UNLEN + 1;
    if (LI_ADVAPI(GetUserNameW)(nameW, &sz))
        WideToUtf8(nameW, out, outCap);
    else if (outCap)
        out[0] = 0;
}

static
void
GetMachineBanner(
    char*  out,
    size_t outCap
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END
    wchar_t nameW[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
    DWORD   sz                                 = MAX_COMPUTERNAME_LENGTH + 1;
    if (LI_KERNEL(GetComputerNameW)(nameW, &sz))
        WideToUtf8(nameW, out, outCap);
    else if (outCap)
        out[0] = 0;
}

int
BuildToolExtrasJson(
    const wchar_t* FilePath,
    char*          Out,
    size_t         OutCap
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    if (!Out || OutCap < 4)
        return 0;

    Out[0] = 0;
    if (!FilePath || !FilePath[0])
        return 0;

    LI_KERNEL(LoadLibraryW)(pxenc(L"version.dll"));

    DWORD dummy = 0;
    DWORD sz    = LI_VERSION(GetFileVersionInfoSizeW)(FilePath, &dummy);
    if (sz == 0)
        return 0;

    void* blob = HeapAlloc(GetProcessHeap(), 0, sz);
    if (!blob)
        return 0;

    if (!LI_VERSION(GetFileVersionInfoW)(FilePath, 0, sz, blob)) {
        HeapFree(GetProcessHeap(), 0, blob);
        return 0;
    }

    struct { WORD lang, code; } *trans = NULL;
    UINT trLen = 0;
    if (!LI_VERSION(VerQueryValueW)(blob, pxenc(L"\\VarFileInfo\\Translation"), (LPVOID*)&trans, &trLen) || trLen < 4) {
        HeapFree(GetProcessHeap(), 0, blob);
        return 0;
    }

    auto keyW = [](size_t i) -> const wchar_t* {
        switch (i) {
        case 0: return PX_W(L"CompanyName");
        case 1: return PX_W(L"ProductName");
        case 2: return PX_W(L"OriginalFilename");
        case 3: return PX_W(L"InternalName");
        case 4: return PX_W(L"FileDescription");
        case 5: return PX_W(L"ProductVersion");
        case 6: return PX_W(L"FileVersion");
        default: return L"";
        }
    };
    auto keyA = [](size_t i) -> const char* {
        switch (i) {
        case 0: return PX_A("company");
        case 1: return PX_A("product");
        case 2: return PX_A("original");
        case 3: return PX_A("internal");
        case 4: return PX_A("description");
        case 5: return PX_A("productVersion");
        case 6: return PX_A("fileVersion");
        default: return "";
        }
    };
    const size_t keyCount = 7;

    int written = snprintf(Out, OutCap, PX_A("{"));
    if (written < 0 || (size_t)written >= OutCap) {
        HeapFree(GetProcessHeap(), 0, blob);
        return 0;
    }

    bool first = true;

    for (size_t i = 0; i < keyCount; i++) {
        wchar_t sub[128];
        _snwprintf_s(sub, _TRUNCATE,
                     PX_W(L"\\StringFileInfo\\%04x%04x\\%ls"),
                     trans[0].lang, trans[0].code, keyW(i));
        wchar_t* val  = NULL;
        UINT     vLen = 0;
        if (LI_VERSION(VerQueryValueW)(blob, sub, (LPVOID*)&val, &vLen) && val && vLen > 0) {
            char utf8[256];
            WideToUtf8(val, utf8, sizeof(utf8));
            char esc[512];
            EscapeJsonUtf8(utf8, esc, sizeof(esc));
            int n = snprintf(Out + written, OutCap - written,
                             PX_A("%s\"%s\":\"%s\""),
                             first ? PX_A("") : PX_A(","), keyA(i), esc);
            if (n <= 0 || (size_t)(written + n) >= OutCap)
                break;

            written += n;
            first = false;
        }
    }

    int n = snprintf(Out + written, OutCap - written, PX_A("}"));
    if (n > 0 && (size_t)(written + n) < OutCap)
        written += n;

    HeapFree(GetProcessHeap(), 0, blob);
    return written;
}

int
BuildDetectionJson(
    const char*    Type,
    const char*    Reason,
    const wchar_t* OffenderPath,
    const wchar_t* ScreenshotPath,
    const char*    Extras,
    char*          Out,
    size_t         OutCap
)
{
    BRKIDA;
    if (!Out || OutCap < 32)
        return 0;

    char ts[32];       GetIsoTimestamp(ts, sizeof(ts));
    char os[64];       GetOsBanner(os, sizeof(os));
    char user[128];    GetUserBanner(user, sizeof(user));
    char machine[128]; GetMachineBanner(machine, sizeof(machine));

    (void)ScreenshotPath;

    char offUtf[520] = { 0 };  WideToUtf8(OffenderPath, offUtf, sizeof(offUtf));

    char offEsc[1024], userEsc[256], machineEsc[256], reasonEsc[512], typeEsc[128];
    EscapeJsonUtf8(offUtf, offEsc, sizeof(offEsc));
    EscapeJsonUtf8(user, userEsc, sizeof(userEsc));
    EscapeJsonUtf8(machine, machineEsc, sizeof(machineEsc));
    EscapeJsonUtf8(Reason ? Reason : PX_A(""), reasonEsc, sizeof(reasonEsc));
    EscapeJsonUtf8(Type ? Type : PX_A("unknown"), typeEsc, sizeof(typeEsc));

    VIRTUALIZER_START
    int written = snprintf(Out, OutCap,
        PX_A("{\"ts\":\"%s\",\"type\":\"%s\",\"reason\":\"%s\","
             "\"path\":\"%s\","
             "\"sys\":{\"user\":\"%s\",\"machine\":\"%s\",\"os\":\"%s\"}"),
        ts, typeEsc, reasonEsc, offEsc, userEsc, machineEsc, os);

    if (written < 0 || (size_t)written >= OutCap) {
        Out[OutCap - 1] = 0;
        return 0;
    }

    if (Extras && Extras[0]) {
        int n = snprintf(Out + written, OutCap - written, PX_A(",\"extras\":%s"), Extras);
        if (n > 0 && (size_t)(written + n) < OutCap)
            written += n;
    }

    int n = snprintf(Out + written, OutCap - written, PX_A("}"));
    if (n > 0 && (size_t)(written + n) < OutCap)
        written += n;
    VIRTUALIZER_END

    Out[OutCap - 1] = 0;
    return written;
}
