#include <windows.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "config.hpp"
#include "net/net.hpp"
#include "crypto/crypto.hpp"
#include "gate/gate.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "pxenc.hpp"
#include "pxstr.hpp"

#define UPD_CONNECT_TIMEOUT_MS 10000
#define UPD_IO_TIMEOUT_MS      30000
#define UPD_MAX_RETRIES        3
#define UPD_RETRY_DELAY_MS     1500

#define UPD_MAX_AGENT (128u * 1024u * 1024u)
#define UPD_MAX_DRV   ( 64u * 1024u * 1024u)

enum {
    E_OK           =    0,
    E_NET_INIT     = -101,
    E_DIAL         = -102,
    E_HANDSHAKE    = -103,
    E_RECV_MAN     = -104,
    E_SRV_ERR      = -105,
    E_BAD_MAN      = -106,
    E_BAD_SIZE     = -107,
    E_ALLOC        = -108,
    E_HASH_INIT    = -109,
    E_RECV_CHUNK   = -110,
    E_CHUNK_ERR    = -120,
    E_CHUNK_AGENT  = -121,
    E_CHUNK_DRV    = -122,
    E_INCOMPLETE   = -123,
    E_HASH_FINAL   = -124,
    E_SHA_MISMATCH = -125,
    E_INSTALL_DIR  = -126,
    E_WRITE_AGENT  = -130,
    E_WRITE_DRV    = -131,
    E_VERIFY_OPEN  = -140,
    E_VERIFY_DIFF  = -143,
    E_GATE         = -150,
    E_LAUNCH       = -160,
    E_SEH_INNER    = -200,
    E_SEH_OUTER    = -999,
};

struct Manifest {
    UINT16 agentMajor, agentMinor, agentBuild, agentRevision;
    UINT16 drvMajor,   drvMinor,   drvBuild,   drvRevision;
    BYTE   agentSha[32];
    BYTE   drvSha[32];
    UINT64 agentSize;
    UINT64 drvSize;
};

static wchar_t g_LogPath[MAX_PATH] = { 0 };

static const BYTE UPD_LOG_KEY[32] = { 0 }; // REDACTED

static const BYTE UPD_LOG_MAGIC[8] = { 'P','X','L','O','G', 0x01, 0x00, 0x00 };

static volatile LONG g_LogMagicReady = 0;

static void
InitLog()
{
    wchar_t base[MAX_PATH] = { 0 };
    if (LI_SHELL32(SHGetFolderPathW)(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, base) != S_OK) return;

    wchar_t d1[MAX_PATH], d2[MAX_PATH], d3[MAX_PATH];
    _snwprintf_s(d1, _TRUNCATE, pxenc(L"%ls\\PhoenixAC"),             base);
    _snwprintf_s(d2, _TRUNCATE, pxenc(L"%ls\\PhoenixAC\\logs"),       base);
    _snwprintf_s(d3, _TRUNCATE, pxenc(L"%ls\\PhoenixAC\\logs\\updater"), base);
    LI_KERNEL(CreateDirectoryW)(d1, NULL);
    LI_KERNEL(CreateDirectoryW)(d2, NULL);
    LI_KERNEL(CreateDirectoryW)(d3, NULL);

    SYSTEMTIME st; LI_KERNEL(GetLocalTime)(&st);
    _snwprintf_s(g_LogPath, _TRUNCATE,
                 pxenc(L"%ls\\%04u-%02u-%02u_%02u-%02u-%02u.log"),
                 d3, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

static void
LogEnsureMagic()
{
    if (InterlockedCompareExchange(&g_LogMagicReady, 0, 0) != 0) return;
    HANDLE h = LI_KERNEL(CreateFileW)(g_LogPath, GENERIC_WRITE,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE,
                                      NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER sz{};
    if (!LI_KERNEL(GetFileSizeEx)(h, &sz)) {
        LI_KERNEL(CloseHandle)(h);
        return;
    }
    if (sz.QuadPart == 0) {
        DWORD w = 0;
        BOOL ok = LI_KERNEL(WriteFile)(h, UPD_LOG_MAGIC, sizeof(UPD_LOG_MAGIC), &w, NULL);
        if (!ok || w != sizeof(UPD_LOG_MAGIC)) {
            LI_KERNEL(CloseHandle)(h);
            return;
        }
    } else if (sz.QuadPart < (LONGLONG)sizeof(UPD_LOG_MAGIC)) {
        LI_KERNEL(CloseHandle)(h);
        return;
    }
    LI_KERNEL(CloseHandle)(h);
    InterlockedExchange(&g_LogMagicReady, 1);
}

static void
LogWrite(const char* channel, const char* fmt, ...)
{
    if (!g_LogPath[0]) return;
    LogEnsureMagic();

    SYSTEMTIME st; LI_KERNEL(GetLocalTime)(&st);
    char line[2048];
    int hdr = _snprintf_s(line, _TRUNCATE,
                          PX_AS("[%04u-%02u-%02u %02u:%02u:%02u] [%-5s] "),
                          st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, channel);
    if (hdr < 0 || hdr > 2046) hdr = 0;

    size_t room = 2048 - (size_t)hdr - 2;
    va_list ap; va_start(ap, fmt);
    int n = _vsnprintf_s(line + hdr, room, _TRUNCATE, fmt, ap);
    va_end(ap);
    if (n < 0) n = 0;

    size_t total = (size_t)hdr + (size_t)n;
    if (total + 1 < 2048) line[total++] = '\n';

    BYTE iv[16];
    if (!SecureRandom(iv, 16)) return;

    BYTE ct[2064 + 16];
    ULONG ctLen = sizeof(ct);
    if (!AesCbcEncrypt(UPD_LOG_KEY, iv, (const BYTE*)line, (ULONG)total, ct, &ctLen))
        return;

    HANDLE h = LI_KERNEL(CreateFileW)(g_LogPath, FILE_APPEND_DATA,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE,
                                      NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;

    BYTE lenBE[4] = {
        (BYTE)(ctLen >> 24), (BYTE)(ctLen >> 16),
        (BYTE)(ctLen >>  8), (BYTE) ctLen
    };
    DWORD w = 0;
    LI_KERNEL(WriteFile)(h, iv,    16,    &w, NULL);
    LI_KERNEL(WriteFile)(h, lenBE,  4,    &w, NULL);
    LI_KERNEL(WriteFile)(h, ct,    ctLen, &w, NULL);
    LI_KERNEL(CloseHandle)(h);
}

#define LOG_INFO(...) LogWrite(PX_AS("INFO"),  __VA_ARGS__)
#define LOG_WARN(...) LogWrite(PX_AS("WARN"),  __VA_ARGS__)
#define LOG_ERR(...)  LogWrite(PX_AS("ERROR"), __VA_ARGS__)
#define LOG_SEH(...)  LogWrite(PX_AS("SEH"),   __VA_ARGS__)

static int
ParseMode(const wchar_t* inputPath)
{
    HANDLE inH = LI_KERNEL(CreateFileW)(inputPath, GENERIC_READ, FILE_SHARE_READ,
                                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (inH == INVALID_HANDLE_VALUE) {
        LI_USER32(MessageBoxW)(NULL, pxenc(L"Cannot open input log."),
                               pxenc(L"PhoenixAC Updater - parse"), MB_OK | MB_ICONERROR);
        return 2;
    }

    BYTE magic[8]; DWORD rd = 0;
    if (!LI_KERNEL(ReadFile)(inH, magic, 8, &rd, NULL) || rd != 8 ||
        memcmp(magic, UPD_LOG_MAGIC, 8) != 0) {
        LI_KERNEL(CloseHandle)(inH);
        LI_USER32(MessageBoxW)(NULL, pxenc(L"Not a PhoenixAC encrypted log."),
                               pxenc(L"PhoenixAC Updater - parse"), MB_OK | MB_ICONERROR);
        return 3;
    }

    wchar_t outPath[MAX_PATH];
    _snwprintf_s(outPath, _TRUNCATE, pxenc(L"%ls.decrypted.log"), inputPath);
    HANDLE outH = LI_KERNEL(CreateFileW)(outPath, GENERIC_WRITE, FILE_SHARE_READ,
                                         NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (outH == INVALID_HANDLE_VALUE) {
        LI_KERNEL(CloseHandle)(inH);
        LI_USER32(MessageBoxW)(NULL, pxenc(L"Cannot create decrypted output."),
                               pxenc(L"PhoenixAC Updater - parse"), MB_OK | MB_ICONERROR);
        return 4;
    }

    ULONG count = 0;
    for (;;) {
        BYTE iv[16], lenBE[4];
        if (!LI_KERNEL(ReadFile)(inH, iv, 16, &rd, NULL) || rd == 0) break;
        if (rd != 16) break;
        if (!LI_KERNEL(ReadFile)(inH, lenBE, 4, &rd, NULL) || rd != 4) break;

        ULONG ctLen = ((ULONG)lenBE[0] << 24) | ((ULONG)lenBE[1] << 16) |
                      ((ULONG)lenBE[2] <<  8) |  (ULONG)lenBE[3];
        if (ctLen == 0 || ctLen > 8192 || (ctLen % 16) != 0) break;

        BYTE ct[8192], pt[8192];
        if (!LI_KERNEL(ReadFile)(inH, ct, ctLen, &rd, NULL) || rd != ctLen) break;

        ULONG ptLen = sizeof(pt);
        if (!AesCbcDecrypt(UPD_LOG_KEY, iv, ct, ctLen, pt, &ptLen)) break;

        DWORD w = 0;
        LI_KERNEL(WriteFile)(outH, pt, ptLen, &w, NULL);
        ++count;
    }
    LI_KERNEL(CloseHandle)(inH);
    LI_KERNEL(CloseHandle)(outH);

    wchar_t msg[512];
    _snwprintf_s(msg, _TRUNCATE,
                 pxenc(L"Decrypted %lu record(s) to:\r\n%ls"), count, outPath);
    LI_USER32(MessageBoxW)(NULL, msg, pxenc(L"PhoenixAC Updater - parse"),
                           MB_OK | MB_ICONINFORMATION);
    return 0;
}

static bool
TryParseCommand(LPWSTR lpCmdLine, wchar_t* pathOut, size_t cap)
{
    if (!lpCmdLine || !cap) return false;
    const wchar_t* p = lpCmdLine;
    while (*p == L' ' || *p == L'\t') ++p;
    if (p[0] != L'p' || p[1] != L'a' || p[2] != L'r' || p[3] != L's' || p[4] != L'e')
        return false;
    if (p[5] != L' ' && p[5] != L'\t') return false;

    p += 5;
    while (*p == L' ' || *p == L'\t') ++p;
    if (!*p) return false;

    size_t i = 0;
    if (*p == L'"') {
        ++p;
        while (*p && *p != L'"' && i + 1 < cap) pathOut[i++] = *p++;
    } else {
        while (*p && *p != L' ' && *p != L'\t' && i + 1 < cap) pathOut[i++] = *p++;
    }
    pathOut[i] = 0;
    return i > 0;
}

static const char*
StageOf(int code)
{
    if (code <= E_SEH_OUTER)   return PX_A("seh-outer");
    if (code <= E_SEH_INNER)   return PX_A("seh-inner");
    if (code <= E_LAUNCH)      return PX_A("launch");
    if (code <= E_GATE)        return PX_A("gate");
    if (code <= E_VERIFY_OPEN) return PX_A("verify-disk");
    if (code <= E_WRITE_AGENT) return PX_A("write-file");
    if (code <= E_INSTALL_DIR) return PX_A("install-dir");
    if (code <= E_HASH_FINAL)  return PX_A("verify-net");
    if (code <= E_RECV_CHUNK)  return PX_A("receive-chunks");
    return PX_A("handshake-or-manifest");
}

static void
FailWith(int code)
{
    const char* stage = StageOf(code);
    LOG_ERR(PX_AS("FAIL stage=%s code=%d gle=%lu"), stage, code, LI_KERNEL(GetLastError)());

    wchar_t wstage[64] = { 0 };
    for (int i = 0; i < 63 && stage[i]; ++i) wstage[i] = (wchar_t)(unsigned char)stage[i];

    wchar_t wbuf[1024];
    _snwprintf_s(wbuf, _TRUNCATE,
        pxenc(L"Aggiornamento fallito.\r\n\r\nStep: %ls\r\nCodice: %d\r\n\r\nLog: %ls"),
        wstage, code, g_LogPath);

    LI_USER32(MessageBoxW)(NULL, wbuf, pxenc(L"PhoenixAC Updater"),
                           MB_OK | MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST);
}

static bool
GetInstallDir(wchar_t* out, DWORD cch)
{
    wchar_t path[MAX_PATH];
    DWORD n = LI_KERNEL(GetModuleFileNameW)(NULL, path, MAX_PATH);
    if (!n || n >= MAX_PATH) return false;
    wchar_t* slash = wcsrchr(path, L'\\');
    if (!slash) return false;
    *slash = 0;
    return wcscpy_s(out, cch, path) == 0;
}

static bool
ParseManifest(const BYTE* b, ULONG len, Manifest* m)
{
    if (len < 96) return false;
    m->agentMajor = (UINT16)((b[0] << 8) | b[1]);
    m->agentMinor = (UINT16)((b[2] << 8) | b[3]);
    UINT32 ab = ((UINT32)b[4] << 24) | ((UINT32)b[5] << 16) | ((UINT32)b[6] << 8) | b[7];
    m->agentBuild    = (UINT16)(ab >> 16);
    m->agentRevision = (UINT16)(ab & 0xffff);

    m->drvMajor = (UINT16)((b[8]  << 8) | b[9]);
    m->drvMinor = (UINT16)((b[10] << 8) | b[11]);
    UINT32 db = ((UINT32)b[12] << 24) | ((UINT32)b[13] << 16) | ((UINT32)b[14] << 8) | b[15];
    m->drvBuild    = (UINT16)(db >> 16);
    m->drvRevision = (UINT16)(db & 0xffff);

    memcpy(m->agentSha, b + 16, 32);
    memcpy(m->drvSha,   b + 48, 32);

    m->agentSize = 0; m->drvSize = 0;
    for (int i = 0; i < 8; i++) m->agentSize = (m->agentSize << 8) | b[80 + i];
    for (int i = 0; i < 8; i++) m->drvSize   = (m->drvSize   << 8) | b[88 + i];
    return true;
}

static bool
IEqualW(const wchar_t* a, const wchar_t* b)
{
    while (*a && *b) {
        wchar_t ca = *a, cb = *b;
        if (ca >= L'A' && ca <= L'Z') ca = (wchar_t)(ca + 32);
        if (cb >= L'A' && cb <= L'Z') cb = (wchar_t)(cb + 32);
        if (ca != cb) return false;
        ++a; ++b;
    }
    return !*a && !*b;
}

static ULONG
KillByName(const wchar_t* image)
{
    HANDLE snap = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    ULONG killed = 0;
    PROCESSENTRY32W pe = { sizeof(pe) };
    DWORD self = LI_KERNEL(GetCurrentProcessId)();
    if (LI_KERNEL(Process32FirstW)(snap, &pe)) {
        do {
            if (pe.th32ProcessID == self) continue;
            if (!IEqualW(pe.szExeFile, image)) continue;
            HANDLE ph = LI_KERNEL(OpenProcess)(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pe.th32ProcessID);
            if (!ph) continue;
            if (LI_KERNEL(TerminateProcess)(ph, 0)) killed++;
            LI_KERNEL(WaitForSingleObject)(ph, 2000);
            LI_KERNEL(CloseHandle)(ph);
        } while (LI_KERNEL(Process32NextW)(snap, &pe));
    }
    LI_KERNEL(CloseHandle)(snap);
    return killed;
}

static bool
WaitWritable(const wchar_t* path, DWORD timeoutMs)
{
    DWORD start = LI_KERNEL(GetTickCount)();
    for (;;) {
        HANDLE h = LI_KERNEL(CreateFileW)(path, GENERIC_WRITE, 0, NULL,
                                          OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) { LI_KERNEL(CloseHandle)(h); return true; }
        DWORD gle = LI_KERNEL(GetLastError)();
        if (gle != ERROR_SHARING_VIOLATION && gle != ERROR_ACCESS_DENIED && gle != ERROR_LOCK_VIOLATION)
            return false;
        if (LI_KERNEL(GetTickCount)() - start > timeoutMs) return false;
        LI_KERNEL(Sleep)(100);
    }
}

static bool
AtomicWrite(const wchar_t* path, const BYTE* data, ULONG len)
{
    wchar_t tmp[MAX_PATH];
    if (LI_KERNEL(lstrlenW)(path) + 16 >= MAX_PATH)
        return false;
    _snwprintf_s(tmp, _TRUNCATE, pxenc(L"%ls.new%lu"), path, LI_KERNEL(GetCurrentProcessId)());

    HANDLE h = LI_KERNEL(CreateFileW)(tmp, GENERIC_WRITE, 0, NULL,
                                      CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        LOG_ERR(PX_AS("tmp open failed gle=%lu path=%ls"), LI_KERNEL(GetLastError)(), tmp);
        return false;
    }

    ULONG off = 0;
    while (off < len) {
        DWORD chunk = (len - off > 65536) ? 65536 : (len - off), w = 0;
        if (!LI_KERNEL(WriteFile)(h, data + off, chunk, &w, NULL) || w != chunk) {
            LOG_ERR(PX_AS("WriteFile failed off=%lu gle=%lu"), off, LI_KERNEL(GetLastError)());
            LI_KERNEL(CloseHandle)(h);
            LI_KERNEL(DeleteFileW)(tmp);
            return false;
        }
        off += w;
    }
    LI_KERNEL(FlushFileBuffers)(h);
    LI_KERNEL(CloseHandle)(h);

    WaitWritable(path, 3000);

    for (int attempt = 0; attempt < 5; ++attempt) {
        if (LI_KERNEL(MoveFileExW)(tmp, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            return true;
        DWORD gle = LI_KERNEL(GetLastError)();
        LOG_WARN(PX_AS("MoveFileExW attempt=%d gle=%lu path=%ls"), attempt, gle, path);
        if (gle != ERROR_SHARING_VIOLATION && gle != ERROR_ACCESS_DENIED && gle != ERROR_LOCK_VIOLATION) break;
        LI_KERNEL(Sleep)(400);
    }
    LI_KERNEL(DeleteFileW)(tmp);
    return false;
}

static bool
ConstEq(const BYTE* a, const BYTE* b, ULONG n)
{
    ULONG d = 0;
    for (ULONG i = 0; i < n; i++) d |= (ULONG)(a[i] ^ b[i]);
    return d == 0;
}

static bool
HashFile(const wchar_t* path, BYTE out[32])
{
    HANDLE h = LI_KERNEL(CreateFileW)(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;

    UPD_SHA256_CTX ctx;
    if (!Sha256Init(&ctx)) { LI_KERNEL(CloseHandle)(h); return false; }

    BYTE buf[65536]; DWORD rd = 0;
    while (LI_KERNEL(ReadFile)(h, buf, sizeof(buf), &rd, NULL) && rd > 0)
        Sha256Update(&ctx, buf, rd);

    LI_KERNEL(CloseHandle)(h);
    return Sha256Final(&ctx, out);
}

struct FreeGuard {
    void* p;
    ~FreeGuard() { if (p) LI_KERNEL(HeapFree)(LI_KERNEL(GetProcessHeap)(), 0, p); }
};

static int
DoAttempt()
{
    BRKIDA;
    auto host = PX_AS(KG_UPDATER_HOST_STR);
    auto port = PX_AS(KG_UPDATER_PORT_STR);
    LOG_INFO(PX_AS("attempt: %s:%s"), host.get(), port.get());

    if (!NetInit()) return E_NET_INIT;

    SOCKET s = NetDial(host, port, UPD_CONNECT_TIMEOUT_MS, UPD_IO_TIMEOUT_MS);
    if (s == INVALID_SOCKET) { NetShutdown(); return E_DIAL; }

    UPD_SESSION_KEYS keys;
    if (!NetHandshake(s, &keys)) { NetClose(s); NetShutdown(); return E_HANDSHAKE; }

    BYTE body[UPD_MAX_PACKET_BYTES];
    ULONG bodyLen = sizeof(body);
    UINT16 op = 0;
    int stage = 0;
    if (!NetRecvEncrypted(s, &keys, &op, body, &bodyLen, &stage)) {
        NetClose(s); NetShutdown(); return E_RECV_MAN;
    }
    if (op == UPD_OP_ERROR)    { NetClose(s); NetShutdown(); return E_SRV_ERR; }
    if (op != UPD_OP_MANIFEST) { NetClose(s); NetShutdown(); return E_BAD_MAN; }

    Manifest man;
    if (!ParseManifest(body, bodyLen, &man)) { NetClose(s); NetShutdown(); return E_BAD_MAN; }
    if (!man.agentSize || man.agentSize > UPD_MAX_AGENT ||
        !man.drvSize   || man.drvSize   > UPD_MAX_DRV) {
        NetClose(s); NetShutdown(); return E_BAD_SIZE;
    }
    LOG_INFO(PX_AS("manifest: agent=%llu drv=%llu"),
        (unsigned long long)man.agentSize, (unsigned long long)man.drvSize);

    BYTE* agentBuf = (BYTE*)LI_KERNEL(HeapAlloc)(LI_KERNEL(GetProcessHeap)(), 0, (SIZE_T)man.agentSize);
    BYTE* drvBuf   = (BYTE*)LI_KERNEL(HeapAlloc)(LI_KERNEL(GetProcessHeap)(), 0, (SIZE_T)man.drvSize);
    FreeGuard ga{ agentBuf }, gd{ drvBuf };
    if (!agentBuf || !drvBuf) { NetClose(s); NetShutdown(); return E_ALLOC; }

    UPD_SHA256_CTX agentSha, drvSha;
    if (!Sha256Init(&agentSha)) {
        NetClose(s); NetShutdown(); return E_HASH_INIT;
    }
    if (!Sha256Init(&drvSha)) {
        BYTE _junk[32];
        Sha256Final(&agentSha, _junk);
        NetClose(s); NetShutdown(); return E_HASH_INIT;
    }

    UINT64 agentGot = 0, drvGot = 0;
    for (;;) {
        bodyLen = sizeof(body);
        stage = 0;
        if (!NetRecvEncrypted(s, &keys, &op, body, &bodyLen, &stage)) {
            NetClose(s); NetShutdown(); return E_RECV_CHUNK - stage;
        }
        if (op == UPD_OP_END)   break;
        if (op == UPD_OP_ERROR) { NetClose(s); NetShutdown(); return E_CHUNK_ERR; }
        if (bodyLen < 8) continue;

        UINT64 off = 0;
        for (int i = 0; i < 8; i++) off = (off << 8) | body[i];
        ULONG chunk = bodyLen - 8;
        const BYTE* p = body + 8;

        if (op == UPD_OP_CHUNK_AGENT) {
            if (off != agentGot || off + chunk > man.agentSize) {
                NetClose(s); NetShutdown(); return E_CHUNK_AGENT;
            }
            memcpy(agentBuf + off, p, chunk);
            Sha256Update(&agentSha, p, chunk);
            agentGot += chunk;
        } else if (op == UPD_OP_CHUNK_DRIVER) {
            if (off != drvGot || off + chunk > man.drvSize) {
                NetClose(s); NetShutdown(); return E_CHUNK_DRV;
            }
            memcpy(drvBuf + off, p, chunk);
            Sha256Update(&drvSha, p, chunk);
            drvGot += chunk;
        }
    }
    NetClose(s); NetShutdown();

    if (agentGot != man.agentSize || drvGot != man.drvSize) return E_INCOMPLETE;

    BYTE gotAgent[32], gotDrv[32];
    if (!Sha256Final(&agentSha, gotAgent) || !Sha256Final(&drvSha, gotDrv)) return E_HASH_FINAL;
    if (!ConstEq(gotAgent, man.agentSha, 32) || !ConstEq(gotDrv, man.drvSha, 32))
        return E_SHA_MISMATCH;

    wchar_t installDir[MAX_PATH];
    if (!GetInstallDir(installDir, MAX_PATH)) return E_INSTALL_DIR;

    wchar_t agentPath[MAX_PATH], drvPath[MAX_PATH];
    _snwprintf_s(agentPath, _TRUNCATE, pxenc(L"%ls\\PhoenixAgent.exe"), installDir);
    _snwprintf_s(drvPath,   _TRUNCATE, pxenc(L"%ls\\PhoenixDrv.sys"),   installDir);

    ULONG killed = KillByName(pxenc(L"PhoenixAgent.exe"));
    LOG_INFO(PX_AS("killed agent instances=%lu"), killed);
    if (killed) LI_KERNEL(Sleep)(500);

    if (!AtomicWrite(agentPath, agentBuf, (ULONG)man.agentSize)) return E_WRITE_AGENT;
    if (!AtomicWrite(drvPath,   drvBuf,   (ULONG)man.drvSize))   return E_WRITE_DRV;

    BYTE onDisk[32];
    if (!HashFile(agentPath, onDisk)) return E_VERIFY_OPEN;
    if (!ConstEq(onDisk, man.agentSha, 32)) return E_VERIFY_DIFF;

    if (!UpdGateSetEnv()) return E_GATE;

    STARTUPINFOW si; memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    wchar_t cmd[MAX_PATH + 4];
    _snwprintf_s(cmd, _TRUNCATE, pxenc(L"\"%ls\""), agentPath);

    if (!LI_KERNEL(CreateProcessW)(agentPath, cmd, NULL, NULL, FALSE, 0, NULL, installDir, &si, &pi))
        return E_LAUNCH;

    if (pi.hThread)  LI_KERNEL(CloseHandle)(pi.hThread);
    if (pi.hProcess) LI_KERNEL(CloseHandle)(pi.hProcess);

    LOG_INFO(PX_AS("SUCCESS: agent launched"));
    return E_OK;
}

static bool
IsRetryable(int code)
{
    return code >= E_HASH_INIT && code <= E_NET_INIT;
}

static int
DoUpdate()
{
    int last = 0;
    for (int i = 1; i <= UPD_MAX_RETRIES; ++i) {
        LOG_INFO(PX_AS("---- attempt %d/%d ----"), i, UPD_MAX_RETRIES);
        int code;
        __try { code = DoAttempt(); }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            code = E_SEH_INNER;
            LOG_SEH(PX_AS("SEH inside attempt code=0x%08X"), GetExceptionCode());
        }
        if (code == E_OK) return E_OK;
        last = code;
        LOG_WARN(PX_AS("attempt %d failed code=%d"), i, code);
        if (!IsRetryable(code)) break;
        LI_KERNEL(Sleep)(UPD_RETRY_DELAY_MS * i);
    }
    FailWith(last);
    return 1;
}

int APIENTRY
wWinMain(HINSTANCE, HINSTANCE, LPWSTR lpCmdLine, int)
{
    wchar_t parsePath[MAX_PATH];
    if (TryParseCommand(lpCmdLine, parsePath, MAX_PATH))
        return ParseMode(parsePath);

    InitLog();
    LOG_INFO(PX_AS("==== updater launched ===="));
    __try { return DoUpdate(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG_SEH(PX_AS("top-level SEH code=0x%08X"), GetExceptionCode());
        FailWith(E_SEH_OUTER);
        return 1;
    }
}
