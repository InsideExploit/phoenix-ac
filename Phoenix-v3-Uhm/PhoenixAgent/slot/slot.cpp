#include "slot.hpp"
#include <tlhelp32.h>
#include <time.h>
#include "../guard/guard.hpp"
#include "../dbg.hpp"
#include "pxstr.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

#define KG_SLOT_XOR_KEY  0x7C4E91B6u
#define KG_SLOT_INTERVAL 2500
#define KG_SLOT_BACKOFF  250

static HANDLE g_SlotThread    = NULL;
static HANDLE g_SlotStopEvent = NULL;
static HANDLE g_SlotDevice    = INVALID_HANDLE_VALUE;

static
bool
NameContainsCI(
    const wchar_t* name,
    const wchar_t* needle
)
{
    size_t nlen = 0;
    while (needle[nlen])
        nlen++;
    for (size_t i = 0; name[i]; i++) {
        size_t j = 0;
        while (j < nlen && name[i + j]) {
            wchar_t a = name[i + j], b = needle[j];
            if (a >= L'A' && a <= L'Z') a = (wchar_t)(a + 32);
            if (b >= L'A' && b <= L'Z') b = (wchar_t)(b + 32);
            if (a != b) break;
            j++;
        }
        if (j == nlen) return true;
    }
    return false;
}

static
UINT32
FindGtaPid()
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    HANDLE snap = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W pe  = { sizeof(pe) };
    UINT32          pid = 0;
    if (LI_KERNEL(Process32FirstW)(snap, &pe)) {
        do {
            const wchar_t* n = pe.szExeFile;
            if (NameContainsCI(n, pxenc(L"GTAProcess")) ||
                NameContainsCI(n, pxenc(L"GameProcess")))
            {
                pid = pe.th32ProcessID;
                KGDBG(L"[slot] FindGtaPid matched name=%ls pid=%u\n", n, pid);
                break;
            }
        } while (LI_KERNEL(Process32NextW)(snap, &pe));
    }

    LI_KERNEL(CloseHandle)(snap);
    return pid;
}

static
bool
ResolveTargetAddress(
    HANDLE  device,
    UINT32  pid,
    UINT64* outAddr
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END
    UINT64 base = 0;
    UINT32 size = 0;
    if (!QueryModuleInfo(device, pid, &base, &size))
        return false;

    if (size < 0x1000 || size > 0x20000000u)
        return false;

    UINT8 pattern[] = {
        0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x8B, 0x9C, 0x24, 0x70, 0x01, 0x00, 0x00,
        0x84, 0xC0,
        0x0F, 0x45, 0xCF,
        0x8B, 0xC1,
        0x48, 0x81, 0xC4, 0x00, 0x00, 0x00, 0x00,
        0x5F, 0xC3, 0xCC,
        0x48, 0x8B, 0x0D
    };
    UINT8 mask[] = {
        1, 1, 0, 0, 0, 0,
        1, 1, 1, 1, 1, 1, 0, 0,
        1, 1,
        1, 1, 1,
        1, 1,
        1, 1, 1, 0, 0, 0, 0,
        1, 1, 1,
        1, 1, 1
    };

    UINT64 hit = 0;
    if (!ScanPattern(device, pid, base, size, pattern, mask, sizeof(pattern), &hit)) {
        KGDBG(L"[slot] ScanPattern FAILED pid=%u base=0x%016llX size=0x%X\n",
              pid, (unsigned long long)base, size);
        return false;
    }

    if (hit == 0) {
        KGDBG(L"[slot] ScanPattern returned hit=0 (no match)\n");
        return false;
    }

    KGDBG(L"[slot] ScanPattern hit=0x%016llX\n", (unsigned long long)hit);

    UINT8 buf[16];
    if (!ReadMem(device, pid, hit, buf, sizeof(buf))) {
        KGDBG(L"[slot] ReadMem FAILED at hit=0x%016llX\n", (unsigned long long)hit);
        return false;
    }

    KGDBG(L"[slot] bytes at hit: %02X %02X %02X %02X %02X %02X %02X %02X\n",
          buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);

    INT32  disp   = *(INT32*)(buf + 2);
    UINT64 target = hit + 6 + (INT64)disp;
    *outAddr = target;
    KGDBG(L"[slot] resolved disp=0x%08X target=0x%016llX\n",
          (unsigned int)disp, (unsigned long long)target);
    return true;
}

static
DWORD
WINAPI
SlotWriterThread(
    LPVOID
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    UINT32 pid        = 0;
    UINT64 targetAddr = 0;
    bool   resolved   = false;
    UINT32 misses     = 0;

    for (;;) {
        DWORD w = LI_KERNEL(WaitForSingleObject)(g_SlotStopEvent, resolved ? KG_SLOT_INTERVAL : KG_SLOT_BACKOFF);
        if (w == WAIT_OBJECT_0)
            break;

        if (!resolved) {
            pid = FindGtaPid();
            if (pid == 0) {
                misses++;
                if ((misses % 40) == 1)
                    KGDBG(L"[slot] waiting for GTAProcess/GameProcess (misses=%u)\n", misses);
                continue;
            }

            if (!ResolveTargetAddress(g_SlotDevice, pid, &targetAddr)) {
                misses++;
                KGDBG(L"[slot] ResolveTargetAddress failed pid=%u (misses=%u)\n", pid, misses);
                if (misses > 60)
                    misses = 0;

                continue;
            }

            resolved = true;
            misses   = 0;
            KGDBG(L"[slot] resolved pid=%u addr=0x%016llX\n", pid, targetAddr);
        }

        UINT32 ts  = (UINT32)((UINT64)time(NULL) & 0xFFFFFFFFull);
        UINT32 enc = ts ^ KG_SLOT_XOR_KEY;

        if (!WriteMem(g_SlotDevice, pid, targetAddr, &enc, sizeof(enc))) {
            KGDBG(L"[slot] WriteMem FAILED pid=%u addr=0x%016llX enc=0x%08X, re-resolving\n",
                  pid, (unsigned long long)targetAddr, enc);
            resolved   = false;
            targetAddr = 0;
            continue;
        }

        UINT32 verify = 0;
        if (ReadMem(g_SlotDevice, pid, targetAddr, &verify, sizeof(verify))) {
            if (verify == enc) {
                KGDBG(L"[slot] wrote enc=0x%08X ts=%u OK\n", enc, ts);
            } else {
                KGDBG(L"[slot] WROTE 0x%08X but READ BACK 0x%08X (address is wrong or being overwritten)\n",
                      enc, verify);
            }
        } else {
            KGDBG(L"[slot] wrote enc=0x%08X (verify-read failed)\n", enc);
        }
    }

    return 0;
}

bool
SlotStart(
    HANDLE     Device,
    const BYTE SlotKey[32],
    HANDLE     StopEvent
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END
    (void)SlotKey;
    if (g_SlotThread)
        return true;

    if (!Device || Device == INVALID_HANDLE_VALUE)
        return false;

    if (!StopEvent)
        return false;

    g_SlotDevice    = Device;
    g_SlotStopEvent = StopEvent;
    g_SlotThread    = LI_KERNEL(CreateThread)(NULL, 0, SlotWriterThread, NULL, 0, NULL);
    return g_SlotThread != NULL;
}

void
SlotStop()
{
    if (g_SlotThread) {
        LI_KERNEL(WaitForSingleObject)(g_SlotThread, 3000);
        LI_KERNEL(CloseHandle)(g_SlotThread);
        g_SlotThread    = NULL;
        g_SlotDevice    = INVALID_HANDLE_VALUE;
        g_SlotStopEvent = NULL;
    }
}
