#include "ptrcrypt.hpp"
#include <tlhelp32.h>
#include "../guard/guard.hpp"
#include "../dbg.hpp"
#include "shared.hpp"
#include "pxstr.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

extern "C" PVOID NTAPI RtlAddVectoredExceptionHandler(
    ULONG                       First,
    PVECTORED_EXCEPTION_HANDLER Handler);

#define KG_PC_INTERVAL_MS       5
#define KG_PC_BACKOFF_MS        500
#define KG_PC_SENTINEL          0x0000133700001337ULL

static HANDLE  g_PcThread    = NULL;
static HANDLE  g_PcStopEvent = NULL;
static HANDLE  g_PcDevice    = INVALID_HANDLE_VALUE;
static bool    g_PcArmed     = false;
static UINT32  g_PcTargetPid = 0;
static UINT64  g_PcTargetAddr = 0;
static UINT64  g_PcRealValue  = 0;

static
bool
PcNameContainsCI(
    const wchar_t* name,
    const wchar_t* needle
)
{
    size_t nlen = 0;
    while (needle[nlen]) nlen++;
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
PcFindGamePid()
{
    HANDLE snap = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W pe  = { sizeof(pe) };
    UINT32          pid = 0;
    if (LI_KERNEL(Process32FirstW)(snap, &pe)) {
        do {
            if (PcNameContainsCI(pe.szExeFile, pxenc(L"GTAProcess")) ||
                PcNameContainsCI(pe.szExeFile, pxenc(L"GameProcess"))) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (LI_KERNEL(Process32NextW)(snap, &pe));
    }
    LI_KERNEL(CloseHandle)(snap);
    return pid;
}

static
UINT32
PcPickAlertableTid(
    UINT32 pid
)
{
    HANDLE snap = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    THREADENTRY32 te = { sizeof(te) };
    UINT32 tid = 0;
    if (LI_KERNEL(Thread32First)(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                tid = te.th32ThreadID;
                break;
            }
        } while (LI_KERNEL(Thread32Next)(snap, &te));
    }
    LI_KERNEL(CloseHandle)(snap);
    return tid;
}

static
bool
PcResolveMsPool(
    HANDLE  device,
    UINT32  pid,
    UINT64* outStaticAddr,
    UINT64* outPoolAddr
)
{
    UINT64 base = 0;
    UINT32 size = 0;
    if (!QueryModuleInfo(device, pid, &base, &size))
        return false;
    if (size < 0x1000 || size > 0x20000000u)
        return false;

    UINT8 pattern[] = {
        0x48, 0x8B, 0x35, 0x00, 0x00, 0x00, 0x00,
        0x45, 0x33, 0xF6,
        0x45, 0x33, 0xFF
    };
    UINT8 mask[] = {
        1, 1, 1, 0, 0, 0, 0,
        1, 1, 1,
        1, 1, 1
    };

    UINT64 hit = 0;
    if (!ScanPattern(device, pid, base, size, pattern, mask, sizeof(pattern), &hit))
        return false;
    if (hit == 0)
        return false;

    UINT8 buf[7] = { 0 };
    if (!ReadMem(device, pid, hit, buf, sizeof(buf)))
        return false;

    INT32  disp    = *(INT32*)(buf + 3);
    UINT64 staticA = hit + 7 + (INT64)disp;

    UINT64 poolA = 0;
    if (!ReadMem(device, pid, staticA, &poolA, sizeof(poolA)))
        return false;

    *outStaticAddr = staticA;
    *outPoolAddr   = poolA;

    KGDBG(L"[ptrcrypt] _ms_pPool static=0x%llX pool=0x%llX\n",
          (unsigned long long)staticA,
          (unsigned long long)poolA);
    return true;
}

typedef struct _KG_PC_POOL_HDR {
    UINT64 aStorage;
    UINT64 aFlags;
    INT32  nSize;
    INT32  nStorageSize;
} KG_PC_POOL_HDR;

static
UINT32
PcEnumeratePeds(
    HANDLE  device,
    UINT32  pid,
    UINT64  poolAddr,
    UINT64* outPeds,
    UINT32  maxPeds
)
{
    KG_PC_POOL_HDR hdr = { 0 };
    if (!ReadMem(device, pid, poolAddr, &hdr, sizeof(hdr)))
        return 0;

    KGDBG(L"[ptrcrypt] pool storage=0x%llX flags=0x%llX size=%d slotSize=%d\n",
          (unsigned long long)hdr.aStorage,
          (unsigned long long)hdr.aFlags,
          hdr.nSize,
          hdr.nStorageSize);

    if (hdr.nSize <= 0 || hdr.nSize > 4096)
        return 0;
    if (hdr.nStorageSize <= 0 || hdr.nStorageSize > 0x10000)
        return 0;
    if (hdr.aStorage == 0 || hdr.aFlags == 0)
        return 0;

    UINT8* flags = (UINT8*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)hdr.nSize);
    if (!flags)
        return 0;

    if (!ReadMem(device, pid, hdr.aFlags, flags, (UINT32)hdr.nSize)) {
        HeapFree(GetProcessHeap(), 0, flags);
        return 0;
    }

    UINT32 count = 0;
    for (INT32 i = hdr.nSize - 1; i >= 0 && count < maxPeds; --i) {
        if ((flags[i] & 0x80) == 0) {
            outPeds[count++] = hdr.aStorage + (UINT64)i * (UINT64)hdr.nStorageSize;
        }
    }

    HeapFree(GetProcessHeap(), 0, flags);
    return count;
}

static
bool
PcResolveVtableCallOffset(
    HANDLE  device,
    UINT32  pid,
    UINT8*  outVtableOff
)
{
    UINT64 base = 0;
    UINT32 size = 0;
    if (!QueryModuleInfo(device, pid, &base, &size))
        return false;
    if (size < 0x1000 || size > 0x20000000u)
        return false;

    UINT8 pattern[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08,
        0x48, 0x89, 0x6C, 0x24, 0x10,
        0x48, 0x89, 0x74, 0x24, 0x18,
        0x57,
        0x48, 0x83, 0xEC, 0x00,
        0x48, 0x8B, 0x01,
        0x41, 0x8B, 0xE8,
        0x48, 0x8B, 0xFA
    };
    UINT8 mask[] = {
        1, 1, 1, 1, 1,
        1, 1, 1, 1, 1,
        1, 1, 1, 1, 1,
        1,
        1, 1, 1, 0,
        1, 1, 1,
        1, 1, 1,
        1, 1, 1
    };

    UINT64 hit = 0;
    if (!ScanPattern(device, pid, base, size, pattern, mask, sizeof(pattern), &hit))
        return false;
    if (hit == 0)
        return false;

    KGDBG(L"[ptrcrypt] GetBonePosition hit=0x%llX\n", (unsigned long long)hit);

    UINT8 window[0x200] = { 0 };
    if (!ReadMem(device, pid, hit, window, sizeof(window)))
        return false;

    for (SIZE_T i = 0; i + 2 < sizeof(window); ++i) {
        if (window[i] == 0xFF && window[i + 1] == 0x50) {
            *outVtableOff = window[i + 2];
            KGDBG(L"[ptrcrypt] first FF 50 at hit+0x%zX vtable_off=0x%X\n",
                  i, (unsigned)*outVtableOff);
            return true;
        }
    }

    KGDBG(L"[ptrcrypt] no FF 50 found in 0x200 window\n");
    return false;
}

static
bool
PcResolveFragInstFieldOffset(
    HANDLE  device,
    UINT32  pid,
    UINT32* outFieldOff
)
{
    UINT64 base = 0;
    UINT32 size = 0;
    if (!QueryModuleInfo(device, pid, &base, &size))
        return false;
    if (size < 0x1000 || size > 0x20000000u)
        return false;

    UINT8 pattern[] = {
        0x48, 0x8B, 0x81, 0x00, 0x00, 0x00, 0x00, 0xC3
    };
    UINT8 mask[] = { 1, 1, 1, 0, 0, 0, 0, 1 };

    UINT64 hit = 0;
    if (!ScanPattern(device, pid, base, size, pattern, mask, sizeof(pattern), &hit))
        return false;
    if (hit == 0)
        return false;

    UINT8 buf[8] = { 0 };
    if (!ReadMem(device, pid, hit, buf, sizeof(buf)))
        return false;

    *outFieldOff = *(UINT32*)(buf + 3);
    KGDBG(L"[ptrcrypt] FragInst-body hit=0x%llX field_off=0x%X\n",
          (unsigned long long)hit, (unsigned)*outFieldOff);
    return true;
}

static
bool
PcResolveMsInstance(
    HANDLE  device,
    UINT32  pid,
    UINT64* outAddr
)
{
    UINT64 base = 0;
    UINT32 size = 0;
    if (!QueryModuleInfo(device, pid, &base, &size)) {
        KGDBG(L"[ptrcrypt] QueryModuleInfo failed pid=%u\n", pid);
        return false;
    }
    if (size < 0x1000 || size > 0x20000000u) {
        KGDBG(L"[ptrcrypt] bad module size 0x%X\n", size);
        return false;
    }

    UINT8 pattern[] = {
        0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x8B, 0x48, 0x08,
        0x48, 0x85, 0xC9,
        0x0F, 0x84, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x8B, 0x51, 0x50
    };
    UINT8 mask[] = {
        1, 1, 1, 0, 0, 0, 0,
        1, 1, 1, 1,
        1, 1, 1,
        1, 1, 0, 0, 0, 0,
        1, 1, 1, 1
    };

    UINT64 hit = 0;
    if (!ScanPattern(device, pid, base, size, pattern, mask, sizeof(pattern), &hit)) {
        KGDBG(L"[ptrcrypt] ScanPattern FAILED\n");
        return false;
    }
    if (hit == 0) {
        KGDBG(L"[ptrcrypt] pattern not found\n");
        return false;
    }

    UINT8 buf[7];
    if (!ReadMem(device, pid, hit, buf, sizeof(buf))) {
        KGDBG(L"[ptrcrypt] ReadMem at hit failed\n");
        return false;
    }

    INT32  disp   = *(INT32*)(buf + 3);
    UINT64 target = hit + 7 + (INT64)disp;
    *outAddr = target;
    KGDBG(L"[ptrcrypt] hit=0x%llX ms_pInstance=0x%llX\n",
          (unsigned long long)hit, (unsigned long long)target);
    return true;
}

static
bool
PcArm(
    HANDLE device,
    UINT32 pid,
    UINT32 tid,
    UINT64 msPInstanceAddr,
    UINT64 rtlAvehAddr,
    UINT64* outAllocBase,
    UINT64* outRealValue
)
{
    KG_PTRCRYPT_ARM_REQUEST req = { 0 };
    req.Pid           = pid;
    req.Tid           = tid;
    req.TargetPtrAddr = msPInstanceAddr;
    req.RtlAvehAddr   = rtlAvehAddr;
    req.Sentinel      = KG_PC_SENTINEL;

    KG_PTRCRYPT_ARM_RESULT res = { 0 };
    DWORD returned = 0;
    BOOL b = LI_KERNEL(DeviceIoControl)(device, IOCTL_KG_PTRCRYPT_ARM,
                                        &req, sizeof(req),
                                        &res, sizeof(res),
                                        &returned, NULL);
    if (!b || returned != sizeof(res)) {
        KGDBG(L"[ptrcrypt] IOCTL_KG_PTRCRYPT_ARM failed err=%lu returned=%lu\n",
              LI_KERNEL(GetLastError)(), returned);
        return false;
    }

    *outAllocBase = res.AllocBase;
    *outRealValue = res.RealValue;
    return true;
}

static
DWORD
WINAPI
PcThread(LPVOID)
{
    UINT64 rtlAveh = (UINT64)(ULONG_PTR)LI_NTDLL(RtlAddVectoredExceptionHandler);
    if (rtlAveh == 0) {
        KGDBG(L"[ptrcrypt] failed to resolve RtlAddVectoredExceptionHandler\n");
        return 0;
    }
    KGDBG(L"[ptrcrypt] RtlAveh=0x%llX\n", (unsigned long long)rtlAveh);

    while (!g_PcArmed) {
        DWORD w = LI_KERNEL(WaitForSingleObject)(g_PcStopEvent, KG_PC_BACKOFF_MS);
        if (w == WAIT_OBJECT_0)
            return 0;

        UINT32 pid = PcFindGamePid();
        if (pid == 0)
            continue;

        UINT32 tid = PcPickAlertableTid(pid);
        if (tid == 0) {
            KGDBG(L"[ptrcrypt] no thread for pid=%u\n", pid);
            continue;
        }

        UINT64 addr = 0;
        if (!PcResolveMsInstance(g_PcDevice, pid, &addr))
            continue;

        UINT64 allocBase = 0;
        UINT64 realValue = 0;
        if (!PcArm(g_PcDevice, pid, tid, addr, rtlAveh, &allocBase, &realValue)) {
            KGDBG(L"[ptrcrypt] arm failed pid=%u tid=%u\n", pid, tid);
            continue;
        }

        g_PcTargetPid  = pid;
        g_PcTargetAddr = addr;
        g_PcRealValue  = realValue;
        g_PcArmed      = true;

        KGDBG(L"[ptrcrypt] ARMED pid=%u alloc=0x%llX real=0x%llX sentinel=0x%llX interval=%dms\n",
              pid,
              (unsigned long long)allocBase,
              (unsigned long long)realValue,
              (unsigned long long)KG_PC_SENTINEL,
              KG_PC_INTERVAL_MS);
    }

    UINT64 sentinel = KG_PC_SENTINEL;

    for (;;) {
        DWORD w = LI_KERNEL(WaitForSingleObject)(g_PcStopEvent, KG_PC_INTERVAL_MS);
        if (w == WAIT_OBJECT_0)
            break;

        if (!WriteMem(g_PcDevice, g_PcTargetPid, g_PcTargetAddr, &sentinel, 8)) {
            KGDBG(L"[ptrcrypt] WriteMem sentinel FAILED\n");
            break;
        }
    }

    WriteMem(g_PcDevice, g_PcTargetPid, g_PcTargetAddr, &g_PcRealValue, 8);
    KGDBG(L"[ptrcrypt] final restore on exit\n");

    return 0;
}

bool
PtrCryptStart(
    HANDLE Device,
    HANDLE StopEvent
)
{
    if (g_PcThread) return true;
    if (!Device || Device == INVALID_HANDLE_VALUE) return false;
    if (!StopEvent) return false;

    g_PcDevice    = Device;
    g_PcStopEvent = StopEvent;
    g_PcArmed     = false;
    g_PcThread    = LI_KERNEL(CreateThread)(NULL, 0, PcThread, NULL, 0, NULL);
    return g_PcThread != NULL;
}

void
PtrCryptStop()
{
    if (g_PcThread) {
        LI_KERNEL(WaitForSingleObject)(g_PcThread, 8000);
        LI_KERNEL(CloseHandle)(g_PcThread);
        g_PcThread     = NULL;
        g_PcDevice     = INVALID_HANDLE_VALUE;
        g_PcStopEvent  = NULL;
        g_PcArmed      = false;
        g_PcTargetPid  = 0;
        g_PcTargetAddr = 0;
        g_PcRealValue  = 0;
    }
}
