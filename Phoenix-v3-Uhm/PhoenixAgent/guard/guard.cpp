#include "guard.hpp"
#include "crypto/crypto.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

__declspec(noinline)
HANDLE
OpenGuard(
)
{
    BRKIDA;
    HANDLE h;
    VIRTUALIZER_START
    h = LI_KERNEL(CreateFileW)(pxenc(KG_USER_PATH),
                               GENERIC_READ | GENERIC_WRITE,
                               0, NULL, OPEN_EXISTING, 0, NULL);
    VIRTUALIZER_END
    return h;
}

__declspec(noinline)
bool
RegisterGuard(
    HANDLE Device
)
{
    BRKIDA;
    if (!Device || Device == INVALID_HANDLE_VALUE) return false;

    KG_REGISTER_REQUEST req = { 0 };
    BOOL b = FALSE;
    volatile int _vm_seal = 0;

    VIRTUALIZER_START
    if (SecureRandom(req.Nonce, KG_NONCE_LEN)) {
        BYTE key[32];
        GetHmacKey(key);

        BYTE message[KG_REGISTER_CONTEXT_LEN + KG_NONCE_LEN];
        memcpy(message, PX_A(KG_REGISTER_CONTEXT), KG_REGISTER_CONTEXT_LEN);
        memcpy(message + KG_REGISTER_CONTEXT_LEN, req.Nonce, KG_NONCE_LEN);

        bool ok = HmacSha256(key, sizeof(key), message, sizeof(message), req.Mac);
        SecureZeroMemory(key, sizeof(key));

        if (ok) {
            DWORD returned = 0;
            b = LI_KERNEL(DeviceIoControl)(Device, IOCTL_KG_REGISTER,
                                           &req, sizeof(req),
                                           NULL, 0, &returned, NULL);
        }
    }

    SecureZeroMemory(&req, sizeof(req));
    VIRTUALIZER_END
    _vm_seal = 1;
    (void)_vm_seal;

    return !!b;
}

__declspec(noinline)
bool
QueryGuardStatus(
    HANDLE            Device,
    KG_STATUS_REPORT* Out
)
{
    BRKIDA;
    if (!Device || Device == INVALID_HANDLE_VALUE || !Out) return false;

    BOOL  b        = FALSE;
    DWORD returned = 0;
    VIRTUALIZER_START
    b = LI_KERNEL(DeviceIoControl)(Device, IOCTL_KG_STATUS,
                                   NULL, 0,
                                   Out, sizeof(*Out), &returned, NULL);
    VIRTUALIZER_END
    return !!b && returned == sizeof(*Out);
}

__declspec(noinline)
bool
ArmRelaunch(
    HANDLE         Device,
    const wchar_t* Basename,
    const BYTE     Token[KG_TOKEN_LEN]
)
{
    BRKIDA;
    if (!Device || Device == INVALID_HANDLE_VALUE || !Basename || !Token) return false;

    size_t chars = wcslen(Basename);
    if (chars == 0 || chars > KG_BASENAME_MAX) return false;

    KG_ARM_REQUEST req = { 0 };
    BOOL b = FALSE;
    volatile int _vm_seal = 0;

    VIRTUALIZER_START
    req.BasenameLen = (UINT16)(chars * sizeof(WCHAR));
    memcpy(req.Basename, Basename, req.BasenameLen);
    memcpy(req.Token, Token, KG_TOKEN_LEN);
    VIRTUALIZER_END
    _vm_seal = 1;
    (void)_vm_seal;

    if (SecureRandom(req.Nonce, KG_NONCE_LEN)) {
        BYTE key[32];
        GetHmacKey(key);

        BYTE message[KG_ARM_CONTEXT_LEN + KG_NONCE_LEN + sizeof(req.Basename) + KG_TOKEN_LEN];
        ULONG mlen = 0;
        memcpy(message,        PX_A(KG_ARM_CONTEXT), KG_ARM_CONTEXT_LEN); mlen += KG_ARM_CONTEXT_LEN;
        memcpy(message + mlen, req.Nonce,      KG_NONCE_LEN);       mlen += KG_NONCE_LEN;
        memcpy(message + mlen, req.Basename,   req.BasenameLen);    mlen += req.BasenameLen;
        memcpy(message + mlen, req.Token,      KG_TOKEN_LEN);       mlen += KG_TOKEN_LEN;

        bool ok = HmacSha256(key, sizeof(key), message, mlen, req.Mac);
        SecureZeroMemory(key, sizeof(key));

        if (ok) {
            VIRTUALIZER_START
            DWORD returned = 0;
            b = LI_KERNEL(DeviceIoControl)(Device, IOCTL_KG_ARM_RELAUNCH,
                                           &req, sizeof(req),
                                           NULL, 0, &returned, NULL);
            VIRTUALIZER_END
        }
    }

    SecureZeroMemory(&req, sizeof(req));

    return !!b;
}

__declspec(noinline)
bool
AttestGuard(
    HANDLE     Device,
    const BYTE Token[KG_TOKEN_LEN]
)
{
    BRKIDA;
    if (!Device || Device == INVALID_HANDLE_VALUE || !Token) return false;

    KG_ATTEST_REQUEST req = { 0 };
    BOOL b = FALSE;

    VIRTUALIZER_START
    memcpy(req.Token, Token, KG_TOKEN_LEN);
    DWORD returned = 0;
    b = LI_KERNEL(DeviceIoControl)(Device, IOCTL_KG_ATTEST,
                                   &req, sizeof(req),
                                   NULL, 0, &returned, NULL);
    SecureZeroMemory(&req, sizeof(req));
    VIRTUALIZER_END

    return !!b;
}

__declspec(noinline)
bool
QuerySteamId(
    HANDLE  Device,
    UINT64* Out
)
{
    BRKIDA;
    if (!Device || Device == INVALID_HANDLE_VALUE || !Out) return false;

    KG_STEAM_ID id = { 0 };
    BOOL  b        = FALSE;
    DWORD returned = 0;

    VIRTUALIZER_START
    b = LI_KERNEL(DeviceIoControl)(Device, IOCTL_KG_STEAMID,
                                   NULL, 0,
                                   &id, sizeof(id), &returned, NULL);
    VIRTUALIZER_END

    if (!b || returned != sizeof(id)) return false;

    *Out = id.SteamId64;
    return true;
}

__declspec(noinline)
bool
QueryLastBlock(
    HANDLE         Device,
    KG_LAST_BLOCK* Out
)
{
    BRKIDA;
    if (!Device || Device == INVALID_HANDLE_VALUE || !Out) return false;

    BOOL  b        = FALSE;
    DWORD returned = 0;
    VIRTUALIZER_START
    b = LI_KERNEL(DeviceIoControl)(Device, IOCTL_KG_LAST_BLOCK,
                                   NULL, 0,
                                   Out, sizeof(*Out), &returned, NULL);
    VIRTUALIZER_END
    return !!b && returned == sizeof(*Out);
}

__declspec(noinline)
bool
QueryTrustedCount(
    HANDLE  Device,
    UINT32* Out
)
{
    BRKIDA;
    if (!Device || Device == INVALID_HANDLE_VALUE || !Out) return false;

    UINT32 count = 0;
    BOOL  b        = FALSE;
    DWORD returned = 0;
    VIRTUALIZER_START
    b = LI_KERNEL(DeviceIoControl)(Device, IOCTL_KG_TRUSTED_COUNT,
                                   NULL, 0,
                                   &count, sizeof(count), &returned, NULL);
    VIRTUALIZER_END
    if (!b || returned != sizeof(count)) return false;

    *Out = count;
    return true;
}

__declspec(noinline)
bool
KillTrustedGuard(
    HANDLE Device
)
{
    BRKIDA;
    if (!Device || Device == INVALID_HANDLE_VALUE) return false;

    BOOL  b        = FALSE;
    DWORD returned = 0;
    VIRTUALIZER_START
    b = LI_KERNEL(DeviceIoControl)(Device, IOCTL_KG_KILL_TRUSTED,
                                   NULL, 0, NULL, 0, &returned, NULL);
    VIRTUALIZER_END
    return !!b;
}

__declspec(noinline)
bool
ShutdownGuard(
    HANDLE Device
)
{
    BRKIDA;
    if (!Device || Device == INVALID_HANDLE_VALUE) return false;

    BOOL  b        = FALSE;
    DWORD returned = 0;
    VIRTUALIZER_START
    b = LI_KERNEL(DeviceIoControl)(Device, IOCTL_KG_SHUTDOWN,
                                   NULL, 0, NULL, 0, &returned, NULL);
    VIRTUALIZER_END
    return !!b;
}

bool
QueryModuleInfo(
    HANDLE  Device,
    UINT32  Pid,
    UINT64* Base,
    UINT32* Size
)
{
    BRKIDA;
    if (!Device || Device == INVALID_HANDLE_VALUE || !Base || !Size) return false;

    VIRTUALIZER_START
    KG_MODULE_REQUEST req = { Pid, 0 };
    KG_MODULE_RESULT  res = { 0 };
    DWORD returned = 0;
    BOOL b = LI_KERNEL(DeviceIoControl)(Device, IOCTL_KG_MODULE_INFO,
                                        &req, sizeof(req),
                                        &res, sizeof(res), &returned, NULL);
    if (!b || returned != sizeof(res)) return false;

    *Base = res.Base;
    *Size = res.Size;
    VIRTUALIZER_END
    return true;
}

bool
ScanPattern(
    HANDLE       Device,
    UINT32       Pid,
    UINT64       RangeStart,
    UINT64       RangeSize,
    const UINT8* Pattern,
    const UINT8* Mask,
    UINT32       Len,
    UINT64*      Hit
)
{
    BRKIDA;
    if (!Device || Device == INVALID_HANDLE_VALUE || !Pattern || !Mask || !Hit) return false;
    if (Len == 0 || Len > KG_SCAN_MAX_PAT) return false;

    VIRTUALIZER_START
    KG_SCAN_REQUEST req = { 0 };
    req.Pid        = Pid;
    req.PatternLen = Len;
    req.RangeStart = RangeStart;
    req.RangeSize  = RangeSize;
    memcpy(req.Pattern, Pattern, Len);
    memcpy(req.Mask,    Mask,    Len);

    KG_SCAN_RESULT res = { 0 };
    DWORD returned = 0;
    BOOL b = LI_KERNEL(DeviceIoControl)(Device, IOCTL_KG_SCAN,
                                        &req, sizeof(req),
                                        &res, sizeof(res), &returned, NULL);
    if (!b || returned != sizeof(res)) return false;

    *Hit = res.Hit;
    VIRTUALIZER_END
    return res.Hit != 0;
}

bool
ReadMem(
    HANDLE Device,
    UINT32 Pid,
    UINT64 Address,
    void*  Dest,
    UINT32 Size
)
{
    BRKIDA;
    if (!Device || Device == INVALID_HANDLE_VALUE || !Dest) return false;
    if (Size == 0 || Size > KG_MEM_MAX_IO) return false;

    VIRTUALIZER_START
    KG_MEM_READ_REQUEST req = { Pid, Size, Address };
    DWORD returned = 0;
    BOOL b = LI_KERNEL(DeviceIoControl)(Device, IOCTL_KG_MEM_READ,
                                        &req, sizeof(req),
                                        Dest, Size, &returned, NULL);
    VIRTUALIZER_END
    return !!b && returned == Size;
}

bool
WriteMem(
    HANDLE      Device,
    UINT32      Pid,
    UINT64      Address,
    const void* Source,
    UINT32      Size
)
{
    BRKIDA;
    if (!Device || Device == INVALID_HANDLE_VALUE || !Source) return false;
    if (Size == 0 || Size > KG_MEM_MAX_IO) return false;

    VIRTUALIZER_START
    KG_MEM_WRITE_REQUEST req = { 0 };
    req.Pid     = Pid;
    req.Size    = Size;
    req.Address = Address;
    memcpy(req.Data, Source, Size);

    DWORD needed   = (DWORD)(FIELD_OFFSET(KG_MEM_WRITE_REQUEST, Data) + Size);
    DWORD returned = 0;
    BOOL b = LI_KERNEL(DeviceIoControl)(Device, IOCTL_KG_MEM_WRITE,
                                        &req, needed,
                                        NULL, 0, &returned, NULL);
    VIRTUALIZER_END
    return !!b;
}

__declspec(noinline)
bool
QueryHwid(
    HANDLE          Device,
    KG_HWID_RESULT* Out
)
{
    BRKIDA;
    if (!Device || Device == INVALID_HANDLE_VALUE || !Out) return false;

    BOOL  b        = FALSE;
    DWORD returned = 0;
    VIRTUALIZER_START
    b = LI_KERNEL(DeviceIoControl)(Device, IOCTL_KG_HWID,
                                   NULL, 0,
                                   Out, sizeof(*Out), &returned, NULL);
    VIRTUALIZER_END
    return !!b && returned == sizeof(*Out);
}

__declspec(noinline)
bool
UncloakWindow(
    HANDLE Device,
    HWND   Window,
    UINT32 Value
)
{
    BRKIDA;
    if (!Device || Device == INVALID_HANDLE_VALUE || !Window) return false;

    KG_UNCLOAK_WINDOW_REQ req = { 0 };
    req.WindowHandle = (UINT64)(ULONG_PTR)Window;
    req.Value        = Value;

    BOOL  b        = FALSE;
    DWORD returned = 0;
    VIRTUALIZER_START
    b = LI_KERNEL(DeviceIoControl)(Device, IOCTL_KG_UNCLOAK_WINDOW,
                                   &req, sizeof(req),
                                   NULL, 0, &returned, NULL);
    VIRTUALIZER_END
    return !!b;
}
