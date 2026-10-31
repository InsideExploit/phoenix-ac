#pragma once

#ifdef _KERNEL_MODE
#include <ntifs.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

#include "config.hpp"

#define KG_DEVICE_NAME    L"\\Device\\PhoenixDrv"
#define KG_SYMLINK_NAME   L"\\DosDevices\\PhoenixDrv"
#define KG_USER_PATH      L"\\\\.\\PhoenixDrv"
#define KG_SERVICE_NAME   L"PhoenixDrv"
#define KG_DISPLAY_NAME   L"Phoenix Kernel Guard"
#define KG_BINARY_NAME    L"PhoenixDrv.sys"

#define KG_FILE_DEVICE    0x8100

#define IOCTL_KG_REGISTER     CTL_CODE(KG_FILE_DEVICE, 0x800, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_KG_STATUS       CTL_CODE(KG_FILE_DEVICE, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_KG_ARM_RELAUNCH CTL_CODE(KG_FILE_DEVICE, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_KG_ATTEST       CTL_CODE(KG_FILE_DEVICE, 0x803, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_KG_STEAMID      CTL_CODE(KG_FILE_DEVICE, 0x804, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_KG_SHUTDOWN     CTL_CODE(KG_FILE_DEVICE, 0x805, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_KG_LAST_BLOCK   CTL_CODE(KG_FILE_DEVICE, 0x806, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_KG_KILL_TRUSTED CTL_CODE(KG_FILE_DEVICE, 0x807, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_KG_TRUSTED_COUNT CTL_CODE(KG_FILE_DEVICE, 0x808, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_KG_MODULE_INFO  CTL_CODE(KG_FILE_DEVICE, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KG_SCAN         CTL_CODE(KG_FILE_DEVICE, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KG_MEM_READ     CTL_CODE(KG_FILE_DEVICE, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KG_MEM_WRITE    CTL_CODE(KG_FILE_DEVICE, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KG_HWID             CTL_CODE(KG_FILE_DEVICE, 0x80D, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_KG_CRITICAL_COMMIT  CTL_CODE(KG_FILE_DEVICE, 0x80E, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_KG_NETMON_POP       CTL_CODE(KG_FILE_DEVICE, 0x80F, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_KG_UNCLOAK_WINDOW   CTL_CODE(KG_FILE_DEVICE, 0x810, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_KG_MMAP_POP         CTL_CODE(KG_FILE_DEVICE, 0x811, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_KG_IRP_POP          CTL_CODE(KG_FILE_DEVICE, 0x812, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_KG_ALLOC_IN_TARGET  CTL_CODE(KG_FILE_DEVICE, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KG_APC_INJECT       CTL_CODE(KG_FILE_DEVICE, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KG_PTRCRYPT_ARM     CTL_CODE(KG_FILE_DEVICE, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define KG_MMAP_DUMP_BYTES 512
#define KG_MMAP_MOD_NAME_MAX 128

typedef struct _KG_MMAP_EVENT {
    UINT64 TimestampMs;
    UINT64 StartAddress;
    UINT32 Tid;
    UINT32 DumpLen;
    UINT8  Dump[KG_MMAP_DUMP_BYTES];
    UINT16 NearestModuleOffset;
    UINT16 _Pad;
    UINT32 _Pad2;
    CHAR   NearestModule[KG_MMAP_MOD_NAME_MAX];
} KG_MMAP_EVENT;

#define KG_IRP_NAME_MAX 128

typedef struct _KG_IRP_EVENT {
    UINT64 TimestampMs;
    UINT64 OffendingAddress;
    UINT32 MajorFunction;
    UINT32 DumpLen;
    UINT8  Dump[KG_MMAP_DUMP_BYTES];
    UINT16 NearestModuleOffset;
    UINT16 _Pad;
    UINT32 _Pad2;
    CHAR   NearestModule[KG_MMAP_MOD_NAME_MAX];
    WCHAR  DriverName[KG_IRP_NAME_MAX];
    WCHAR  DeviceName[KG_IRP_NAME_MAX];
    WCHAR  SymlinkName[KG_IRP_NAME_MAX];
} KG_IRP_EVENT;

typedef struct _KG_UNCLOAK_WINDOW_REQ {
    UINT64 WindowHandle;
    UINT32 Value;
    UINT32 _Pad;
} KG_UNCLOAK_WINDOW_REQ;

#define KG_NETEVT_TCP_CONNECT 1
#define KG_NETEVT_TCP_ACCEPT  2

#define KG_NETEVT_PROC_MAX 260

typedef struct _KG_NET_EVENT {
    UINT64 TimestampMs;
    UINT32 Kind;
    UINT32 Pid;
    UINT16 Family;
    UINT16 LocalPort;
    UINT16 RemotePort;
    UINT16 ProcessPathLen;
    UINT8  RemoteAddr[16];
    UINT8  LocalAddr[16];
    WCHAR  ProcessPath[KG_NETEVT_PROC_MAX];
} KG_NET_EVENT;

#define KG_BLOCK_PATH_MAX   260
#define KG_BLOCK_REASON_MAX 64

typedef struct _KG_LAST_BLOCK {
    UINT32 Sequence;
    UINT16 PathLen;
    UINT16 ReasonLen;
    WCHAR  Path[KG_BLOCK_PATH_MAX];
    WCHAR  Reason[KG_BLOCK_REASON_MAX];
} KG_LAST_BLOCK;

#define KG_NONCE_LEN 16
#define KG_MAC_LEN   32
#define KG_TOKEN_LEN 32

#define KG_REGISTER_CONTEXT     "PXREG_V1"
#define KG_REGISTER_CONTEXT_LEN 8

#define KG_ARM_CONTEXT     "PXARM_V1"
#define KG_ARM_CONTEXT_LEN 8

#define KG_BASENAME_MAX 64

#pragma pack(push, 1)
typedef struct _KG_REGISTER_REQUEST {
    UINT8 Nonce[KG_NONCE_LEN];
    UINT8 Mac[KG_MAC_LEN];
} KG_REGISTER_REQUEST;

typedef struct _KG_ARM_REQUEST {
    UINT8  Nonce[KG_NONCE_LEN];
    UINT8  Mac[KG_MAC_LEN];
    UINT16 BasenameLen;
    UINT8  _pad[6];
    WCHAR  Basename[KG_BASENAME_MAX];
    UINT8  Token[KG_TOKEN_LEN];
} KG_ARM_REQUEST;

typedef struct _KG_ATTEST_REQUEST {
    UINT8 Token[KG_TOKEN_LEN];
} KG_ATTEST_REQUEST;

typedef enum _KG_STATE {
    KgStateUnknown     = 0,
    KgStateDisabled    = 1,
    KgStateEnabled     = 2,
    KgStateUnavailable = 3,
} KG_STATE;

typedef struct _KG_STEAM_ID {
    UINT64 SteamId64;
} KG_STEAM_ID;

typedef struct _KG_STATUS_REPORT {
    UINT32 SecureBoot;
    UINT32 SecureBootFirmware;
    UINT32 Hvci;
    UINT32 HvciPoolProbe;
    UINT32 Vbs;
    UINT32 KernelDma;
    UINT32 Tpm;
    UINT32 Reserved;
} KG_STATUS_REPORT;

#define KG_SCAN_MAX_PAT 64
#define KG_MEM_MAX_IO   0x4000

typedef struct _KG_MODULE_REQUEST {
    UINT32 Pid;
    UINT32 _pad;
} KG_MODULE_REQUEST;

typedef struct _KG_MODULE_RESULT {
    UINT64 Base;
    UINT32 Size;
    UINT32 _pad;
} KG_MODULE_RESULT;

typedef struct _KG_SCAN_REQUEST {
    UINT32 Pid;
    UINT32 PatternLen;
    UINT64 RangeStart;
    UINT64 RangeSize;
    UINT8  Pattern[KG_SCAN_MAX_PAT];
    UINT8  Mask[KG_SCAN_MAX_PAT];
} KG_SCAN_REQUEST;

typedef struct _KG_SCAN_RESULT {
    UINT64 Hit;
} KG_SCAN_RESULT;

typedef struct _KG_MEM_READ_REQUEST {
    UINT32 Pid;
    UINT32 Size;
    UINT64 Address;
} KG_MEM_READ_REQUEST;

typedef struct _KG_MEM_WRITE_REQUEST {
    UINT32 Pid;
    UINT32 Size;
    UINT64 Address;
    UINT8  Data[KG_MEM_MAX_IO];
} KG_MEM_WRITE_REQUEST;

typedef struct _KG_ALLOC_REQUEST {
    UINT32 Pid;
    UINT32 Size;
    UINT32 Protect;
    UINT32 _pad;
} KG_ALLOC_REQUEST;

typedef struct _KG_ALLOC_RESULT {
    UINT64 Address;
} KG_ALLOC_RESULT;

typedef struct _KG_APC_REQUEST {
    UINT32 Pid;
    UINT32 Tid;
    UINT64 UserRoutine;
    UINT64 Arg1;
    UINT64 Arg2;
    UINT64 Arg3;
} KG_APC_REQUEST;

typedef struct _KG_PTRCRYPT_ARM_REQUEST {
    UINT32 Pid;
    UINT32 Tid;
    UINT64 TargetPtrAddr;
    UINT64 RtlAvehAddr;
    UINT64 Sentinel;
} KG_PTRCRYPT_ARM_REQUEST;

typedef struct _KG_PTRCRYPT_ARM_RESULT {
    UINT64 AllocBase;
    UINT64 RealValue;
} KG_PTRCRYPT_ARM_RESULT;

#define KG_HWID_HASH_HEX_LEN 65
#define KG_HWID_JSON_MAX     2048

typedef struct _KG_HWID_RESULT {
    UINT8  Hash[32];
    CHAR   HashHex[KG_HWID_HASH_HEX_LEN];
    UINT32 JsonLen;
    CHAR   Json[KG_HWID_JSON_MAX];
} KG_HWID_RESULT;

#define KG_CRITICAL_TITLE_MAX 64
#define KG_CRITICAL_BODY_MAX  512

typedef struct _KG_CRITICAL_COMMIT {
    UINT16 TitleLen;
    UINT16 BodyLen;
    UINT32 _pad;
    WCHAR  Title[KG_CRITICAL_TITLE_MAX];
    WCHAR  Body[KG_CRITICAL_BODY_MAX];
} KG_CRITICAL_COMMIT;
#pragma pack(pop)

static const UINT8 g_HmacObf[32] = { 0 }; // REDACTED

#define KG_HMAC_XOR 0x5A

static __inline
VOID
GetHmacKey(
    _Out_writes_(32) UINT8 Out[32]
)
{
    for (int i = 0; i < 32; ++i)
        Out[i] = (UINT8)(g_HmacObf[i] ^ KG_HMAC_XOR);
}
