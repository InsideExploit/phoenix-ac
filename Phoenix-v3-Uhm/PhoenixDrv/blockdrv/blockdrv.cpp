#include "blockdrv.hpp"

#include <bcrypt.h>

#include "pxstr.hpp"
#include "klazy.hpp"

extern "C"
VOID
BlocklistRecordFromKernel(
    _In_ PCUNICODE_STRING Path,
    _In_ const WCHAR*     Reason
);

static const UINT8 g_VulnMd5[][16] = {
#include "blockdrv_md5.inl"
};

static const ULONG g_VulnMd5Count = (ULONG)(sizeof(g_VulnMd5) / sizeof(g_VulnMd5[0]));

static BOOLEAN         g_LoadNotifyInstalled = FALSE;
static PVOID           g_ScanThreadObj       = NULL;
static volatile LONG   g_ScanAbort           = 0;

static
int
Md5Compare(
    _In_reads_bytes_(16) const UINT8* Left,
    _In_reads_bytes_(16) const UINT8* Right
)
{
    for (int i = 0; i < 16; i++) {
        if (Left[i] < Right[i])
            return -1;

        if (Left[i] > Right[i])
            return 1;
    }

    return 0;
}

static
BOOLEAN
IsBlacklisted(
    _In_reads_bytes_(16) const UINT8 Md5[16]
)
{
    LONG Low  = 0;
    LONG High = (LONG)g_VulnMd5Count - 1;

    while (Low <= High) {
        LONG Mid = Low + (High - Low) / 2;
        int Cmp = Md5Compare(Md5, g_VulnMd5[Mid]);
        if (Cmp == 0)
            return TRUE;

        if (Cmp < 0)
            High = Mid - 1;
        else
            Low = Mid + 1;
    }

    return FALSE;
}

static
NTSTATUS
Md5File(
    _In_                   PCUNICODE_STRING Path,
    _Out_writes_bytes_(16) UINT8            Out[16]
)
{
    if (Path == NULL || Path->Buffer == NULL || Path->Length == 0)
        return STATUS_INVALID_PARAMETER;

    OBJECT_ATTRIBUTES Attributes;
    InitializeObjectAttributes(&Attributes,
                               (PUNICODE_STRING)Path,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    HANDLE          FileHandle = NULL;
    IO_STATUS_BLOCK IoStatus   = { 0 };

    NTSTATUS Status = KL_NT(ZwCreateFile)(&FileHandle,
                                          FILE_GENERIC_READ,
                                          &Attributes,
                                          &IoStatus,
                                          NULL,
                                          FILE_ATTRIBUTE_NORMAL,
                                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                          FILE_OPEN,
                                          FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                                          NULL,
                                          0);
    if (!NT_SUCCESS(Status))
        return Status;

    FILE_STANDARD_INFORMATION FileInfo = { 0 };
    Status = KL_NT(ZwQueryInformationFile)(FileHandle,
                                           &IoStatus,
                                           &FileInfo,
                                           sizeof(FileInfo),
                                           FileStandardInformation);
    if (!NT_SUCCESS(Status)) {
        KL_NT(ZwClose)(FileHandle);
        return Status;
    }

    if (FileInfo.EndOfFile.QuadPart <= 0 ||
        FileInfo.EndOfFile.QuadPart > 64ULL * 1024 * 1024) {
        KL_NT(ZwClose)(FileHandle);
        return STATUS_FILE_TOO_LARGE;
    }

    BCRYPT_ALG_HANDLE  AlgHandle  = NULL;
    BCRYPT_HASH_HANDLE HashHandle = NULL;

    Status = KL_KSECDD(BCryptOpenAlgorithmProvider)(&AlgHandle,
                                                    PX_W(BCRYPT_MD5_ALGORITHM),
                                                    NULL,
                                                    0);
    if (!NT_SUCCESS(Status)) {
        KL_NT(ZwClose)(FileHandle);
        return Status;
    }

    Status = KL_KSECDD(BCryptCreateHash)(AlgHandle, &HashHandle, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(Status)) {
        KL_KSECDD(BCryptCloseAlgorithmProvider)(AlgHandle, 0);
        KL_NT(ZwClose)(FileHandle);
        return Status;
    }

    const ULONG Chunk = 64 * 1024;
    PVOID Buffer = KL_NT(ExAllocatePool2)(POOL_FLAG_PAGED, Chunk, 'DhKB');
    if (Buffer == NULL) {
        KL_KSECDD(BCryptDestroyHash)(HashHandle);
        KL_KSECDD(BCryptCloseAlgorithmProvider)(AlgHandle, 0);
        KL_NT(ZwClose)(FileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    LARGE_INTEGER Offset;
    Offset.QuadPart = 0;
    ULONGLONG Remaining = (ULONGLONG)FileInfo.EndOfFile.QuadPart;

    while (Remaining > 0) {
        ULONG Want = Remaining > Chunk ? Chunk : (ULONG)Remaining;
        Status = KL_NT(ZwReadFile)(FileHandle,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &IoStatus,
                                   Buffer,
                                   Want,
                                   &Offset,
                                   NULL);
        if (!NT_SUCCESS(Status) || IoStatus.Information == 0)
            break;

        Status = KL_KSECDD(BCryptHashData)(HashHandle,
                                           (PUCHAR)Buffer,
                                           (ULONG)IoStatus.Information,
                                           0);
        if (!NT_SUCCESS(Status))
            break;

        Offset.QuadPart += (LONGLONG)IoStatus.Information;
        Remaining       -= IoStatus.Information;
    }

    if (NT_SUCCESS(Status))
        Status = KL_KSECDD(BCryptFinishHash)(HashHandle, Out, 16, 0);

    g_KH.ExFreePoolWithTag(Buffer, 0);
    KL_KSECDD(BCryptDestroyHash)(HashHandle);
    KL_KSECDD(BCryptCloseAlgorithmProvider)(AlgHandle, 0);
    KL_NT(ZwClose)(FileHandle);
    return Status;
}

static
VOID
CheckAndReport(
    _In_ PCUNICODE_STRING FullImageName
)
{
    if (FullImageName == NULL || FullImageName->Buffer == NULL || FullImageName->Length == 0)
        return;

    UINT8 Md5[16] = { 0 };
    NTSTATUS Status = Md5File(FullImageName, Md5);
    if (!NT_SUCCESS(Status))
        return;

    if (!IsBlacklisted(Md5))
        return;

#if KG_BLOCKDRV_ENABLE
    BlocklistRecordFromKernel(FullImageName, PX_W(L"vuln-drv"));

    KG_DRV_LOG("[PhoenixDrv/BlockDrv] vulnerable driver hit path=%wZ\n",
               FullImageName);
#endif
}

KG_NO_OBFUSCATE
_Function_class_(PLOAD_IMAGE_NOTIFY_ROUTINE)
static
VOID
NTAPI
LoadImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_     HANDLE          ProcessId,
    _In_     PIMAGE_INFO     ImageInfo
)
{
    UNREFERENCED_PARAMETER(ImageInfo);

    if (ProcessId != NULL)
        return;

    if (FullImageName == NULL)
        return;

    CheckAndReport(FullImageName);
}

typedef struct _KG_LDR_ENTRY_MIN {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} KG_LDR_ENTRY_MIN, *PKG_LDR_ENTRY_MIN;

_Function_class_(KSTART_ROUTINE)
static
VOID
NTAPI
ScanLoadedThread(
    _In_ PVOID Context
)
{
    UNREFERENCED_PARAMETER(Context);

    if (g_KlazyAnchor == NULL) {
        KL_NT(PsTerminateSystemThread)(STATUS_UNSUCCESSFUL);
        return;
    }

    PKG_LDR_ENTRY_MIN Self  = (PKG_LDR_ENTRY_MIN)g_KlazyAnchor;
    LIST_ENTRY*       Start = &Self->InLoadOrderLinks;
    LIST_ENTRY*       Cur   = Start;

    for (int Guard = 0; Guard < 4096; Guard++) {
        if (InterlockedCompareExchange(&g_ScanAbort, 1, 1))
            break;

        PKG_LDR_ENTRY_MIN Entry = (PKG_LDR_ENTRY_MIN)Cur;
        if (Entry != Self &&
            Entry->FullDllName.Buffer != NULL &&
            Entry->FullDllName.Length > 0) {
            CheckAndReport(&Entry->FullDllName);
        }

        Cur = Cur->Flink;
        if (Cur == NULL || Cur == Start)
            break;
    }

    KL_NT(PsTerminateSystemThread)(STATUS_SUCCESS);
}

_Use_decl_annotations_
KG_NO_OBFUSCATE
VOID
BlockdrvScanLoadedAsync(
    VOID
)
{
    PAGED_CODE();

    HANDLE ThreadHandle = NULL;
    OBJECT_ATTRIBUTES Attributes;
    InitializeObjectAttributes(&Attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    NTSTATUS Status = KL_NT(PsCreateSystemThread)(&ThreadHandle,
                                                  THREAD_ALL_ACCESS,
                                                  &Attributes,
                                                  NULL,
                                                  NULL,
                                                  ScanLoadedThread,
                                                  NULL);
    if (!NT_SUCCESS(Status))
        return;

    PVOID ThreadObject = NULL;
    auto RefFn = KL_NT(ObReferenceObjectByHandle);
    if (RefFn != NULL)
        RefFn(ThreadHandle, SYNCHRONIZE, NULL, KernelMode, &ThreadObject, NULL);

    KL_NT(ZwClose)(ThreadHandle);

    PVOID Previous = (PVOID)InterlockedExchangePointer(&g_ScanThreadObj, ThreadObject);
    if (Previous != NULL) {
        auto DerefFn = KL_NT(ObfDereferenceObject);
        if (DerefFn != NULL)
            DerefFn(Previous);
    }
}

_Use_decl_annotations_
KG_NO_OBFUSCATE
NTSTATUS
BlockdrvInstall(
    VOID
)
{
    PAGED_CODE();

    if (g_LoadNotifyInstalled)
        return STATUS_SUCCESS;

    NTSTATUS Status = KL_NT(PsSetLoadImageNotifyRoutine)(LoadImageNotify);
    if (!NT_SUCCESS(Status))
        return Status;

    g_LoadNotifyInstalled = TRUE;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
KG_NO_OBFUSCATE
VOID
BlockdrvUninstall(
    VOID
)
{
    PAGED_CODE();

    if (g_LoadNotifyInstalled) {
        KL_NT(PsRemoveLoadImageNotifyRoutine)(LoadImageNotify);
        g_LoadNotifyInstalled = FALSE;
    }

    InterlockedExchange(&g_ScanAbort, 1);

    PVOID ThreadObject = (PVOID)InterlockedExchangePointer(&g_ScanThreadObj, NULL);
    if (ThreadObject != NULL) {
        auto WaitFn = KL_NT(KeWaitForSingleObject);
        if (WaitFn != NULL)
            WaitFn(ThreadObject, Executive, KernelMode, FALSE, NULL);

        auto DerefFn = KL_NT(ObfDereferenceObject);
        if (DerefFn != NULL)
            DerefFn(ThreadObject);
    }
}
