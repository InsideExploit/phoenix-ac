#include "regfilter.hpp"

#include "shared.hpp"
#include "pxstr.hpp"
#include "klazy.hpp"

#include "integrity/integrity.hpp"

extern "C"
NTSTATUS
CmRegisterCallback(
    _In_     PEX_CALLBACK_FUNCTION Function,
    _In_opt_ PVOID                 Context,
    _Out_    PLARGE_INTEGER        Cookie
);

extern "C"
NTSTATUS
CmUnRegisterCallback(
    _In_ LARGE_INTEGER Cookie
);

extern "C"
NTSTATUS
CmCallbackGetKeyObjectIDEx(
    _In_      PLARGE_INTEGER      Cookie,
    _In_      PVOID               Object,
    _Out_opt_ PULONG_PTR          ObjectID,
    _Out_     PCUNICODE_STRING*   ObjectName,
    _In_      ULONG               Flags
);

extern "C"
VOID
CmCallbackReleaseKeyObjectIDEx(
    _In_ PCUNICODE_STRING ObjectName
);

extern "C"
NTSTATUS
SeLocateProcessImageName(
    _In_  PEPROCESS         Process,
    _Out_ PUNICODE_STRING*  ImageFileName
);

extern "C"
VOID
BlocklistRecordFromKernel(
    _In_ PCUNICODE_STRING Path,
    _In_ const WCHAR*     Reason
);

static LARGE_INTEGER g_RegCookie    = { 0 };
static BOOLEAN       g_RegInstalled = FALSE;

#define KG_REENTRY_SLOTS 16
static HANDLE g_ReentrantThreads[KG_REENTRY_SLOTS] = { 0 };

KG_NO_OBFUSCATE
static
VOID
MarkReentrantEnter(
    _In_ HANDLE ThreadId
)
{
    for (int i = 0; i < KG_REENTRY_SLOTS; i++) {
        if (InterlockedCompareExchangePointer(&g_ReentrantThreads[i], ThreadId, NULL) == NULL)
            return;
    }
}

KG_NO_OBFUSCATE
static
VOID
MarkReentrantExit(
    _In_ HANDLE ThreadId
)
{
    for (int i = 0; i < KG_REENTRY_SLOTS; i++) {
        if (InterlockedCompareExchangePointer(&g_ReentrantThreads[i], NULL, ThreadId) == ThreadId)
            return;
    }
}

KG_NO_OBFUSCATE
static
BOOLEAN
IsReentrant(
    VOID
)
{
    HANDLE ThreadId = KL_NT(PsGetCurrentThreadId)();
    for (int i = 0; i < KG_REENTRY_SLOTS; i++) {
        if ((HANDLE)ReadPointerAcquire(&g_ReentrantThreads[i]) == ThreadId)
            return TRUE;
    }

    return FALSE;
}

KG_NO_OBFUSCATE
static
BOOLEAN
FindSubstringCI(
    _In_      PCUNICODE_STRING Hay,
    _In_      const WCHAR*     Needle,
    _Out_opt_ USHORT*          OutOffsetChars
)
{
    if (Hay == NULL || Hay->Buffer == NULL || Needle == NULL)
        return FALSE;

    UNICODE_STRING Want;
    KlazyMakeUS(&Want, Needle);
    if (Hay->Length < Want.Length)
        return FALSE;

    USHORT HayChars  = Hay->Length / sizeof(WCHAR);
    USHORT WantChars = Want.Length / sizeof(WCHAR);

    for (USHORT i = 0; i + WantChars <= HayChars; i++) {
        UNICODE_STRING Sub;
        Sub.Buffer        = Hay->Buffer + i;
        Sub.Length        = Want.Length;
        Sub.MaximumLength = Want.Length;
        if (KL_NT(RtlEqualUnicodeString)(&Sub, &Want, TRUE)) {
            if (OutOffsetChars != NULL)
                *OutOffsetChars = i;

            return TRUE;
        }
    }

    return FALSE;
}

KG_NO_OBFUSCATE
static
BOOLEAN
GetServicesTail(
    _In_  PCUNICODE_STRING Path,
    _Out_ UNICODE_STRING*  OutTail
)
{
    USHORT Off = 0;
    if (!FindSubstringCI(Path, PX_W(L"\\Services\\"), &Off))
        return FALSE;

    UNICODE_STRING Marker;
    KlazyMakeUS(&Marker, PX_W(L"\\Services\\"));
    USHORT MarkerChars = Marker.Length / sizeof(WCHAR);

    USHORT PathChars = Path->Length / sizeof(WCHAR);
    USHORT TailStart = Off + MarkerChars;

    OutTail->Buffer        = Path->Buffer + TailStart;
    OutTail->Length        = (USHORT)((PathChars - TailStart) * sizeof(WCHAR));
    OutTail->MaximumLength = OutTail->Length;
    return TRUE;
}

KG_NO_OBFUSCATE
static
BOOLEAN
PathUnderServices(
    _In_ PCUNICODE_STRING Path
)
{
    UNICODE_STRING Tail;
    return GetServicesTail(Path, &Tail);
}

static
BOOLEAN
TailMatchesServiceName(
    _In_ const UNICODE_STRING* Tail,
    _In_ const WCHAR*          Name
)
{
    UNICODE_STRING Want;
    KlazyMakeUS(&Want, Name);

    if (Tail->Length < Want.Length)
        return FALSE;

    UNICODE_STRING Head;
    Head.Buffer        = Tail->Buffer;
    Head.Length        = Want.Length;
    Head.MaximumLength = Want.Length;

    if (!KL_NT(RtlEqualUnicodeString)(&Head, &Want, TRUE))
        return FALSE;

    if (Tail->Length == Want.Length)
        return TRUE;

    return Tail->Buffer[Want.Length / sizeof(WCHAR)] == L'\\';
}

static
BOOLEAN
IsOwnServiceKey(
    _In_ PCUNICODE_STRING Path
)
{
    UNICODE_STRING Tail;
    if (!GetServicesTail(Path, &Tail))
        return FALSE;

    return TailMatchesServiceName(&Tail, PX_W(L"PhoenixDrv"));
}

static
BOOLEAN
TailStartsWithServicePrefix(
    _In_ const UNICODE_STRING* Tail,
    _In_ const WCHAR*          Prefix
)
{
    UNICODE_STRING Want;
    KlazyMakeUS(&Want, Prefix);

    if (Tail->Length < Want.Length)
        return FALSE;

    UNICODE_STRING Head;
    Head.Buffer        = Tail->Buffer;
    Head.Length        = Want.Length;
    Head.MaximumLength = Want.Length;

    return KL_NT(RtlEqualUnicodeString)(&Head, &Want, TRUE);
}

static
BOOLEAN
IsAllowedDriverService(
    _In_ PCUNICODE_STRING Path
)
{
    UNICODE_STRING Tail;
    if (!GetServicesTail(Path, &Tail))
        return FALSE;

    if (TailMatchesServiceName(&Tail, PX_W(L"nvlddmkm")))
        return TRUE;

    if (TailStartsWithServicePrefix(&Tail, PX_W(L"amduw23g")))
        return TRUE;

    return FALSE;
}

static
BOOLEAN
GetServiceKeyPath(
    _In_  PCUNICODE_STRING FullPath,
    _Out_ UNICODE_STRING*  OutKey
)
{
    UNICODE_STRING Tail;
    if (!GetServicesTail(FullPath, &Tail))
        return FALSE;

    USHORT TailChars = Tail.Length / sizeof(WCHAR);
    USHORT NameEnd   = TailChars;
    for (USHORT i = 0; i < TailChars; i++) {
        if (Tail.Buffer[i] == L'\\') {
            NameEnd = i;
            break;
        }
    }

    if (NameEnd == 0)
        return FALSE;

    USHORT ServicePathBytes = (USHORT)(((Tail.Buffer + NameEnd) - FullPath->Buffer) * sizeof(WCHAR));
    OutKey->Buffer        = FullPath->Buffer;
    OutKey->Length        = ServicePathBytes;
    OutKey->MaximumLength = ServicePathBytes;
    return TRUE;
}

static
ULONG
QuerySvcType(
    _In_ PCUNICODE_STRING KeyPath
)
{
    OBJECT_ATTRIBUTES Attributes;
    InitializeObjectAttributes(&Attributes,
                               (PUNICODE_STRING)KeyPath,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    HANDLE ThreadId = KL_NT(PsGetCurrentThreadId)();
    MarkReentrantEnter(ThreadId);

    HANDLE KeyHandle = NULL;
    NTSTATUS Status = KL_NT(ZwOpenKey)(&KeyHandle, KEY_QUERY_VALUE, &Attributes);
    if (!NT_SUCCESS(Status)) {
        MarkReentrantExit(ThreadId);
        return 0;
    }

    UNICODE_STRING ValueName;
    KlazyMakeUS(&ValueName, PX_W(L"Type"));

    UCHAR Buffer[32] = { 0 };
    ULONG Returned = 0;
    Status = KL_NT(ZwQueryValueKey)(KeyHandle,
                                    &ValueName,
                                    KeyValuePartialInformation,
                                    Buffer,
                                    sizeof(Buffer),
                                    &Returned);
    KL_NT(ZwClose)(KeyHandle);
    MarkReentrantExit(ThreadId);

    if (!NT_SUCCESS(Status))
        return 0;

    KEY_VALUE_PARTIAL_INFORMATION* Info = (KEY_VALUE_PARTIAL_INFORMATION*)Buffer;
    if (Info->Type != REG_DWORD || Info->DataLength < sizeof(ULONG))
        return 0;

    return *(ULONG*)Info->Data;
}

static
BOOLEAN
IsDriverType(
    _In_ ULONG ServiceType
)
{
    return ServiceType == SERVICE_KERNEL_DRIVER || ServiceType == SERVICE_FILE_SYSTEM_DRIVER;
}

KG_NO_OBFUSCATE
static
BOOLEAN
ValueNameIs(
    _In_ PCUNICODE_STRING Name,
    _In_ const WCHAR*     Literal
)
{
    if (Name == NULL || Name->Buffer == NULL || Literal == NULL)
        return FALSE;

    UNICODE_STRING Want;
    KlazyMakeUS(&Want, Literal);
    return KL_NT(RtlEqualUnicodeString)((PUNICODE_STRING)Name, &Want, TRUE);
}

static
BOOLEAN
IsNvStreamProofKeyPath(
    _In_ PCUNICODE_STRING Path
)
{
    return FindSubstringCI(Path, PX_W(L"\\NVIDIA Corporation\\Global\\NvApp\\ShadowPlay\\FTS"), NULL);
}

static
BOOLEAN
IsNvStreamProofValueName(
    _In_ PCUNICODE_STRING Name
)
{
    return ValueNameIs(Name, PX_W(L"{497B8458-4244-4EE6-BFEA-F3D2BA294F21}"));
}

static
VOID
ReportNvStreamProof(
    _In_ PCUNICODE_STRING KeyPath,
    _In_ const WCHAR*     Reason
)
{
    PEPROCESS       Process   = KL_NT(IoGetCurrentProcess)();
    PUNICODE_STRING ImageName = NULL;

    NTSTATUS Status = KL_NT(SeLocateProcessImageName)(Process, &ImageName);
    if (NT_SUCCESS(Status) && ImageName != NULL && ImageName->Length != 0) {
        KG_DRV_LOG("[PhoenixDrv/RegFilter] nv-streamproof %ls caller=%wZ key=%wZ\n",
                   Reason, ImageName, KeyPath);
        BlocklistRecordFromKernel(ImageName, Reason);
        g_KH.ExFreePoolWithTag(ImageName, 0);
    } else {
        KG_DRV_LOG("[PhoenixDrv/RegFilter] nv-streamproof %ls key=%wZ\n",
                   Reason, KeyPath);
        BlocklistRecordFromKernel(KeyPath, Reason);
    }
}

_Use_decl_annotations_
KG_NO_OBFUSCATE
VOID
RegFilterScanNvStreamProof(
    VOID
)
{
    PAGED_CODE();

    UNICODE_STRING KeyPath;
    KlazyMakeUS(&KeyPath,
        PX_W(L"\\Registry\\Machine\\SOFTWARE\\NVIDIA Corporation\\Global\\NvApp\\ShadowPlay\\FTS"));

    OBJECT_ATTRIBUTES Attributes;
    InitializeObjectAttributes(&Attributes,
                               &KeyPath,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    HANDLE ThreadId = KL_NT(PsGetCurrentThreadId)();
    MarkReentrantEnter(ThreadId);

    HANDLE KeyHandle = NULL;
    NTSTATUS Status = KL_NT(ZwOpenKey)(&KeyHandle, KEY_QUERY_VALUE, &Attributes);
    if (!NT_SUCCESS(Status)) {
        MarkReentrantExit(ThreadId);
        return;
    }

    UNICODE_STRING ValueName;
    KlazyMakeUS(&ValueName, PX_W(L"{497B8458-4244-4EE6-BFEA-F3D2BA294F21}"));

    UCHAR Buffer[64] = { 0 };
    ULONG Returned = 0;
    Status = KL_NT(ZwQueryValueKey)(KeyHandle,
                                    &ValueName,
                                    KeyValuePartialInformation,
                                    Buffer,
                                    sizeof(Buffer),
                                    &Returned);
    KL_NT(ZwClose)(KeyHandle);
    MarkReentrantExit(ThreadId);

    if (!NT_SUCCESS(Status))
        return;

    KEY_VALUE_PARTIAL_INFORMATION* Info = (KEY_VALUE_PARTIAL_INFORMATION*)Buffer;
    ULONG DwordValue = 0;
    if (Info->Type == REG_DWORD && Info->DataLength >= sizeof(ULONG))
        DwordValue = *(ULONG*)Info->Data;

    KG_DRV_LOG("[PhoenixDrv/RegFilter] startup: nv-streamproof value present type=%u data=0x%08X\n",
               Info->Type, DwordValue);

    ReportNvStreamProof(&KeyPath, PX_W(L"nv-streamproof-existing"));
}

KG_NO_OBFUSCATE
_Function_class_(EX_CALLBACK_FUNCTION)
static
NTSTATUS
RegCallback(
    _In_     PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
)
{
    UNREFERENCED_PARAMETER(CallbackContext);

    if (Argument2 == NULL)
        return STATUS_SUCCESS;

    if (IsReentrant())
        return STATUS_SUCCESS;

    REG_NOTIFY_CLASS NotifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    switch (NotifyClass) {

    case RegNtPreSetValueKey: {
        REG_SET_VALUE_KEY_INFORMATION* Info = (REG_SET_VALUE_KEY_INFORMATION*)Argument2;
        if (Info->Object == NULL || Info->ValueName == NULL)
            return STATUS_SUCCESS;

        PCUNICODE_STRING KeyPath = NULL;
        NTSTATUS Status = KL_NT(CmCallbackGetKeyObjectIDEx)(&g_RegCookie,
                                                            Info->Object,
                                                            NULL,
                                                            &KeyPath,
                                                            0);
        if (!NT_SUCCESS(Status) || KeyPath == NULL)
            return STATUS_SUCCESS;

        if (IsNvStreamProofKeyPath(KeyPath) && IsNvStreamProofValueName(Info->ValueName))
            ReportNvStreamProof(KeyPath, PX_W(L"nv-streamproof-set"));

        if (!PathUnderServices(KeyPath) || IsOwnServiceKey(KeyPath) || IsAllowedDriverService(KeyPath)) {
            KL_NT(CmCallbackReleaseKeyObjectIDEx)(KeyPath);
            return STATUS_SUCCESS;
        }

        BOOLEAN Deny = FALSE;

        if (ValueNameIs(Info->ValueName, PX_W(L"Type"))) {
            if (Info->Type == REG_DWORD && Info->DataSize >= sizeof(ULONG) && Info->Data != NULL) {
                ULONG NewType = *(ULONG*)Info->Data;
                if (IsDriverType(NewType)) {
                    Deny = TRUE;
                    KG_DRV_LOG("[PhoenixDrv/RegFilter] deny Type=%u on %wZ\n",
                               NewType, KeyPath);
                }
            }
        } else {
            UNICODE_STRING SvcKey;
            if (GetServiceKeyPath(KeyPath, &SvcKey)) {
                ULONG SvcType = QuerySvcType(&SvcKey);
                if (IsDriverType(SvcType)) {
                    Deny = TRUE;
                    KG_DRV_LOG("[PhoenixDrv/RegFilter] deny set %wZ on driver-svc %wZ\n",
                               Info->ValueName, &SvcKey);
                }
            }
        }

        KL_NT(CmCallbackReleaseKeyObjectIDEx)(KeyPath);
#if KG_REGFILTER_ENFORCE
        return Deny ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
#else
        (VOID)Deny;
        return STATUS_SUCCESS;
#endif
    }

    case RegNtPreQueryValueKey: {
        REG_QUERY_VALUE_KEY_INFORMATION* Info = (REG_QUERY_VALUE_KEY_INFORMATION*)Argument2;
        if (Info->Object == NULL || Info->ValueName == NULL)
            return STATUS_SUCCESS;

        if (!ValueNameIs(Info->ValueName, PX_W(L"ImagePath")) &&
            !ValueNameIs(Info->ValueName, PX_W(L"Type"))) {
            return STATUS_SUCCESS;
        }

        PCUNICODE_STRING KeyPath = NULL;
        NTSTATUS Status = KL_NT(CmCallbackGetKeyObjectIDEx)(&g_RegCookie,
                                                            Info->Object,
                                                            NULL,
                                                            &KeyPath,
                                                            0);
        if (!NT_SUCCESS(Status) || KeyPath == NULL)
            return STATUS_SUCCESS;

        if (!PathUnderServices(KeyPath) || IsOwnServiceKey(KeyPath) || IsAllowedDriverService(KeyPath)) {
            KL_NT(CmCallbackReleaseKeyObjectIDEx)(KeyPath);
            return STATUS_SUCCESS;
        }

        UNICODE_STRING SvcKey;
        BOOLEAN Deny = FALSE;
        if (GetServiceKeyPath(KeyPath, &SvcKey)) {
            ULONG SvcType = QuerySvcType(&SvcKey);
            if (IsDriverType(SvcType)) {
                Deny = TRUE;
                KG_DRV_LOG("[PhoenixDrv/RegFilter] deny query %wZ on driver-svc %wZ\n",
                           Info->ValueName, &SvcKey);
            }
        }

        KL_NT(CmCallbackReleaseKeyObjectIDEx)(KeyPath);
#if KG_REGFILTER_ENFORCE
        return Deny ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
#else
        (VOID)Deny;
        return STATUS_SUCCESS;
#endif
    }

    case RegNtPreDeleteKey:
    case RegNtPreDeleteValueKey: {
        REG_DELETE_KEY_INFORMATION* Info = (REG_DELETE_KEY_INFORMATION*)Argument2;
        if (Info->Object == NULL)
            return STATUS_SUCCESS;

        PCUNICODE_STRING KeyPath = NULL;
        NTSTATUS Status = KL_NT(CmCallbackGetKeyObjectIDEx)(&g_RegCookie,
                                                            Info->Object,
                                                            NULL,
                                                            &KeyPath,
                                                            0);
        if (!NT_SUCCESS(Status) || KeyPath == NULL)
            return STATUS_SUCCESS;

        if (!PathUnderServices(KeyPath) || IsOwnServiceKey(KeyPath) || IsAllowedDriverService(KeyPath)) {
            KL_NT(CmCallbackReleaseKeyObjectIDEx)(KeyPath);
            return STATUS_SUCCESS;
        }

        UNICODE_STRING SvcKey;
        BOOLEAN Deny = FALSE;
        if (GetServiceKeyPath(KeyPath, &SvcKey)) {
            ULONG SvcType = QuerySvcType(&SvcKey);
            if (IsDriverType(SvcType)) {
                Deny = TRUE;
                KG_DRV_LOG("[PhoenixDrv/RegFilter] deny delete on driver-svc %wZ\n",
                           &SvcKey);
            }
        }

        KL_NT(CmCallbackReleaseKeyObjectIDEx)(KeyPath);
#if KG_REGFILTER_ENFORCE
        return Deny ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
#else
        (VOID)Deny;
        return STATUS_SUCCESS;
#endif
    }
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
KG_NO_OBFUSCATE
NTSTATUS
RegFilterInstall(
    VOID
)
{
    PAGED_CODE();

    if (g_RegInstalled)
        return STATUS_SUCCESS;

    auto RegisterFn = KL_NT(CmRegisterCallback);
    if (RegisterFn == NULL) {
        KG_DRV_LOG("[PhoenixDrv/RegFilter] CmRegisterCallback unresolved\n");
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS Status = RegisterFn(RegCallback, NULL, &g_RegCookie);
    KG_DRV_LOG("[PhoenixDrv/RegFilter] CmRegisterCallback rc=0x%08X cookie=0x%llx\n",
               (ULONG)Status, (unsigned long long)g_RegCookie.QuadPart);
    if (!NT_SUCCESS(Status))
        return Status;

    g_RegInstalled = TRUE;
    IntegrityRegister((PVOID)&RegCallback);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
KG_NO_OBFUSCATE
VOID
RegFilterUninstall(
    VOID
)
{
    PAGED_CODE();

    if (!g_RegInstalled)
        return;

    KL_NT(CmUnRegisterCallback)(g_RegCookie);
    g_RegInstalled = FALSE;
    g_RegCookie.QuadPart = 0;
}
