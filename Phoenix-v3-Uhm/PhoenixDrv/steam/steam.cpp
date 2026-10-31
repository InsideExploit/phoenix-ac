#include "steam.hpp"

#include <ntstrsafe.h>

#include "pxstr.hpp"
#include "klazy.hpp"

#define KG_STEAM_ID64_BASE 0x0110000100000000ULL
#define KG_LOG(fmt, ...)   KG_DRV_LOG("[PhoenixDrv/Steam] " fmt, ##__VA_ARGS__)

static
BOOLEAN
SubkeyIsUserHive(
    _In_ const UNICODE_STRING* Name
)
{
    if (Name == NULL || Name->Length < sizeof(WCHAR))
        return FALSE;

    UNICODE_STRING ClassesSuffix;
    KlazyMakeUS(&ClassesSuffix, PX_W(L"_Classes"));

    if (Name->Length >= ClassesSuffix.Length) {
        UNICODE_STRING Tail;
        Tail.Buffer        = (PWCH)((PUCHAR)Name->Buffer + Name->Length - ClassesSuffix.Length);
        Tail.Length        = ClassesSuffix.Length;
        Tail.MaximumLength = Tail.Length;

        if (KL_NT(RtlEqualUnicodeString)(&Tail, &ClassesSuffix, TRUE))
            return FALSE;
    }

    if (Name->Buffer[0] == L'.')
        return FALSE;

    return TRUE;
}

static
NTSTATUS
TryReadActiveUser(
    _In_  const UNICODE_STRING* Hive,
    _Out_ UINT32*               Out
)
{
    WCHAR PathBuffer[512];
    NTSTATUS PrintStatus = RtlStringCbPrintfW(PathBuffer,
                                              sizeof(PathBuffer),
                                              PX_W(L"\\Registry\\User\\%wZ\\Software\\Valve\\Steam\\ActiveProcess"),
                                              Hive);
    if (!NT_SUCCESS(PrintStatus)) {
        KG_LOG("printf hive failed 0x%08X\n", PrintStatus);
        return PrintStatus;
    }

    KG_LOG("try open %ws\n", PathBuffer);

    UNICODE_STRING KeyPath;
    KlazyMakeUS(&KeyPath, PathBuffer);

    OBJECT_ATTRIBUTES Attributes;
    InitializeObjectAttributes(&Attributes,
                               &KeyPath,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    HANDLE KeyHandle = NULL;
    NTSTATUS Status = KL_NT(ZwOpenKey)(&KeyHandle, KEY_QUERY_VALUE, &Attributes);
    KG_LOG("  ZwOpenKey=0x%08X\n", Status);
    if (!NT_SUCCESS(Status))
        return Status;

    UNICODE_STRING ValueName;
    KlazyMakeUS(&ValueName, PX_W(L"ActiveUser"));

    UCHAR ValueBuffer[64];
    ULONG ValueLen = 0;
    Status = KL_NT(ZwQueryValueKey)(KeyHandle,
                                    &ValueName,
                                    KeyValuePartialInformation,
                                    ValueBuffer,
                                    sizeof(ValueBuffer),
                                    &ValueLen);
    KG_LOG("  ZwQueryValueKey=0x%08X vlen=%lu\n", Status, ValueLen);
    KL_NT(ZwClose)(KeyHandle);
    if (!NT_SUCCESS(Status))
        return Status;

    PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)ValueBuffer;
    if (Info->Type != REG_DWORD || Info->DataLength != sizeof(UINT32)) {
        KG_LOG("  bad type=%lu dlen=%lu\n", Info->Type, Info->DataLength);
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    *Out = *(UINT32*)Info->Data;
    KG_LOG("  ActiveUser=%lu\n", *Out);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ReadActiveSteamId64(
    UINT64* Out
)
{
    KG_LOG("ReadActiveSteamId64 enter\n");

    if (Out == NULL)
        return STATUS_INVALID_PARAMETER;

    *Out = 0;

    UNICODE_STRING UserRoot;
    KlazyMakeUS(&UserRoot, PX_W(L"\\Registry\\User"));

    OBJECT_ATTRIBUTES Attributes;
    InitializeObjectAttributes(&Attributes,
                               &UserRoot,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    HANDLE RootHandle = NULL;
    NTSTATUS Status = KL_NT(ZwOpenKey)(&RootHandle, KEY_ENUMERATE_SUB_KEYS, &Attributes);
    KG_LOG("open \\Registry\\User = 0x%08X\n", Status);
    if (!NT_SUCCESS(Status))
        return Status;

    ULONG Index = 0;
    NTSTATUS Result = STATUS_NOT_FOUND;
    const ULONG MaxHives = 64;

    for (; Index < MaxHives; ) {
        UCHAR NameBuffer[512];
        ULONG Returned = 0;
        Status = KL_NT(ZwEnumerateKey)(RootHandle,
                                       Index,
                                       KeyBasicInformation,
                                       NameBuffer,
                                       sizeof(NameBuffer),
                                       &Returned);
        KG_LOG("enum[%lu] = 0x%08X got=%lu\n", Index, Status, Returned);
        if (Status == STATUS_NO_MORE_ENTRIES)
            break;

        Index++;
        if (!NT_SUCCESS(Status))
            continue;

        if (Returned < sizeof(KEY_BASIC_INFORMATION))
            continue;

        PKEY_BASIC_INFORMATION Basic = (PKEY_BASIC_INFORMATION)NameBuffer;
        UNICODE_STRING SubName;
        SubName.Buffer        = Basic->Name;
        SubName.Length        = (USHORT)Basic->NameLength;
        SubName.MaximumLength = SubName.Length;

        KG_LOG("  hive=%wZ isUser=%d\n", &SubName, SubkeyIsUserHive(&SubName));

        if (!SubkeyIsUserHive(&SubName))
            continue;

        UINT32 ActiveUser = 0;
        NTSTATUS ReadStatus = TryReadActiveUser(&SubName, &ActiveUser);
        KG_LOG("  TryReadActiveUser=0x%08X user=%lu\n", ReadStatus, ActiveUser);
        if (!NT_SUCCESS(ReadStatus))
            continue;

        if (ActiveUser == 0)
            continue;

        *Out = KG_STEAM_ID64_BASE + (UINT64)ActiveUser;
        Result = STATUS_SUCCESS;
        break;
    }

    KL_NT(ZwClose)(RootHandle);
    KG_LOG("ReadActiveSteamId64 exit rc=0x%08X id=0x%016llX\n", Result, *Out);
    return Result;
}
