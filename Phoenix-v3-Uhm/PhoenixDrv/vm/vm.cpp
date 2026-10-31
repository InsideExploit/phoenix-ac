#include "vm.hpp"

#include <intrin.h>

#include "pxstr.hpp"
#include "klazy.hpp"

static
BOOLEAN
CpuidGuest(
    VOID
)
{
    int Regs[4] = { 0 };
    __cpuid(Regs, 1);
    if (!(Regs[2] & (1 << 31)))
        return FALSE;

    __cpuid(Regs, 0x40000000);
    if ((ULONG)Regs[0] < 0x40000000)
        return TRUE;

    char Vendor[13] = { 0 };
    RtlCopyMemory(Vendor + 0, &Regs[1], 4);
    RtlCopyMemory(Vendor + 4, &Regs[2], 4);
    RtlCopyMemory(Vendor + 8, &Regs[3], 4);
    Vendor[12] = '\0';

    if (RtlEqualMemory(Vendor, PX_A("Microsoft Hv"), 12))
        return FALSE;

    KG_DRV_LOG("[PhoenixDrv/VM] cpuid guest vendor=%s\n", Vendor);
    return TRUE;
}

static
const WCHAR*
GetForbiddenBiosSubstring(
    _In_ ULONG Index
)
{
    switch (Index) {
    case 0:  return PX_W(L"virtual machine");
    case 1:  return PX_W(L"vmware");
    case 2:  return PX_W(L"vbox");
    case 3:  return PX_W(L"virtualbox");
    case 4:  return PX_W(L"innotek");
    case 5:  return PX_W(L"qemu");
    case 6:  return PX_W(L"kvm");
    case 7:  return PX_W(L"xen");
    case 8:  return PX_W(L"parallels");
    case 9:  return PX_W(L"bochs");
    case 10: return PX_W(L"bhyve");
    case 11: return PX_W(L"nutanix");
    case 12: return PX_W(L"shadow");
    case 13: return PX_W(L"blade");
    case 14: return PX_W(L"blade group");
    case 15: return PX_W(L"ovh");
    case 16: return PX_W(L"scaleway");
    case 17: return PX_W(L"amazon ec2");
    case 18: return PX_W(L"google compute");
    case 19: return PX_W(L"gce");
    case 20: return PX_W(L"digitalocean");
    case 21: return PX_W(L"linode");
    case 22: return PX_W(L"vultr");
    case 23: return PX_W(L"microsoft corporation vm");
    default: return NULL;
    }
}

#define KG_FORBIDDEN_BIOS_COUNT 24

static
BOOLEAN
UnicodeContainsCiA(
    _In_reads_(HayCharCount) const WCHAR* Hay,
    _In_                     USHORT       HayCharCount,
    _In_z_                   const WCHAR* Needle
)
{
    if (Hay == NULL || Needle == NULL)
        return FALSE;

    SIZE_T NeedleLen = 0;
    while (Needle[NeedleLen])
        ++NeedleLen;

    if (NeedleLen == 0 || (SIZE_T)HayCharCount < NeedleLen)
        return FALSE;

    for (USHORT i = 0; i + NeedleLen <= HayCharCount; ++i) {
        BOOLEAN Equal = TRUE;

        for (SIZE_T j = 0; j < NeedleLen; ++j) {
            WCHAR A = Hay[i + j];
            WCHAR B = Needle[j];

            if (A >= L'A' && A <= L'Z')
                A = (WCHAR)(A - L'A' + L'a');
            if (B >= L'A' && B <= L'Z')
                B = (WCHAR)(B - L'A' + L'a');

            if (A != B) {
                Equal = FALSE;
                break;
            }
        }

        if (Equal)
            return TRUE;
    }

    return FALSE;
}

static
BOOLEAN
QueryBiosStringMatches(
    _In_z_ const WCHAR* ValueName
)
{
    UNICODE_STRING KeyPath;
    KlazyMakeUS(&KeyPath, PX_W(L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS"));

    OBJECT_ATTRIBUTES Attributes;
    InitializeObjectAttributes(&Attributes,
                               &KeyPath,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    HANDLE KeyHandle = NULL;
    NTSTATUS Status = KL_NT(ZwOpenKey)(&KeyHandle, KEY_QUERY_VALUE, &Attributes);
    if (!NT_SUCCESS(Status))
        return FALSE;

    UNICODE_STRING ValueNameUs;
    KlazyMakeUS(&ValueNameUs, ValueName);

    UCHAR Buffer[512];
    ULONG Returned = 0;
    Status = KL_NT(ZwQueryValueKey)(KeyHandle,
                                    &ValueNameUs,
                                    KeyValuePartialInformation,
                                    Buffer,
                                    sizeof(Buffer),
                                    &Returned);
    KL_NT(ZwClose)(KeyHandle);
    if (!NT_SUCCESS(Status))
        return FALSE;

    PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
    if (Info->Type != REG_SZ || Info->DataLength < sizeof(WCHAR))
        return FALSE;

    const WCHAR* Text  = (const WCHAR*)Info->Data;
    USHORT       Chars = (USHORT)(Info->DataLength / sizeof(WCHAR));
    if (Chars > 0 && Text[Chars - 1] == L'\0')
        --Chars;

    if (Chars == 0)
        return FALSE;

    for (ULONG i = 0; i < KG_FORBIDDEN_BIOS_COUNT; ++i) {
        const WCHAR* Needle = GetForbiddenBiosSubstring(i);
        if (Needle == NULL)
            continue;

        if (UnicodeContainsCiA(Text, Chars, Needle)) {
            KG_DRV_LOG("[PhoenixDrv/VM] BIOS %ws matched substring '%ws' text='%ws'\n",
                       ValueName, Needle, Text);
            return TRUE;
        }
    }

    return FALSE;
}

static
const WCHAR*
GetSmbiosValueName(
    _In_ ULONG Index
)
{
    switch (Index) {
    case 0: return PX_W(L"SystemManufacturer");
    case 1: return PX_W(L"SystemProductName");
    case 2: return PX_W(L"SystemFamily");
    case 3: return PX_W(L"SystemVersion");
    case 4: return PX_W(L"BIOSVendor");
    case 5: return PX_W(L"BIOSVersion");
    case 6: return PX_W(L"BaseBoardManufacturer");
    case 7: return PX_W(L"BaseBoardProduct");
    default: return NULL;
    }
}

#define KG_SMBIOS_VALUE_COUNT 8

static
BOOLEAN
SmbiosGuest(
    VOID
)
{
    for (ULONG i = 0; i < KG_SMBIOS_VALUE_COUNT; ++i) {
        const WCHAR* Name = GetSmbiosValueName(i);
        if (Name == NULL)
            continue;

        if (QueryBiosStringMatches(Name))
            return TRUE;
    }

    return FALSE;
}

_Use_decl_annotations_
BOOLEAN
IsRunningInDisallowedVm(
    VOID
)
{
#if KG_VM_ENFORCE
    if (CpuidGuest())
        return TRUE;

    if (SmbiosGuest())
        return TRUE;
#endif
    return FALSE;
}
