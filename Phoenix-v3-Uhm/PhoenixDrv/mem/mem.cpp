#include "mem.hpp"

extern "C" {
	NTSTATUS
	MmCopyVirtualMemory(
	    _In_  PEPROCESS         SourceProcess,
	    _In_  PVOID             SourceAddress,
	    _In_  PEPROCESS         TargetProcess,
	    _Out_ PVOID             TargetAddress,
	    _In_  SIZE_T            BufferSize,
	    _In_  KPROCESSOR_MODE   PreviousMode,
	    _Out_ PSIZE_T           ReturnSize
	);

	PVOID
	PsGetProcessSectionBaseAddress(
	    _In_ PEPROCESS Process
	);
}

#include "pxstr.hpp"
#include "klazy.hpp"

#define KG_MEM_LOG(fmt, ...) KG_DRV_LOG("[PhoenixDrv/Mem] " fmt, ##__VA_ARGS__)

KG_NO_OBFUSCATE
static
BOOLEAN
ReadUserMemory(
    _In_                     PEPROCESS Target,
    _In_                     PVOID     Address,
    _Out_writes_bytes_(Size) PVOID     Dest,
    _In_                     SIZE_T    Size
)
{
    SIZE_T   Copied = 0;
    NTSTATUS Status = KL_NT(MmCopyVirtualMemory)(Target,
                                                 Address,
                                                 KL_NT(IoGetCurrentProcess)(),
                                                 Dest,
                                                 Size,
                                                 KernelMode,
                                                 &Copied);
    return NT_SUCCESS(Status) && Copied == Size;
}

KG_NO_OBFUSCATE
_Use_decl_annotations_
NTSTATUS
MemQueryModule(
    UINT32            Pid,
    KG_MODULE_RESULT* Out
)
{
    if (Out == NULL)
        return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(Out, sizeof(*Out));

    PEPROCESS Process = NULL;
    NTSTATUS  Status  = KL_NT(PsLookupProcessByProcessId)((HANDLE)(ULONG_PTR)Pid, &Process);
    if (!NT_SUCCESS(Status))
        return Status;

    PVOID Base = KL_NT(PsGetProcessSectionBaseAddress)(Process);
    if (Base == NULL) {
        KL_NT(ObfDereferenceObject)(Process);
        return STATUS_NOT_FOUND;
    }

    UINT8 Header[0x400];
    if (!ReadUserMemory(Process, Base, Header, sizeof(Header))) {
        KL_NT(ObfDereferenceObject)(Process);
        return STATUS_ACCESS_DENIED;
    }

    KL_NT(ObfDereferenceObject)(Process);

    if (Header[0] != 'M' || Header[1] != 'Z')
        return STATUS_INVALID_IMAGE_FORMAT;

    UINT32 PeOffset = *(UINT32*)(Header + 0x3C);
    if (PeOffset > sizeof(Header) - 0x100)
        return STATUS_INVALID_IMAGE_FORMAT;

    if (*(UINT32*)(Header + PeOffset) != 0x00004550u)
        return STATUS_INVALID_IMAGE_FORMAT;

    UINT16 Magic       = *(UINT16*)(Header + PeOffset + 0x18);
    UINT32 SizeOfImage = 0;
    if (Magic == 0x20b)
        SizeOfImage = *(UINT32*)(Header + PeOffset + 0x18 + 0x38);
    else if (Magic == 0x10b)
        SizeOfImage = *(UINT32*)(Header + PeOffset + 0x18 + 0x38);
    else
        return STATUS_INVALID_IMAGE_FORMAT;

    Out->Base = (UINT64)Base;
    Out->Size = SizeOfImage;
    return STATUS_SUCCESS;
}

KG_NO_OBFUSCATE
_Use_decl_annotations_
NTSTATUS
MemRead(
    UINT32  Pid,
    UINT64  Address,
    PVOID   Dest,
    SIZE_T  Size,
    SIZE_T* Copied
)
{
    if (Dest == NULL || Size == 0 || Size > KG_MEM_MAX_IO)
        return STATUS_INVALID_PARAMETER;

    *Copied = 0;

    PEPROCESS Process = NULL;
    NTSTATUS  Status  = KL_NT(PsLookupProcessByProcessId)((HANDLE)(ULONG_PTR)Pid, &Process);
    if (!NT_SUCCESS(Status))
        return Status;

    SIZE_T Read = 0;
    Status = KL_NT(MmCopyVirtualMemory)(Process,
                                        (PVOID)(ULONG_PTR)Address,
                                        KL_NT(IoGetCurrentProcess)(),
                                        Dest,
                                        Size,
                                        KernelMode,
                                        &Read);
    KL_NT(ObfDereferenceObject)(Process);
    if (!NT_SUCCESS(Status))
        return Status;

    *Copied = Read;
    return STATUS_SUCCESS;
}

KG_NO_OBFUSCATE
_Use_decl_annotations_
NTSTATUS
MemWrite(
    UINT32       Pid,
    UINT64       Address,
    const void*  Source,
    SIZE_T       Size,
    SIZE_T*      Copied
)
{
    if (Source == NULL || Size == 0 || Size > KG_MEM_MAX_IO)
        return STATUS_INVALID_PARAMETER;

    *Copied = 0;

    PEPROCESS Process = NULL;
    NTSTATUS  Status  = KL_NT(PsLookupProcessByProcessId)((HANDLE)(ULONG_PTR)Pid, &Process);
    if (!NT_SUCCESS(Status))
        return Status;

    SIZE_T Written = 0;
    Status = KL_NT(MmCopyVirtualMemory)(KL_NT(IoGetCurrentProcess)(),
                                        (PVOID)Source,
                                        Process,
                                        (PVOID)(ULONG_PTR)Address,
                                        Size,
                                        KernelMode,
                                        &Written);
    KL_NT(ObfDereferenceObject)(Process);
    if (!NT_SUCCESS(Status))
        return Status;

    *Copied = Written;
    return STATUS_SUCCESS;
}

KG_NO_OBFUSCATE
_Use_decl_annotations_
NTSTATUS
MemScan(
    const KG_SCAN_REQUEST* Req,
    KG_SCAN_RESULT*        Out
)
{
    if (Req == NULL || Out == NULL)
        return STATUS_INVALID_PARAMETER;

    Out->Hit = 0;

    if (Req->PatternLen == 0 || Req->PatternLen > KG_SCAN_MAX_PAT)
        return STATUS_INVALID_PARAMETER;

    if (Req->RangeSize == 0 || Req->RangeSize > 0x10000000ULL)
        return STATUS_INVALID_PARAMETER;

    PEPROCESS Process = NULL;
    NTSTATUS  Status  = KL_NT(PsLookupProcessByProcessId)((HANDLE)(ULONG_PTR)Req->Pid, &Process);
    if (!NT_SUCCESS(Status))
        return Status;

    const SIZE_T ChunkSize = 0x4000;
    UINT8* Chunk = (UINT8*)KL_NT(ExAllocatePool2)(POOL_FLAG_NON_PAGED,
                                                  ChunkSize + KG_SCAN_MAX_PAT,
                                                  'nCSk');
    if (Chunk == NULL) {
        KL_NT(ObfDereferenceObject)(Process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    UINT64   Cursor = Req->RangeStart;
    UINT64   End    = Req->RangeStart + Req->RangeSize;
    SIZE_T   Carry  = 0;
    NTSTATUS Result = STATUS_NOT_FOUND;

    while (Cursor < End) {
        SIZE_T Want = ChunkSize;
        if (Cursor + Want > End)
            Want = (SIZE_T)(End - Cursor);

        SIZE_T   Read       = 0;
        NTSTATUS ReadStatus = KL_NT(MmCopyVirtualMemory)(Process,
                                                         (PVOID)(ULONG_PTR)Cursor,
                                                         KL_NT(IoGetCurrentProcess)(),
                                                         Chunk + Carry,
                                                         Want,
                                                         KernelMode,
                                                         &Read);
        if (!NT_SUCCESS(ReadStatus) || Read == 0) {
            Cursor += Want;
            Carry   = 0;
            continue;
        }

        SIZE_T Total = Carry + Read;
        if (Total >= Req->PatternLen) {
            SIZE_T Limit = Total - Req->PatternLen;

            for (SIZE_T i = 0; i <= Limit; i++) {
                BOOLEAN Match = TRUE;

                for (UINT32 k = 0; k < Req->PatternLen; k++) {
                    if (Req->Mask[k] && Chunk[i + k] != Req->Pattern[k]) {
                        Match = FALSE;
                        break;
                    }
                }

                if (Match) {
                    Out->Hit = Cursor - Carry + i;
                    Result   = STATUS_SUCCESS;
                    break;
                }
            }
        }

        if (Result == STATUS_SUCCESS)
            break;

        if (Total >= Req->PatternLen) {
            SIZE_T Keep = Req->PatternLen - 1;
            RtlMoveMemory(Chunk, Chunk + Total - Keep, Keep);
            Carry = Keep;
        } else Carry = Total;

        Cursor += Read;
    }

    g_KH.ExFreePoolWithTag(Chunk, 0);
    KL_NT(ObfDereferenceObject)(Process);
    return Result;
}
