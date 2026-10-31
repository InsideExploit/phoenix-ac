#include "crypto.hpp"

#include <bcrypt.h>

#include "klazy.hpp"

_Use_decl_annotations_
NTSTATUS
HmacSha256(
    const UINT8*  Key,
    ULONG         KeyLen,
    const UINT8*  Data,
    ULONG         DataLen,
    UINT8         Out[32]
)
{
    BCRYPT_ALG_HANDLE  AlgHandle  = NULL;
    BCRYPT_HASH_HANDLE HashHandle = NULL;

    NTSTATUS Status = KL_KSECDD(BCryptOpenAlgorithmProvider)(&AlgHandle,
                                                             PX_W(BCRYPT_SHA256_ALGORITHM),
                                                             NULL,
                                                             BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = KL_KSECDD(BCryptCreateHash)(AlgHandle,
                                         &HashHandle,
                                         NULL,
                                         0,
                                         (PUCHAR)Key,
                                         KeyLen,
                                         0);
    if (!NT_SUCCESS(Status)) {
        KL_KSECDD(BCryptCloseAlgorithmProvider)(AlgHandle, 0);
        return Status;
    }

    Status = KL_KSECDD(BCryptHashData)(HashHandle, (PUCHAR)Data, DataLen, 0);
    if (NT_SUCCESS(Status))
        Status = KL_KSECDD(BCryptFinishHash)(HashHandle, Out, 32, 0);

    KL_KSECDD(BCryptDestroyHash)(HashHandle);
    KL_KSECDD(BCryptCloseAlgorithmProvider)(AlgHandle, 0);
    return Status;
}
