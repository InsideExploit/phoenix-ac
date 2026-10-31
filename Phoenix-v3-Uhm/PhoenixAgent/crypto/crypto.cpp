#include "crypto.hpp"
#include <bcrypt.h>
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0)
#endif

bool
HmacSha256(
    const BYTE* Key,
    ULONG       KeyLen,
    const BYTE* Data,
    ULONG       DataLen,
    BYTE        Out[32]
)
{
    VIRTUALIZER_START
    BRKIDA;
    if (!Key || !Data || !Out || KeyLen == 0)
        return false;

    BCRYPT_ALG_HANDLE  alg  = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;

    NTSTATUS status = LI_BCRYPT(BCryptOpenAlgorithmProvider)(&alg, pxenc(L"SHA256"), NULL,
                                                             BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status != STATUS_SUCCESS)
        return false;

    status = LI_BCRYPT(BCryptCreateHash)(alg, &hash, NULL, 0, (PUCHAR)Key, KeyLen, 0);
    if (status != STATUS_SUCCESS) {
        LI_BCRYPT(BCryptCloseAlgorithmProvider)(alg, 0);
        return false;
    }

    status = LI_BCRYPT(BCryptHashData)(hash, (PUCHAR)Data, DataLen, 0);
    if (status == STATUS_SUCCESS)
        status = LI_BCRYPT(BCryptFinishHash)(hash, Out, 32, 0);

    LI_BCRYPT(BCryptDestroyHash)(hash);
    LI_BCRYPT(BCryptCloseAlgorithmProvider)(alg, 0);
    VIRTUALIZER_END
    return status == STATUS_SUCCESS;
}

bool
SecureRandom(
    BYTE* Buffer,
    ULONG Length
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END
    if (!Buffer || Length == 0)
        return false;

    return LI_BCRYPT(BCryptGenRandom)(NULL, Buffer, Length,
                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG) == STATUS_SUCCESS;
}
