#include "crypto.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "pxenc.hpp"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0)
#endif

static NTSTATUS
OpenSha256(BCRYPT_ALG_HANDLE* alg, DWORD flags)
{
    return LI_BCRYPT(BCryptOpenAlgorithmProvider)(alg, pxenc(L"SHA256"), NULL, flags);
}

__declspec(noinline)
bool
HmacSha256(const BYTE* Key, ULONG KeyLen,
           const BYTE* Data, ULONG DataLen,
           BYTE Out[32])
{
    BRKIDA;
    if (!Key || !Data || !Out || KeyLen == 0)
        return false;

    BCRYPT_ALG_HANDLE  alg  = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;

    if (OpenSha256(&alg, BCRYPT_ALG_HANDLE_HMAC_FLAG) != STATUS_SUCCESS)
        return false;

    NTSTATUS s = LI_BCRYPT(BCryptCreateHash)(alg, &hash, NULL, 0, (PUCHAR)Key, KeyLen, 0);
    if (s == STATUS_SUCCESS) {
        s = LI_BCRYPT(BCryptHashData)(hash, (PUCHAR)Data, DataLen, 0);
        if (s == STATUS_SUCCESS)
            s = LI_BCRYPT(BCryptFinishHash)(hash, Out, 32, 0);
        LI_BCRYPT(BCryptDestroyHash)(hash);
    }
    LI_BCRYPT(BCryptCloseAlgorithmProvider)(alg, 0);
    return s == STATUS_SUCCESS;
}

bool
SecureRandom(BYTE* Buffer, ULONG Length)
{
    if (!Buffer || Length == 0)
        return false;
    return LI_BCRYPT(BCryptGenRandom)(NULL, Buffer, Length,
                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG) == STATUS_SUCCESS;
}

bool
Sha256Init(UPD_SHA256_CTX* Ctx)
{
    BRKIDA;
    if (!Ctx) return false;
    Ctx->Alg = NULL; Ctx->Hash = NULL;

    if (OpenSha256(&Ctx->Alg, 0) != STATUS_SUCCESS)
        return false;

    if (LI_BCRYPT(BCryptCreateHash)(Ctx->Alg, &Ctx->Hash, NULL, 0, NULL, 0, 0) != STATUS_SUCCESS) {
        LI_BCRYPT(BCryptCloseAlgorithmProvider)(Ctx->Alg, 0);
        Ctx->Alg = NULL;
        return false;
    }
    return true;
}

bool
Sha256Update(UPD_SHA256_CTX* Ctx, const BYTE* Data, ULONG Len)
{
    if (!Ctx || !Ctx->Hash || !Data) return false;
    if (Len == 0) return true;
    return LI_BCRYPT(BCryptHashData)(Ctx->Hash, (PUCHAR)Data, Len, 0) == STATUS_SUCCESS;
}

bool
Sha256Final(UPD_SHA256_CTX* Ctx, BYTE Out[32])
{
    if (!Ctx || !Ctx->Hash || !Out) return false;
    NTSTATUS s = LI_BCRYPT(BCryptFinishHash)(Ctx->Hash, Out, 32, 0);
    LI_BCRYPT(BCryptDestroyHash)(Ctx->Hash);
    LI_BCRYPT(BCryptCloseAlgorithmProvider)(Ctx->Alg, 0);
    Ctx->Hash = NULL; Ctx->Alg = NULL;
    return s == STATUS_SUCCESS;
}

static __declspec(noinline)
bool
AesCbc(bool encrypt,
       const BYTE Key[32], const BYTE Iv[16],
       const BYTE* In, ULONG InLen,
       BYTE* Out, ULONG* OutLen)
{
    BRKIDA;
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE k   = NULL;

    if (LI_BCRYPT(BCryptOpenAlgorithmProvider)(&alg, pxenc(L"AES"), NULL, 0) != STATUS_SUCCESS)
        return false;

    auto cbcBox = pxenc_raw(L"ChainingModeCBC");
    NTSTATUS s = LI_BCRYPT(BCryptSetProperty)(alg,
        pxenc(L"ChainingMode"),
        (PUCHAR)cbcBox.get(),
        sizeof(cbcBox.buf), 0);
    if (s != STATUS_SUCCESS) {
        LI_BCRYPT(BCryptCloseAlgorithmProvider)(alg, 0);
        return false;
    }

    s = LI_BCRYPT(BCryptGenerateSymmetricKey)(alg, &k, NULL, 0, (PUCHAR)Key, 32, 0);
    if (s != STATUS_SUCCESS) {
        LI_BCRYPT(BCryptCloseAlgorithmProvider)(alg, 0);
        return false;
    }

    BYTE ivCopy[16]; memcpy(ivCopy, Iv, 16);
    ULONG produced = 0;
    s = encrypt
        ? LI_BCRYPT(BCryptEncrypt)(k, (PUCHAR)In, InLen, NULL, ivCopy, 16,
                                   Out, *OutLen, &produced, BCRYPT_BLOCK_PADDING)
        : LI_BCRYPT(BCryptDecrypt)(k, (PUCHAR)In, InLen, NULL, ivCopy, 16,
                                   Out, *OutLen, &produced, BCRYPT_BLOCK_PADDING);

    LI_BCRYPT(BCryptDestroyKey)(k);
    LI_BCRYPT(BCryptCloseAlgorithmProvider)(alg, 0);
    if (s != STATUS_SUCCESS) return false;
    *OutLen = produced;
    return true;
}

bool
AesCbcDecrypt(const BYTE Key[32], const BYTE Iv[16],
              const BYTE* Ct, ULONG CtLen, BYTE* Pt, ULONG* PtLen)
{
    return AesCbc(false, Key, Iv, Ct, CtLen, Pt, PtLen);
}

bool
AesCbcEncrypt(const BYTE Key[32], const BYTE Iv[16],
              const BYTE* Pt, ULONG PtLen, BYTE* Ct, ULONG* CtLen)
{
    return AesCbc(true, Key, Iv, Pt, PtLen, Ct, CtLen);
}
