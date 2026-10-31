#pragma once
#include <windows.h>
#include <bcrypt.h>

bool HmacSha256(const BYTE* Key, ULONG KeyLen, const BYTE* Data, ULONG DataLen, BYTE Out[32]);
bool SecureRandom(BYTE* Buffer, ULONG Length);

struct UPD_SHA256_CTX {
    BCRYPT_ALG_HANDLE  Alg;
    BCRYPT_HASH_HANDLE Hash;
};

bool Sha256Init  (UPD_SHA256_CTX* Ctx);
bool Sha256Update(UPD_SHA256_CTX* Ctx, const BYTE* Data, ULONG Len);
bool Sha256Final (UPD_SHA256_CTX* Ctx, BYTE Out[32]);

bool AesCbcDecrypt(const BYTE Key[32], const BYTE Iv[16],
                   const BYTE* Ct, ULONG CtLen, BYTE* Pt, ULONG* PtLen);
bool AesCbcEncrypt(const BYTE Key[32], const BYTE Iv[16],
                   const BYTE* Pt, ULONG PtLen, BYTE* Ct, ULONG* CtLen);
