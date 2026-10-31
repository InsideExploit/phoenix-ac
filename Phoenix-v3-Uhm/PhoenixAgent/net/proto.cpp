#include "proto.hpp"
#include <ws2tcpip.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>
#include "../crypto/crypto.hpp"
#include "../dbg.hpp"
#include "pxstr.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0)
#endif

#define KG_WIRE_MAGIC   0x50414331u
#define KG_WIRE_VERSION 0x0001

static const BYTE KG_PSK[32] = { 0 }; // REDACTED

static
void
HkdfExpand32(
    const BYTE  prk[32],
    const char* info,
    ULONG       infoLen,
    BYTE        out[32]
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    BYTE buf[64];
    memcpy(buf, info, infoLen);
    buf[infoLen] = 0x01;
    HmacSha256(prk, 32, buf, infoLen + 1, out);
}

static
bool
DeriveKeys(
    const BYTE       clientNonce[16],
    const BYTE       serverNonce[16],
    KG_SESSION_KEYS* out
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    BYTE salt[32];
    memcpy(salt, clientNonce, 16);
    memcpy(salt + 16, serverNonce, 16);

    BYTE prk[32];
    if (!HmacSha256(salt, 32, KG_PSK, 32, prk))
        return false;

    VIRTUALIZER_START
    auto infoEnc  = PX_AS("phoenixac/session/enc/v1");
    auto infoMac  = PX_AS("phoenixac/session/mac/v1");
    auto infoObf  = PX_AS("phoenixac/session/obf/v1");
    auto infoSlot = PX_AS("phoenixac/session/slot/v1");
    VIRTUALIZER_END

    HkdfExpand32(prk, infoEnc,  (ULONG)strlen(infoEnc),  out->Enc);
    HkdfExpand32(prk, infoMac,  (ULONG)strlen(infoMac),  out->Mac);
    HkdfExpand32(prk, infoObf,  (ULONG)strlen(infoObf),  out->Obf);
    HkdfExpand32(prk, infoSlot, (ULONG)strlen(infoSlot), out->Slot);
    return true;
}

static __declspec(noinline)
void
XorObfuscate(
    BYTE*      buf,
    ULONG      len,
    const BYTE obf[32],
    const BYTE nonce[16]
)
{
    BRKIDA;
    VIRTUALIZER_START
    ULONG rot = nonce[0] & 0x1f;
    for (ULONG i = 0; i < len; i++) {
        BYTE k = obf[(i + rot) & 0x1f];
        BYTE p = nonce[i & 0x0f];
        BYTE m = (BYTE)((i * 0x9e) & 0xff);
        buf[i] = (BYTE)(buf[i] ^ k ^ p ^ m);
    }
    VIRTUALIZER_END
}

static
bool
AesCbcCrypt(
    bool        encrypt,
    const BYTE  key[32],
    BYTE        iv[16],
    const BYTE* in,
    ULONG       inLen,
    BYTE*       out,
    ULONG*      outLen
)
{
    VIRTUALIZER_START
    BRKIDA;
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE k = NULL;
    NTSTATUS s = LI_BCRYPT(BCryptOpenAlgorithmProvider)(&alg, pxenc(L"AES"), NULL, 0);
    if (s != STATUS_SUCCESS)
        return false;

    auto cbcBox = pxenc_raw(L"ChainingModeCBC");
    s = LI_BCRYPT(BCryptSetProperty)(alg,
                                     pxenc(L"ChainingMode"),
                                     (PUCHAR)cbcBox.get(),
                                     sizeof(cbcBox.buf), 0);
    if (s != STATUS_SUCCESS) {
        LI_BCRYPT(BCryptCloseAlgorithmProvider)(alg, 0);
        return false;
    }

    s = LI_BCRYPT(BCryptGenerateSymmetricKey)(alg, &k, NULL, 0, (PUCHAR)key, 32, 0);
    if (s != STATUS_SUCCESS) {
        LI_BCRYPT(BCryptCloseAlgorithmProvider)(alg, 0);
        return false;
    }

    ULONG produced = 0;
    BYTE ivCopy[16];
    memcpy(ivCopy, iv, 16);

    if (encrypt) {
        s = LI_BCRYPT(BCryptEncrypt)(k, (PUCHAR)in, inLen, NULL, ivCopy, 16,
                                     out, *outLen, &produced, BCRYPT_BLOCK_PADDING);
    } else {
        s = LI_BCRYPT(BCryptDecrypt)(k, (PUCHAR)in, inLen, NULL, ivCopy, 16,
                                     out, *outLen, &produced, BCRYPT_BLOCK_PADDING);
    }

    LI_BCRYPT(BCryptDestroyKey)(k);
    LI_BCRYPT(BCryptCloseAlgorithmProvider)(alg, 0);
    if (s != STATUS_SUCCESS)
        return false;

    *outLen = produced;
    VIRTUALIZER_END
    return true;
}

static
void
WriteFrameHeader(
    BYTE   hdr[12],
    BYTE   kind,
    UINT32 payloadLen
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    hdr[0] = (BYTE)(KG_WIRE_MAGIC >> 24);
    hdr[1] = (BYTE)(KG_WIRE_MAGIC >> 16);
    hdr[2] = (BYTE)(KG_WIRE_MAGIC >> 8);
    hdr[3] = (BYTE)(KG_WIRE_MAGIC);
    hdr[4] = (BYTE)(KG_WIRE_VERSION >> 8);
    hdr[5] = (BYTE)(KG_WIRE_VERSION);
    hdr[6] = kind;
    hdr[7] = 0;
    hdr[8]  = (BYTE)(payloadLen >> 24);
    hdr[9]  = (BYTE)(payloadLen >> 16);
    hdr[10] = (BYTE)(payloadLen >> 8);
    hdr[11] = (BYTE)payloadLen;
}

static
bool
ReadFrameHeader(
    const BYTE hdr[12],
    BYTE*      kind,
    UINT32*    payloadLen
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    UINT32 magic = ((UINT32)hdr[0] << 24) | ((UINT32)hdr[1] << 16) |
                   ((UINT32)hdr[2] << 8)  | (UINT32)hdr[3];
    UINT16 ver = (UINT16)((hdr[4] << 8) | hdr[5]);
    if (magic != KG_WIRE_MAGIC || ver != KG_WIRE_VERSION)
        return false;

    *kind = hdr[6];
    *payloadLen = ((UINT32)hdr[8] << 24) | ((UINT32)hdr[9] << 16) |
                  ((UINT32)hdr[10] << 8) | (UINT32)hdr[11];
    return true;
}

static
bool
SendAll(
    SOCKET      s,
    const BYTE* data,
    ULONG       len
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    while (len > 0) {
        int n = LI_WS2(send)(s, (const char*)data, len, 0);
        if (n <= 0)
            return false;

        data += n; len -= n;
    }
    return true;
}

static
bool
RecvAll(
    SOCKET s,
    BYTE*  data,
    ULONG  len
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    while (len > 0) {
        int n = LI_WS2(recv)(s, (char*)data, len, 0);
        if (n <= 0)
            return false;

        data += n; len -= n;
    }
    return true;
}

bool
NetInit(
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    LI_KERNEL(LoadLibraryW)(pxenc(L"ws2_32.dll"));
    WSADATA wsa;
    return LI_WS2(WSAStartup)(MAKEWORD(2, 2), &wsa) == 0;
}

void
NetShutdown(
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    LI_WS2(WSACleanup)();
}

SOCKET
NetDial(
    const char* Host,
    const char* Port,
    DWORD       ConnectTimeoutMs,
    DWORD       IoTimeoutMs
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    ADDRINFOA hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    ADDRINFOA* res = NULL;
    int rc = LI_WS2(getaddrinfo)(Host, Port, &hints, &res);
    if (rc != 0 || !res)
        return INVALID_SOCKET;

    SOCKET out = INVALID_SOCKET;
    for (ADDRINFOA* p = res; p; p = p->ai_next) {
        SOCKET s = LI_WS2(socket)(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s == INVALID_SOCKET)
            continue;

        u_long nb = 1;
        LI_WS2(ioctlsocket)(s, FIONBIO, &nb);

        int cr = LI_WS2(connect)(s, p->ai_addr, (int)p->ai_addrlen);
        int err = (cr == 0) ? 0 : LI_WS2(WSAGetLastError)();
        if (cr != 0 && err != WSAEWOULDBLOCK) {
            LI_WS2(closesocket)(s);
            continue;
        }

        if (cr != 0) {
            fd_set wfd, efd;
            FD_ZERO(&wfd); FD_ZERO(&efd);
            FD_SET(s, &wfd); FD_SET(s, &efd);
            TIMEVAL tv;
            tv.tv_sec  = ConnectTimeoutMs / 1000;
            tv.tv_usec = (ConnectTimeoutMs % 1000) * 1000;
            int sr = LI_WS2(select)(0, NULL, &wfd, &efd, &tv);
            if (sr <= 0) {
                LI_WS2(closesocket)(s);
                continue;
            }
            if (FD_ISSET(s, &efd)) {
                LI_WS2(closesocket)(s);
                continue;
            }
        }

        u_long nb0 = 0;
        LI_WS2(ioctlsocket)(s, FIONBIO, &nb0);

        LI_WS2(setsockopt)(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&IoTimeoutMs, sizeof(IoTimeoutMs));
        LI_WS2(setsockopt)(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&IoTimeoutMs, sizeof(IoTimeoutMs));
        out = s;
        break;
    }
    LI_WS2(freeaddrinfo)(res);
    return out;
}

void
NetClose(
    SOCKET s
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    if (s == INVALID_SOCKET)
        return;

    LI_WS2(shutdown)(s, SD_BOTH);
    LI_WS2(closesocket)(s);
}

__declspec(noinline)
bool
NetHandshake(
    SOCKET           s,
    KG_SESSION_KEYS* Keys
)
{
    volatile int _vm_seal = 0;
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END
    _vm_seal = 1;
    (void)_vm_seal;

    BYTE clientNonce[16];
    if (!SecureRandom(clientNonce, 16))
        return false;

    bool ok = false;

    BYTE hdr[12];
    if (RecvAll(s, hdr, 12)) {
        BYTE kind = 0; UINT32 payloadLen = 0;
        if (ReadFrameHeader(hdr, &kind, &payloadLen) &&
            kind == KG_FRAME_HANDSHAKE &&
            payloadLen == 2 + KG_HELLO_LEN) {
            BYTE hello[2 + KG_HELLO_LEN];
            if (RecvAll(s, hello, payloadLen)) {
                UINT16 helloOp = (UINT16)((hello[0] << 8) | hello[1]);
                if (helloOp == KG_OP_SERVER_HELLO) {
                    BYTE serverNonce[16];
                    memcpy(serverNonce, hello + 2, 16);
                    if (DeriveKeys(clientNonce, serverNonce, Keys)) {
                        BYTE chOut[2 + KG_HELLO_LEN];
                        chOut[0] = (BYTE)(KG_OP_CLIENT_HELLO >> 8);
                        chOut[1] = (BYTE)(KG_OP_CLIENT_HELLO);
                        memcpy(chOut + 2, clientNonce, 16);
                        chOut[18] = (BYTE)(KG_PROTO_VERSION >> 8);
                        chOut[19] = (BYTE)(KG_PROTO_VERSION);

                        BYTE chHdr[12];
                        WriteFrameHeader(chHdr, KG_FRAME_HANDSHAKE, sizeof(chOut));
                        if (SendAll(s, chHdr, 12) && SendAll(s, chOut, sizeof(chOut)))
                            ok = true;
                    }
                }
            }
        }
    }

    return ok;
}

bool
NetSendEncrypted(
    SOCKET                 s,
    const KG_SESSION_KEYS* Keys,
    UINT16                 Opcode,
    const BYTE*            Body,
    ULONG                  BodyLen
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    if (BodyLen > 8 * 1024 * 1024)
        return false;

    ULONG innerLen = KG_ENC_INNER_HDR + BodyLen;
    ULONG ctCap    = innerLen + 16;

    BYTE* inner = (BYTE*)HeapAlloc(GetProcessHeap(), 0, innerLen);
    BYTE* ct    = (BYTE*)HeapAlloc(GetProcessHeap(), 0, ctCap);
    if (!inner || !ct) {
        if (inner) HeapFree(GetProcessHeap(), 0, inner);
        if (ct)    HeapFree(GetProcessHeap(), 0, ct);
        return false;
    }

    FILETIME ft; LI_KERNEL(GetSystemTimeAsFileTime)(&ft);
    UINT64 ft64 = ((UINT64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    UINT64 nowMs = (ft64 - 116444736000000000ULL) / 10000ULL;

    for (int i = 0; i < 8; i++) inner[i] = (BYTE)(nowMs >> (56 - i * 8));
    inner[8]  = (BYTE)(Opcode >> 8);
    inner[9]  = (BYTE)Opcode;
    inner[10] = (BYTE)(BodyLen >> 24);
    inner[11] = (BYTE)(BodyLen >> 16);
    inner[12] = (BYTE)(BodyLen >> 8);
    inner[13] = (BYTE)BodyLen;
    memcpy(inner + KG_ENC_INNER_HDR, Body, BodyLen);

    BYTE nonce[16];
    if (!SecureRandom(nonce, 16)) {
        HeapFree(GetProcessHeap(), 0, inner);
        HeapFree(GetProcessHeap(), 0, ct);
        return false;
    }

    XorObfuscate(inner, innerLen, Keys->Obf, nonce);

    BYTE iv[16];
    if (!SecureRandom(iv, 16)) {
        HeapFree(GetProcessHeap(), 0, inner);
        HeapFree(GetProcessHeap(), 0, ct);
        return false;
    }

    ULONG ctLen = ctCap;
    if (!AesCbcCrypt(true, Keys->Enc, iv, inner, innerLen, ct, &ctLen)) {
        HeapFree(GetProcessHeap(), 0, inner);
        HeapFree(GetProcessHeap(), 0, ct);
        return false;
    }
    HeapFree(GetProcessHeap(), 0, inner);

    UINT32 payloadLen = KG_NONCE_LEN + KG_IV_LEN + ctLen + KG_MAC_LEN;
    BYTE hdr[12];
    WriteFrameHeader(hdr, KG_FRAME_ENCRYPTED, payloadLen);

    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE h = NULL;
    NTSTATUS st = LI_BCRYPT(BCryptOpenAlgorithmProvider)(&alg, pxenc(L"SHA256"), NULL,
                                                         BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (st != STATUS_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, ct);
        return false;
    }
    st = LI_BCRYPT(BCryptCreateHash)(alg, &h, NULL, 0, (PUCHAR)Keys->Mac, 32, 0);
    if (st != STATUS_SUCCESS) {
        LI_BCRYPT(BCryptCloseAlgorithmProvider)(alg, 0);
        HeapFree(GetProcessHeap(), 0, ct);
        return false;
    }
    LI_BCRYPT(BCryptHashData)(h, hdr, 12, 0);
    LI_BCRYPT(BCryptHashData)(h, nonce, 16, 0);
    LI_BCRYPT(BCryptHashData)(h, iv, 16, 0);
    LI_BCRYPT(BCryptHashData)(h, ct, ctLen, 0);
    BYTE mac[32];
    LI_BCRYPT(BCryptFinishHash)(h, mac, 32, 0);
    LI_BCRYPT(BCryptDestroyHash)(h);
    LI_BCRYPT(BCryptCloseAlgorithmProvider)(alg, 0);

    bool sendOk = true;
    if (!SendAll(s, hdr, 12))     sendOk = false;
    if (sendOk && !SendAll(s, nonce, 16)) sendOk = false;
    if (sendOk && !SendAll(s, iv, 16))    sendOk = false;
    if (sendOk && !SendAll(s, ct, ctLen)) sendOk = false;
    HeapFree(GetProcessHeap(), 0, ct);
    if (!sendOk)
        return false;

    if (!SendAll(s, mac, 32))
        return false;

    return true;
}

bool
NetRecvEncrypted(
    SOCKET                 s,
    const KG_SESSION_KEYS* Keys,
    UINT16*                Opcode,
    BYTE*                  Body,
    ULONG*                 BodyLen
)
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    BYTE hdr[12];
    if (!RecvAll(s, hdr, 12))
        return false;

    BYTE kind = 0; UINT32 payloadLen = 0;
    if (!ReadFrameHeader(hdr, &kind, &payloadLen))
        return false;

    if (kind != KG_FRAME_ENCRYPTED)
        return false;

    if (payloadLen < KG_NONCE_LEN + KG_IV_LEN + KG_MAC_LEN + 16)
        return false;

    if (payloadLen > 4096)
        return false;

    BYTE payload[4096];
    if (!RecvAll(s, payload, payloadLen))
        return false;

    const BYTE* nonce = payload;
    const BYTE* iv    = payload + KG_NONCE_LEN;
    ULONG ctLen       = payloadLen - KG_NONCE_LEN - KG_IV_LEN - KG_MAC_LEN;
    const BYTE* ct    = payload + KG_NONCE_LEN + KG_IV_LEN;
    const BYTE* mac   = payload + payloadLen - KG_MAC_LEN;

    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE h = NULL;
    NTSTATUS st = LI_BCRYPT(BCryptOpenAlgorithmProvider)(&alg, pxenc(L"SHA256"), NULL,
                                                         BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (st != STATUS_SUCCESS)
        return false;

    st = LI_BCRYPT(BCryptCreateHash)(alg, &h, NULL, 0, (PUCHAR)Keys->Mac, 32, 0);
    if (st != STATUS_SUCCESS) {
        LI_BCRYPT(BCryptCloseAlgorithmProvider)(alg, 0);
        return false;
    }
    LI_BCRYPT(BCryptHashData)(h, hdr, 12, 0);
    LI_BCRYPT(BCryptHashData)(h, (PUCHAR)nonce, 16, 0);
    LI_BCRYPT(BCryptHashData)(h, (PUCHAR)iv, 16, 0);
    LI_BCRYPT(BCryptHashData)(h, (PUCHAR)ct, ctLen, 0);
    BYTE expect[32];
    LI_BCRYPT(BCryptFinishHash)(h, expect, 32, 0);
    LI_BCRYPT(BCryptDestroyHash)(h);
    LI_BCRYPT(BCryptCloseAlgorithmProvider)(alg, 0);

    ULONG diff = 0;
    for (int i = 0; i < 32; i++) diff |= (ULONG)(expect[i] ^ mac[i]);
    if (diff != 0)
        return false;

    BYTE pt[4096];
    ULONG ptLen = sizeof(pt);
    BYTE ivCopy[16]; memcpy(ivCopy, iv, 16);
    if (!AesCbcCrypt(false, Keys->Enc, ivCopy, ct, ctLen, pt, &ptLen))
        return false;

    if (ptLen < KG_ENC_INNER_HDR)
        return false;

    XorObfuscate(pt, ptLen, Keys->Obf, nonce);

    UINT16 op = (UINT16)((pt[8] << 8) | pt[9]);
    UINT32 bLen = ((UINT32)pt[10] << 24) | ((UINT32)pt[11] << 16) |
                  ((UINT32)pt[12] << 8) | (UINT32)pt[13];
    if (ptLen < KG_ENC_INNER_HDR + bLen)
        return false;

    if (bLen > *BodyLen)
        return false;

    *Opcode = op;
    memcpy(Body, pt + KG_ENC_INNER_HDR, bLen);
    *BodyLen = bLen;
    return true;
}
