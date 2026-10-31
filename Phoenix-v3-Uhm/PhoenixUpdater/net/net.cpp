#include "net.hpp"
#include <ws2tcpip.h>
#include <bcrypt.h>
#include <string.h>
#include "../crypto/crypto.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "pxenc.hpp"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0)
#endif

#define UPD_WIRE_MAGIC   0x50414331u
#define UPD_WIRE_VERSION 0x0001

static const BYTE UPD_PSK[32] = { 0 }; // REDACTED

static void
HkdfExpand32(const BYTE prk[32], const char* info, ULONG infoLen, BYTE out[32])
{
    BYTE buf[64];
    memcpy(buf, info, infoLen);
    buf[infoLen] = 0x01;
    HmacSha256(prk, 32, buf, infoLen + 1, out);
    SecureZeroMemory(buf, sizeof(buf));
}

static bool
DeriveKeys(const BYTE clientNonce[16], const BYTE serverNonce[16], UPD_SESSION_KEYS* out)
{
    BYTE salt[32];
    memcpy(salt, clientNonce, 16);
    memcpy(salt + 16, serverNonce, 16);

    BYTE prk[32];
    bool ok = HmacSha256(salt, 32, UPD_PSK, 32, prk);
    SecureZeroMemory(salt, sizeof(salt));
    if (!ok) { SecureZeroMemory(prk, sizeof(prk)); return false; }

    auto info0 = PX_AS("phoenixac/session/enc/v1");
    auto info1 = PX_AS("phoenixac/session/mac/v1");
    auto info2 = PX_AS("phoenixac/session/obf/v1");
    auto info3 = PX_AS("phoenixac/session/slot/v1");
    const char* infos[4] = { info0, info1, info2, info3 };
    BYTE* dests[4] = { out->Enc, out->Mac, out->Obf, out->Slot };
    for (int i = 0; i < 4; i++)
        HkdfExpand32(prk, infos[i], (ULONG)strlen(infos[i]), dests[i]);

    SecureZeroMemory(prk, sizeof(prk));
    return true;
}

static void
XorObf(BYTE* buf, ULONG len, const BYTE obf[32], const BYTE nonce[16])
{
    ULONG rot = nonce[0] & 0x1f;
    for (ULONG i = 0; i < len; i++)
        buf[i] ^= (BYTE)(obf[(i + rot) & 0x1f] ^ nonce[i & 0x0f] ^ (BYTE)((i * 0x9e) & 0xff));
}

static void
WriteU32BE(BYTE* p, UINT32 v)
{
    p[0] = (BYTE)(v >> 24); p[1] = (BYTE)(v >> 16);
    p[2] = (BYTE)(v >>  8); p[3] = (BYTE) v;
}

static UINT32
ReadU32BE(const BYTE* p)
{
    return ((UINT32)p[0] << 24) | ((UINT32)p[1] << 16) |
           ((UINT32)p[2] <<  8) |  (UINT32)p[3];
}

static UINT16
ReadU16BE(const BYTE* p)
{
    return (UINT16)((p[0] << 8) | p[1]);
}

static void
WriteFrameHeader(BYTE hdr[12], BYTE kind, UINT32 payloadLen)
{
    WriteU32BE(hdr, UPD_WIRE_MAGIC);
    hdr[4] = (BYTE)(UPD_WIRE_VERSION >> 8);
    hdr[5] = (BYTE) UPD_WIRE_VERSION;
    hdr[6] = kind;
    hdr[7] = 0;
    WriteU32BE(hdr + 8, payloadLen);
}

static bool
ReadFrameHeader(const BYTE hdr[12], BYTE* kind, UINT32* payloadLen)
{
    if (ReadU32BE(hdr) != UPD_WIRE_MAGIC || ReadU16BE(hdr + 4) != UPD_WIRE_VERSION)
        return false;
    *kind = hdr[6];
    *payloadLen = ReadU32BE(hdr + 8);
    return true;
}

static bool
SendAll(SOCKET s, const BYTE* data, ULONG len)
{
    while (len > 0) {
        int n = LI_WS2(send)(s, (const char*)data, len, 0);
        if (n <= 0) return false;
        data += n; len -= n;
    }
    return true;
}

static bool
RecvAll(SOCKET s, BYTE* data, ULONG len)
{
    while (len > 0) {
        int n = LI_WS2(recv)(s, (char*)data, len, 0);
        if (n <= 0) return false;
        data += n; len -= n;
    }
    return true;
}

bool
NetInit()
{
    LI_KERNEL(LoadLibraryW)(pxenc(L"ws2_32.dll"));
    WSADATA wsa;
    return LI_WS2(WSAStartup)(MAKEWORD(2, 2), &wsa) == 0;
}

void
NetShutdown()
{
    LI_WS2(WSACleanup)();
}

SOCKET
NetDial(const char* Host, const char* Port, DWORD ConnectTimeoutMs, DWORD IoTimeoutMs)
{
    ADDRINFOA hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    ADDRINFOA* res = NULL;
    if (LI_WS2(getaddrinfo)(Host, Port, &hints, &res) != 0 || !res)
        return INVALID_SOCKET;

    SOCKET out = INVALID_SOCKET;
    for (ADDRINFOA* p = res; p; p = p->ai_next) {
        SOCKET s = LI_WS2(socket)(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s == INVALID_SOCKET) continue;

        u_long nb = 1;
        LI_WS2(ioctlsocket)(s, FIONBIO, &nb);

        int cr = LI_WS2(connect)(s, p->ai_addr, (int)p->ai_addrlen);
        if (cr != 0 && LI_WS2(WSAGetLastError)() != WSAEWOULDBLOCK) {
            LI_WS2(closesocket)(s); continue;
        }

        if (cr != 0) {
            fd_set wfd, efd;
            FD_ZERO(&wfd); FD_ZERO(&efd);
            FD_SET(s, &wfd); FD_SET(s, &efd);
            TIMEVAL tv;
            tv.tv_sec  = ConnectTimeoutMs / 1000;
            tv.tv_usec = (ConnectTimeoutMs % 1000) * 1000;
            if (LI_WS2(select)(0, NULL, &wfd, &efd, &tv) <= 0 || FD_ISSET(s, &efd)) {
                LI_WS2(closesocket)(s); continue;
            }
        }

        u_long nb0 = 0;
        LI_WS2(ioctlsocket)(s, FIONBIO, &nb0);
        LI_WS2(setsockopt)(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&IoTimeoutMs, sizeof(IoTimeoutMs));
        LI_WS2(setsockopt)(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&IoTimeoutMs, sizeof(IoTimeoutMs));
        out = s; break;
    }
    LI_WS2(freeaddrinfo)(res);
    return out;
}

void
NetClose(SOCKET s)
{
    if (s == INVALID_SOCKET) return;
    LI_WS2(shutdown)(s, SD_BOTH);
    LI_WS2(closesocket)(s);
}

bool
NetHandshake(SOCKET s, UPD_SESSION_KEYS* Keys)
{
    BYTE clientNonce[16];
    if (!SecureRandom(clientNonce, 16))
        return false;

    BYTE hdr[12];
    if (!RecvAll(s, hdr, 12)) return false;

    BYTE kind = 0; UINT32 payloadLen = 0;
    if (!ReadFrameHeader(hdr, &kind, &payloadLen)) return false;
    if (kind != UPD_FRAME_HANDSHAKE || payloadLen != 2 + UPD_HELLO_LEN) return false;

    BYTE hello[2 + UPD_HELLO_LEN];
    if (!RecvAll(s, hello, payloadLen)) return false;
    if (ReadU16BE(hello) != UPD_OP_SERVER_HELLO) return false;

    BYTE serverNonce[16];
    memcpy(serverNonce, hello + 2, 16);
    bool ok = DeriveKeys(clientNonce, serverNonce, Keys);
    SecureZeroMemory(serverNonce, sizeof(serverNonce));
    if (!ok) { SecureZeroMemory(clientNonce, sizeof(clientNonce)); return false; }

    BYTE chOut[2 + UPD_HELLO_LEN];
    chOut[0] = (BYTE)(UPD_OP_CLIENT_HELLO >> 8);
    chOut[1] = (BYTE) UPD_OP_CLIENT_HELLO;
    memcpy(chOut + 2, clientNonce, 16);
    chOut[18] = (BYTE)(UPD_PROTO_VERSION >> 8);
    chOut[19] = (BYTE) UPD_PROTO_VERSION;
    SecureZeroMemory(clientNonce, sizeof(clientNonce));

    BYTE chHdr[12];
    WriteFrameHeader(chHdr, UPD_FRAME_HANDSHAKE, sizeof(chOut));
    return SendAll(s, chHdr, 12) && SendAll(s, chOut, sizeof(chOut));
}

static bool
ComputeMac(const BYTE macKey[32],
           const BYTE hdr[12], const BYTE* nonce, const BYTE* iv,
           const BYTE* ct, ULONG ctLen,
           BYTE out[32])
{
    BCRYPT_ALG_HANDLE  alg = NULL;
    BCRYPT_HASH_HANDLE h   = NULL;

    if (LI_BCRYPT(BCryptOpenAlgorithmProvider)(&alg, pxenc(L"SHA256"), NULL,
            BCRYPT_ALG_HANDLE_HMAC_FLAG) != STATUS_SUCCESS)
        return false;

    NTSTATUS s = LI_BCRYPT(BCryptCreateHash)(alg, &h, NULL, 0, (PUCHAR)macKey, 32, 0);
    if (s == STATUS_SUCCESS) {
        s = LI_BCRYPT(BCryptHashData)(h, (PUCHAR)hdr,   12,    0);
        if (s == STATUS_SUCCESS)
            s = LI_BCRYPT(BCryptHashData)(h, (PUCHAR)nonce, 16,    0);
        if (s == STATUS_SUCCESS)
            s = LI_BCRYPT(BCryptHashData)(h, (PUCHAR)iv,    16,    0);
        if (s == STATUS_SUCCESS)
            s = LI_BCRYPT(BCryptHashData)(h, (PUCHAR)ct,    ctLen, 0);
        if (s == STATUS_SUCCESS)
            s = LI_BCRYPT(BCryptFinishHash)(h, out, 32, 0);
        LI_BCRYPT(BCryptDestroyHash)(h);
    }
    LI_BCRYPT(BCryptCloseAlgorithmProvider)(alg, 0);
    return s == STATUS_SUCCESS;
}

bool
NetRecvEncrypted(SOCKET s, const UPD_SESSION_KEYS* Keys,
                 UINT16* Opcode, BYTE* Body, ULONG* BodyLen, int* Stage)
{
    auto set = [&](int v) { if (Stage) *Stage = v; };

    set(UPD_RECV_HDR);
    BYTE hdr[12];
    if (!RecvAll(s, hdr, 12)) return false;

    BYTE kind = 0; UINT32 payloadLen = 0;
    set(UPD_RECV_BAD_MAGIC);
    if (!ReadFrameHeader(hdr, &kind, &payloadLen)) return false;

    set(UPD_RECV_BAD_KIND);
    if (kind != UPD_FRAME_ENCRYPTED) return false;

    set(UPD_RECV_LEN_MIN);
    if (payloadLen < UPD_NONCE_LEN + UPD_IV_LEN + UPD_MAC_LEN + 16) return false;

    set(UPD_RECV_LEN_MAX);
    if (payloadLen > UPD_MAX_PACKET_BYTES) return false;

    set(UPD_RECV_ALLOC);
    BYTE* payload = (BYTE*)LI_KERNEL(HeapAlloc)(LI_KERNEL(GetProcessHeap)(), 0, payloadLen);
    if (!payload) return false;

    set(UPD_RECV_PAYLOAD);
    if (!RecvAll(s, payload, payloadLen)) {
        LI_KERNEL(HeapFree)(LI_KERNEL(GetProcessHeap)(), 0, payload); return false;
    }

    BYTE nonce[UPD_NONCE_LEN];
    memcpy(nonce, payload, UPD_NONCE_LEN);
    const BYTE* iv  = payload + UPD_NONCE_LEN;
    ULONG       ctLen = payloadLen - UPD_NONCE_LEN - UPD_IV_LEN - UPD_MAC_LEN;
    const BYTE* ct  = payload + UPD_NONCE_LEN + UPD_IV_LEN;
    const BYTE* mac = payload + payloadLen - UPD_MAC_LEN;

    set(UPD_RECV_HMAC);
    BYTE expect[32];
    if (!ComputeMac(Keys->Mac, hdr, nonce, iv, ct, ctLen, expect)) {
        LI_KERNEL(HeapFree)(LI_KERNEL(GetProcessHeap)(), 0, payload); return false;
    }

    set(UPD_RECV_MAC_DIFF);
    ULONG diff = 0;
    for (int i = 0; i < 32; i++) diff |= (ULONG)(expect[i] ^ mac[i]);
    if (diff) { LI_KERNEL(HeapFree)(LI_KERNEL(GetProcessHeap)(), 0, payload); return false; }

    set(UPD_RECV_AES);
    BYTE* pt = (BYTE*)LI_KERNEL(HeapAlloc)(LI_KERNEL(GetProcessHeap)(), 0, ctLen + 16);
    if (!pt) { LI_KERNEL(HeapFree)(LI_KERNEL(GetProcessHeap)(), 0, payload); return false; }

    ULONG ptLen = ctLen + 16;
    BYTE ivCopy[16]; memcpy(ivCopy, iv, 16);
    if (!AesCbcDecrypt(Keys->Enc, ivCopy, ct, ctLen, pt, &ptLen)) {
        LI_KERNEL(HeapFree)(LI_KERNEL(GetProcessHeap)(), 0, pt);
        LI_KERNEL(HeapFree)(LI_KERNEL(GetProcessHeap)(), 0, payload); return false;
    }
    LI_KERNEL(HeapFree)(LI_KERNEL(GetProcessHeap)(), 0, payload);

    set(UPD_RECV_PT_MIN);
    if (ptLen < UPD_ENC_INNER_HDR) { LI_KERNEL(HeapFree)(LI_KERNEL(GetProcessHeap)(), 0, pt); return false; }

    XorObf(pt, ptLen, Keys->Obf, nonce);

    UINT16 op   = ReadU16BE(pt + 8);
    UINT32 bLen = ReadU32BE(pt + 10);

    set(UPD_RECV_PT_BODY);
    if (ptLen < (ULONG)UPD_ENC_INNER_HDR + bLen) { LI_KERNEL(HeapFree)(LI_KERNEL(GetProcessHeap)(), 0, pt); return false; }

    set(UPD_RECV_BUF_SMALL);
    if (bLen > *BodyLen) { LI_KERNEL(HeapFree)(LI_KERNEL(GetProcessHeap)(), 0, pt); return false; }

    set(UPD_RECV_OK);
    *Opcode  = op;
    *BodyLen = bLen;
    memcpy(Body, pt + UPD_ENC_INNER_HDR, bLen);
    SecureZeroMemory(pt, ptLen);
    LI_KERNEL(HeapFree)(LI_KERNEL(GetProcessHeap)(), 0, pt);
    return true;
}
