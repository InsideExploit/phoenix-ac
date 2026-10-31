#pragma once
#include <windows.h>
#include <winsock2.h>

#define UPD_PROTO_VERSION 0x0001

#define UPD_FRAME_HANDSHAKE 0x01
#define UPD_FRAME_ENCRYPTED 0x02

#define UPD_FRAME_HDR_LEN   12
#define UPD_ENC_INNER_HDR   14
#define UPD_HELLO_LEN       18

#define UPD_NONCE_LEN 16
#define UPD_IV_LEN    16
#define UPD_MAC_LEN   32
#define UPD_KEY_LEN   32

#define UPD_OP_CLIENT_HELLO   0x0001
#define UPD_OP_SERVER_HELLO   0x0002
#define UPD_OP_MANIFEST       0x0300
#define UPD_OP_CHUNK_AGENT    0x0301
#define UPD_OP_CHUNK_DRIVER   0x0302
#define UPD_OP_END            0x0303
#define UPD_OP_ERROR          0x03FF

#define UPD_MAX_PACKET_BYTES  (128 * 1024)

struct UPD_SESSION_KEYS {
    BYTE Enc [UPD_KEY_LEN];
    BYTE Mac [UPD_KEY_LEN];
    BYTE Obf [UPD_KEY_LEN];
    BYTE Slot[UPD_KEY_LEN];
};

bool   NetInit();
void   NetShutdown();
SOCKET NetDial(const char* Host, const char* Port, DWORD ConnectTimeoutMs, DWORD IoTimeoutMs);
void   NetClose(SOCKET s);
bool   NetHandshake(SOCKET s, UPD_SESSION_KEYS* Keys);

enum {
    UPD_RECV_OK         = 0,
    UPD_RECV_HDR        = 1,
    UPD_RECV_BAD_MAGIC  = 2,
    UPD_RECV_BAD_KIND   = 3,
    UPD_RECV_LEN_MIN    = 4,
    UPD_RECV_LEN_MAX    = 5,
    UPD_RECV_ALLOC      = 6,
    UPD_RECV_PAYLOAD    = 7,
    UPD_RECV_HMAC       = 8,
    UPD_RECV_MAC_DIFF   = 9,
    UPD_RECV_AES        = 10,
    UPD_RECV_PT_MIN     = 11,
    UPD_RECV_PT_BODY    = 12,
    UPD_RECV_BUF_SMALL  = 13,
};

bool NetRecvEncrypted(SOCKET s, const UPD_SESSION_KEYS* Keys,
                      UINT16* Opcode, BYTE* Body, ULONG* BodyLen, int* Stage);
