#pragma once
#include <windows.h>
#include <winsock2.h>

#define KG_PROTO_VERSION 0x0001

#define KG_FRAME_HANDSHAKE 0x01
#define KG_FRAME_ENCRYPTED 0x02

#define KG_FRAME_HDR_LEN   12
#define KG_ENC_INNER_HDR   14
#define KG_HELLO_LEN       18

#define KG_NONCE_LEN 16
#define KG_IV_LEN    16
#define KG_MAC_LEN   32
#define KG_KEY_LEN   32

#define KG_OP_CLIENT_HELLO         0x0001
#define KG_OP_SERVER_HELLO         0x0002
#define KG_OP_AUTHENTICATE         0x0010
#define KG_OP_AUTH_RESULT          0x0011
#define KG_OP_ENROLLMENT_QUERY     0x0012
#define KG_OP_ENROLLMENT_RESULT    0x0013
#define KG_OP_HEARTBEAT_PING       0x0020
#define KG_OP_HEARTBEAT_PONG       0x0021
#define KG_OP_SCREENSHOT_REQUEST   0x0110
#define KG_OP_SCREENSHOT_RESPONSE  0x0111
#define KG_OP_SCREENSHOT_CHUNK     0x0112
#define KG_OP_SYSINFO_REQUEST      0x0120
#define KG_OP_SYSINFO_RESPONSE     0x0121
#define KG_OP_PCITREE_REQUEST      0x0122
#define KG_OP_PCITREE_RESPONSE     0x0123
#define KG_OP_MINIDUMPS_REQUEST    0x0124
#define KG_OP_MINIDUMPS_RESPONSE   0x0125
#define KG_OP_DUMPFILE_REQUEST     0x0126
#define KG_OP_DUMPFILE_CHUNK       0x0127
#define KG_OP_DUMPFILE_ERROR       0x0128
#define KG_OP_CLIENT_SHUTDOWN      0x0F01
#define KG_OP_KICK                 0x0F02

typedef struct _KG_SESSION_KEYS {
    BYTE Enc[KG_KEY_LEN];
    BYTE Mac[KG_KEY_LEN];
    BYTE Obf[KG_KEY_LEN];
    BYTE Slot[KG_KEY_LEN];
} KG_SESSION_KEYS;

bool
NetInit(
);

void
NetShutdown(
);

SOCKET
NetDial(
    const char* Host,
    const char* Port,
    DWORD       ConnectTimeoutMs,
    DWORD       IoTimeoutMs
);

void
NetClose(
    SOCKET s
);

bool
NetHandshake(
    SOCKET           s,
    KG_SESSION_KEYS* Keys
);

bool
NetSendEncrypted(
    SOCKET                 s,
    const KG_SESSION_KEYS* Keys,
    UINT16                 Opcode,
    const BYTE*            Body,
    ULONG                  BodyLen
);

bool
NetRecvEncrypted(
    SOCKET                 s,
    const KG_SESSION_KEYS* Keys,
    UINT16*                Opcode,
    BYTE*                  Body,
    ULONG*                 BodyLen
);
