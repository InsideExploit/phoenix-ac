export const WIRE_MAGIC   = 0x50414331;
export const WIRE_VERSION = 0x0001;

export const enum FrameKind {
    Handshake = 0x01,
    Encrypted = 0x02,
}

export const enum Opcode {
    ClientHello        = 0x0001,
    ServerHello        = 0x0002,

    Authenticate       = 0x0010,
    AuthResult         = 0x0011,

    EnrollmentQuery    = 0x0012,
    EnrollmentResult   = 0x0013,

    HeartbeatPing      = 0x0020,
    HeartbeatPong      = 0x0021,

    Detection          = 0x0100,
    DetectionAck       = 0x0101,

    ScreenshotRequest  = 0x0110,
    ScreenshotResponse = 0x0111,
    ScreenshotChunk    = 0x0112,
    SysInfoRequest     = 0x0120,
    SysInfoResponse    = 0x0121,
    PciTreeRequest     = 0x0122,
    PciTreeResponse    = 0x0123,
    MinidumpsRequest   = 0x0124,
    MinidumpsResponse  = 0x0125,
    DumpFileRequest    = 0x0126,
    DumpFileChunk      = 0x0127,
    DumpFileError      = 0x0128,

    AltAccounts        = 0x0130,
    AltAccountsAck     = 0x0131,

    ServerShutdown     = 0x0F00,
    ClientShutdown     = 0x0F01,
    Kick               = 0x0F02,
    Error              = 0x0FFF,
}

export const enum AuthStatus {
    Ok           = 0x00,
    NotEnrolled  = 0x01,
    Banned       = 0x02,
    Suspended    = 0x03,
    BadHardware  = 0x04,
    BadVersion   = 0x05,
    ServerError  = 0xFF,
}

export const enum ErrorCode {
    BadFrame        = 0x01,
    BadMac          = 0x02,
    BadReplay       = 0x03,
    BadOpcode       = 0x04,
    RateLimited     = 0x05,
    HandshakeState  = 0x06,
    Internal        = 0xFF,
}
