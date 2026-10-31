export const WIRE_MAGIC = 0x50414331;

export const WIRE_VERSION = 0x0001;

export const enum FrameKind {
    Handshake = 0x01,
    Encrypted = 0x02,
}

export const enum Opcode {
    ClientHello = 0x0001,
    ServerHello = 0x0002,
    Authenticate = 0x0010,
    AuthResult = 0x0011,
    EnrollmentQuery = 0x0012,
    EnrollmentResult = 0x0013,
    HeartbeatPing = 0x0020,
    HeartbeatPong = 0x0021,
    Detection = 0x0100,
    DetectionAck = 0x0101,
    ScreenshotRequest = 0x0110,
    ScreenshotResponse = 0x0111,
    ScreenshotChunk = 0x0112,
    SysInfoRequest = 0x0120,
    SysInfoResponse = 0x0121,
    PciTreeRequest = 0x0122,
    PciTreeResponse = 0x0123,
    MinidumpsRequest = 0x0124,
    MinidumpsResponse = 0x0125,
    DumpFileRequest = 0x0126,
    DumpFileChunk = 0x0127,
    DumpFileError = 0x0128,
    AltAccounts = 0x0130,
    AltAccountsAck = 0x0131,
    ProcListReq = 0x0158,
    ProcListRes = 0x0159,
    ProcModulesReq = 0x015a,
    ProcModulesRes = 0x015b,
    ProcErr = 0x015c,
    ProcStringsReq = 0x015d,
    ProcStringsRes = 0x015e,
    ProcWindowsReq = 0x015f,
    ProcWindowsRes = 0x0160,
    ScanStartReq = 0x0161,
    ScanProgress = 0x0162,
    ScanHit = 0x0163,
    ScanDone = 0x0164,
    ScanCancelReq = 0x0165,
    ScanErr = 0x0166,
    ServerShutdown = 0x0f00,
    ClientShutdown = 0x0f01,
    Kick = 0x0f02,
    Error = 0x0fff,
}

export const enum AuthStatus {
    Ok = 0x00,
    NotEnrolled = 0x01,
    Banned = 0x02,
    Suspended = 0x03,
    BadHardware = 0x04,
    BadVersion = 0x05,
    WrongMode = 0x06,
    ServerError = 0xff,
}

export const enum ErrorCode {
    BadFrame = 0x01,
    BadMac = 0x02,
    BadReplay = 0x03,
    BadOpcode = 0x04,
    RateLimited = 0x05,
    HandshakeState = 0x06,
    Internal = 0xff,
}
