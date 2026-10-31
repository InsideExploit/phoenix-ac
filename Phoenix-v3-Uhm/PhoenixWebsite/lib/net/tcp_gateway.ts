import net from "node:net";
import { config } from "@/lib/core/config";
import { rateLimit } from "@/lib/security/security";
import {
  WireOpcode,
  buildHeader,
  openBody,
  parseHeader,
  sealBody,
} from "@/lib/net/wire";
import {
  handleAuthCheck,
  handleEvent,
  handleUpdateCheck,
  handleUpdateDownload,
} from "@/lib/net/wire_handlers";

const FRAME_HEADER_SIZE = 20;

function createReader(socket: net.Socket) {
  let buffer = Buffer.alloc(0);
  let waiters: Array<{ need: number; resolve: (buf: Buffer) => void; reject: (e: Error) => void }> = [];

  const flush = () => {
    while (waiters.length && buffer.length >= waiters[0]!.need) {
      const w = waiters.shift()!;
      const out = buffer.subarray(0, w.need);
      buffer = buffer.subarray(w.need);
      w.resolve(Buffer.from(out));
    }
  };

  socket.on("data", (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    flush();
  });

  socket.on("error", (err) => {
    for (const w of waiters) w.reject(err);
    waiters = [];
  });

  socket.on("close", () => {
    for (const w of waiters) w.reject(new Error("socket closed"));
    waiters = [];
  });

  const readExact = (need: number): Promise<Buffer> =>
    new Promise((resolve, reject) => {
      if (buffer.length >= need) {
        const out = buffer.subarray(0, need);
        buffer = buffer.subarray(need);
        resolve(Buffer.from(out));
        return;
      }
      waiters.push({ need, resolve, reject });
    });

  return { readExact };
}

async function dispatch(
  opcode: number,
  inner: Buffer,
  ip: string,
): Promise<{ rspOpcode: number; inner: Buffer; rawTail?: Buffer }> {
  switch (opcode) {
    case WireOpcode.AuthCheckReq: {
      const rsp = await handleAuthCheck(inner, ip);
      return { rspOpcode: WireOpcode.AuthCheckRsp, inner: rsp };
    }
    case WireOpcode.EventReq: {
      const rsp = await handleEvent(inner, ip);
      return { rspOpcode: WireOpcode.EventRsp, inner: rsp };
    }
    case WireOpcode.UpdateCheckReq: {
      const rsp = await handleUpdateCheck(inner);
      return { rspOpcode: WireOpcode.UpdateCheckRsp, inner: rsp };
    }
    case WireOpcode.UpdateDlReq: {
      const dl = await handleUpdateDownload();
      return { rspOpcode: WireOpcode.UpdateDlRsp, inner: dl.header, rawTail: dl.file ?? undefined };
    }
    default:
      return { rspOpcode: opcode | 0x0001, inner: Buffer.from([0]) };
  }
}

async function handleConnection(socket: net.Socket) {
  const ip = socket.remoteAddress ?? "0.0.0.0";
  const reader = createReader(socket);

  if (!rateLimit(`wire:${ip}`, 300, 60_000)) {
    console.warn(`[wire] rate-limited ${ip}`);
    socket.destroy();
    return;
  }

  try {
    const hdrBuf = await reader.readExact(FRAME_HEADER_SIZE);
    const hdr = parseHeader(hdrBuf);

    if (hdr.magic !== 0x31584850 || hdr.version !== 1) {
      console.warn(`[wire] bad header from ${ip} magic=${hdr.magic.toString(16)} ver=${hdr.version}`);
      return;
    }

    if (hdr.bodyLen > 128 << 20) {
      console.warn(`[wire] body too large from ${ip}: ${hdr.bodyLen}`);
      return;
    }

    const body = hdr.bodyLen ? await reader.readExact(hdr.bodyLen) : Buffer.alloc(0);
    const inner = openBody(hdr.opcode, hdr.seq, body);
    const result = await dispatch(hdr.opcode, inner, ip);

    const sealed = sealBody(result.rspOpcode, hdr.seq, result.inner);
    const outHdr = buildHeader(result.rspOpcode, hdr.seq, sealed.length);
    socket.write(Buffer.concat([outHdr, sealed]));

    if (result.rawTail?.length)
      socket.write(result.rawTail);

    console.log(`[wire] ${ip} opcode=0x${hdr.opcode.toString(16)} seq=${hdr.seq} ok`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.warn(`[wire] ${ip} failed: ${msg}`);
  } finally {
    socket.end();
  }
}

export function startTcpGateway() {
  type G = typeof globalThis & { __phoenixWireServer?: net.Server };
  const g = globalThis as G;
  if (g.__phoenixWireServer?.listening) return;

  g.__phoenixWireServer?.close();

  const port = config.phoenix_tcp_port;
  const server = net.createServer((socket) => {
    void handleConnection(socket);
  });

  g.__phoenixWireServer = server;

  server.listen(port, config.bind_host, () => {
    console.log(`[wire] tcp gateway listening on ${config.bind_host}:${port}`);
  });

  server.on("error", (err) => {
    console.error("[wire] tcp gateway error", err);
  });
}
