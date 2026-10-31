import { NextRequest, NextResponse } from "next/server";
import { readFile } from "fs/promises";
import { rateLimit, clientIp, NO_STORE } from "@/lib/security/security";
import { config } from "@/lib/core/config";

export const runtime = "nodejs";

const json = (data: unknown, status = 200) =>
  NextResponse.json(data, { status, headers: NO_STORE });

export async function GET(req: NextRequest) {
  if (!rateLimit(`launcher-rt:${clientIp(req)}`, 5, 60_000))
    return json({ ok: false, error: "too many requests" }, 429);

  const expectedKey = config.phoenix_api_key;
  if (expectedKey && req.headers.get("x-api-key") !== expectedKey)
    return json({ ok: false, error: "forbidden" }, 403);

  const runtimeFile = config.launcher_runtime_file;

  let buf: Buffer;
  try {
    buf = await readFile(runtimeFile);
  } catch {
    return json({ ok: false, error: "file not available" }, 503);
  }

  return new NextResponse(new Uint8Array(buf), {
    status: 200,
    headers: {
      "Content-Type": "application/octet-stream",
      "Content-Disposition": `attachment; filename="rt.bin"`,
      "Content-Length": String(buf.length),
      ...NO_STORE,
    },
  });
}
