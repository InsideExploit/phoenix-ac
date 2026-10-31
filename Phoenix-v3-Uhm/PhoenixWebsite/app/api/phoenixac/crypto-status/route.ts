import { NextRequest, NextResponse } from "next/server";
import { rateLimit, clientIp, NO_STORE } from "@/lib/security/security";
import { isCryptoConfigured, tryDecrypt } from "@/lib/crypto/crypto";
import { config } from "@/lib/core/config";

export const runtime = "nodejs";

export async function GET(req: NextRequest) {
  if (!rateLimit(`crypto-status:${clientIp(req)}`, 30, 60_000))
    return NextResponse.json({ ok: false, error: "too many requests" },
                             { status: 429, headers: NO_STORE });

  const expectedKey = config.phoenix_api_key;
  if (expectedKey && req.headers.get("x-api-key") !== expectedKey)
    return NextResponse.json({ ok: false, error: "forbidden" },
                             { status: 403, headers: NO_STORE });

  const hex = config.phoenix_crypto_key;
  const cryptoConfigured = isCryptoConfigured();
  const keyLen = hex.length;
  const keyHexValid = /^[0-9a-fA-F]{64}$/.test(hex);
  const keyHash = hex
    ? Array.from(hex).reduce((a, c) => (a * 31 + c.charCodeAt(0)) >>> 0, 0)
    : 0;

  return NextResponse.json(
    { ok: true, cryptoConfigured, keyLen, keyHexValid, keyHash },
    { status: 200, headers: NO_STORE },
  );
}

export async function POST(req: NextRequest) {
  if (!rateLimit(`crypto-status-post:${clientIp(req)}`, 30, 60_000))
    return NextResponse.json({ ok: false, error: "too many requests" },
                             { status: 429, headers: NO_STORE });

  const expectedKey = config.phoenix_api_key;
  if (expectedKey && req.headers.get("x-api-key") !== expectedKey)
    return NextResponse.json({ ok: false, error: "forbidden" },
                             { status: 403, headers: NO_STORE });

  const raw = await req.text();
  const encBase64Len = raw.length;
  const dec = tryDecrypt(raw);

  return NextResponse.json(
    {
      ok: true,
      encBase64Len,
      decryptSucceeded: dec !== null,
      decryptedLen: dec?.length ?? 0,
      decryptedPreview: dec ? dec.slice(0, 80) : null,
    },
    { status: 200, headers: NO_STORE },
  );
}
