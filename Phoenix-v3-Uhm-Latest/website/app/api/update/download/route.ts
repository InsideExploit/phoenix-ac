import { NextRequest, NextResponse } from 'next/server';

import { readFile } from 'fs/promises';

import { config } from '@/lib/core/config';
import { clientIp, NO_STORE, rateLimit } from '@/lib/security/security';

export const runtime = 'nodejs';
const json = (data: unknown, status = 200) =>
  NextResponse.json(data, { status, headers: NO_STORE });

export async function GET(req: NextRequest) {
  if (!rateLimit(`update-dl:${clientIp(req)}`, 5, 60000))
    return json({ ok: false, error: 'too many requests' }, 429);
  const expectedKey = config.phoenix_api_key;
  if (expectedKey && req.headers.get('x-api-key') !== expectedKey)
    return json({ ok: false, error: 'forbidden' }, 403);
  const updateFile = config.update_file || 'private/AutoUpdate.exe';
  let buf: Buffer;
  try {
    buf = await readFile(updateFile);
  } catch {
    return json({ ok: false, error: 'file not available' }, 503);
  }
  return new NextResponse(new Uint8Array(buf), {
    status: 200,
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Disposition': `attachment; filename="AutoUpdate.exe"`,
      'Content-Length': String(buf.length),
      ...NO_STORE,
    },
  });
}
