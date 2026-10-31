import { NextRequest, NextResponse } from 'next/server';

import { buildAuthorizeUrl } from '@/lib/auth/steam';
import { clientIp, rateLimit } from '@/lib/security/security';

export const runtime = 'nodejs';

export function GET(req: NextRequest) {
  if (!rateLimit(`steam-login:${clientIp(req)}`, 30, 60000)) {
    return NextResponse.redirect(new URL('/?steam=rate', req.nextUrl.origin));
  }
  return NextResponse.redirect(buildAuthorizeUrl());
}
