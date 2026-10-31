import { NextRequest, NextResponse } from 'next/server';

import crypto from 'crypto';

import { STATE_COOKIE } from '@/lib/auth/session';
import { config } from '@/lib/core/config';
import { discordRedirectUri, publicUrl } from '@/lib/core/url';
import { clientIp, rateLimit } from '@/lib/security/security';

export const runtime = 'nodejs';

export function GET(req: NextRequest) {
  if (!rateLimit(`login:${clientIp(req)}`, 30, 60000)) {
    return NextResponse.redirect(publicUrl(req, '/dashboard?error=rate'));
  }
  const clientId = config.discord_client_id;
  if (!clientId) {
    return NextResponse.redirect(publicUrl(req, '/dashboard?error=config'));
  }
  const redirectUri = discordRedirectUri();
  const state = crypto.randomBytes(16).toString('hex');
  const authorize = new URL('https://discord.com/api/oauth2/authorize');
  authorize.searchParams.set('client_id', clientId);
  authorize.searchParams.set('redirect_uri', redirectUri);
  authorize.searchParams.set('response_type', 'code');
  authorize.searchParams.set('scope', 'identify email');
  authorize.searchParams.set('state', state);
  authorize.searchParams.set('prompt', 'consent');
  const res = NextResponse.redirect(authorize.toString());
  res.cookies.set(STATE_COOKIE, state, {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 600,
    secure: process.env.NODE_ENV === 'production',
  });
  return res;
}
