import type { NextRequest } from "next/server";
import { config } from "@/lib/core/config";

export function publicOrigin(_req?: NextRequest): string {
  return config.site_url.replace(/\/+$/, "");
}

export function publicUrl(_req: NextRequest, path: string): URL {
  return new URL(path, publicOrigin() + "/");
}

export function discordRedirectUri(): string {
  return `${publicOrigin()}/api/auth/callback/discord`;
}
