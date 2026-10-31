import { NextResponse } from "next/server";
import { NO_STORE } from "@/lib/security/security";

export const runtime = "nodejs";

const gone = () =>
  NextResponse.json(
    { ok: false, error: "endpoint deprecato - usare /api/phoenixac/event" },
    { status: 410, headers: NO_STORE },
  );

export async function POST() { return gone(); }
export async function GET()  { return gone(); }
