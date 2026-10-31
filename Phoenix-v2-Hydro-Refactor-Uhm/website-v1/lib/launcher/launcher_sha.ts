import { stat, readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { config } from "@/lib/core/config";

type Cached = { mtimeMs: number; sha: string };
let cache: Cached | null = null;

function launcherPath(): string {
  return config.launcher_file;
}

export async function getLauncherSha(): Promise<string | null> {
  const file = launcherPath();
  try {
    const st = await stat(file);
    if (cache && cache.mtimeMs === st.mtimeMs) return cache.sha;
    const buf = await readFile(file);
    const sha = createHash("sha256").update(buf).digest("hex");
    cache = { mtimeMs: st.mtimeMs, sha };
    return sha;
  } catch {
    return null;
  }
}

export function shaEnforce(): boolean {
  return config.phoenix_launcher_sha_enforce;
}
