import crypto from "crypto";
import { config } from "@/lib/core/config";

const SECRET = config.session_secret;

const MASTER = crypto.scryptSync(SECRET, "phoenixac.api.master.v1", 32);

export function userKey(userId: string): Buffer {
  return crypto.createHmac("sha256", MASTER).update(userId).digest();
}

export function userKeyB64(userId: string): string {
  return userKey(userId).toString("base64");
}

const SEAL_VERSION = 1;

export function sealForUser(userId: string, data: unknown): string {
  const key = userKey(userId);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const pt = Buffer.from(JSON.stringify(data), "utf8");
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([
    Buffer.from([SEAL_VERSION]),
    iv,
    ct,
    tag,
  ]).toString("base64");
}
