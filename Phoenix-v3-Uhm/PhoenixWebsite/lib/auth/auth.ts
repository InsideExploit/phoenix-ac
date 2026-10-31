import { cookies } from "next/headers";
import {
  verify,
  isAllowed,
  SESSION_COOKIE,
  type SessionUser,
} from "./session";

export async function getSessionUser(): Promise<SessionUser | null> {
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  const session = verify(token);
  if (!session) return null;
  return (await isAllowed(session.id)) ? session : null;
}
