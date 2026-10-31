// Schema ownership moved to the backend service (`backend/src/db/migrate.ts`).
// The website no longer bootstraps or ALTERs its own database — the backend runs
// the canonical migrations on startup. This file exists only to satisfy any
// remaining imports and is a no-op.

export async function ensure_database(): Promise<void> {
  return;
}
