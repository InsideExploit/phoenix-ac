export type Player = {
  steam: string;
  discord: string;
  banned: boolean;
  suspended: boolean;
  online: boolean;
  lastSeen: string | null;
  addedBy: string | null;
  createdAt: string | null;
  lastEditBy: string | null;
  lastEditAt: string | null;
  hardwareId: string | null;
  banReason: string | null;
  banCategory: string | null;
  banReasonPublic: boolean;
  bannedBy: string | null;
  bannedAt: string | null;
  suspendReason: string | null;
  suspendedBy: string | null;
  suspendedAt: string | null;
  steamName: string | null;
  discordName: string | null;
  steamAvatar: string | null;
  discordAvatar: string | null;
  agentMode: 'usermode' | 'kernel';
  allowNoSecureBoot: boolean;
  allowNoHvci: boolean;
};

export const BAN_CATEGORIES = [
  { value: 'cheating', label: 'Cheating' },
  { value: 'bug-abuse', label: 'Bug abuse' },
  { value: 'toxicity', label: 'Toxicity' },
  { value: 'alt-account', label: 'Alt account' },
] as const;

export type BanCategoryValue = (typeof BAN_CATEGORIES)[number]['value'];

export function categoryLabel(value: string | null | undefined): string {
  const hit = BAN_CATEGORIES.find((c) => c.value === value);
  return hit ? hit.label : 'Banned';
}

export type View = 'players' | 'pins' | 'stats' | 'evasion' | 'detections';

export type Detection = {
  id: string;
  type: string;
  reason: string | null;
  offendingPath: string | null;
  steamHex: string;
  clientIp: string | null;
  hardwareId: string | null;
  sessionId: string | null;
  screenshotPath: string | null;
  extras: Record<string, unknown> | null;
  createdAt: string;
};

export type Pin = {
  code: string;
  used: boolean;
  createdBy: string;
  createdAt: string;
  expiresAt: string | null;
  expired: boolean;
};

export type StatRow = {
  steamHex: string;
  discordId: string | null;
  license: string | null;
  token: string | null;
  name: string | null;
  kills: number;
  deaths: number;
  kd: number;
  currentStreak: number;
  maxStreak: number;
  lastSeen: string | null;
};

export type EvasionFlag = {
  id: number;
  primaryHex: string;
  secondaryHex: string;
  fpType: string;
  fpValue: string;
  primaryName: string | null;
  secondaryName: string | null;
  clientIp: string | null;
  createdAt: string;
};

export type LookupResult = {
  steamName?: string;
  steamAvatar?: string;
  discordName?: string;
  discordAvatar?: string;
};

export type PlayerFilter = 'all' | 'online' | 'offline' | 'suspended' | 'banned';

export type PinFilter = 'all' | 'available' | 'used' | 'expired';

export type MenuState = {
  player: Player;
  top: number;
  right: number;
} | null;

export type ToastPayload = {
  message: string;
  duration?: number;
} | null;

export type ShotViewerState = {
  steam: string;
  state: 'loading' | 'ready' | 'error';
  path?: string;
  error?: string;
  method?: 'nvidia' | 'gdi' | 'auto';
  usedMethod?: 'nvidia' | 'gdi' | 'auto';
} | null;

export type BulkShotEntry = {
  steam: string;
  displayName?: string;
  avatar?: string;
  state: 'loading' | 'ready' | 'error';
  path?: string;
  error?: string;
};

export type BulkShotState = {
  entries: Record<string, BulkShotEntry>;
  total: number;
  done: number;
  method: 'nvidia' | 'gdi' | 'auto';
} | null;

export type ProcessBrowserState = {
  steam: string;
  displayName?: string;
} | null;

export type ScansState = {
  steam: string;
  displayName?: string;
} | null;

export const PAGE_SIZE = 15;

export const PLAYERS_API = '/api/players?all=1';
