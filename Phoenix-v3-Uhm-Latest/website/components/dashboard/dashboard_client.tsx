'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';

import { ToastNotification } from '@/components/ui/toast-notification';

import { DashboardShell } from './dashboard_shell';
import './dashboard_theme.css';
import {
  MIN_LOAD,
  decryptSealed,
  fetchLookup,
  fetchPlayersDecrypted,
  mergeLookups,
  playersEqual,
  prefetchPlayerLookups,
  sleep,
} from './data';
import { AddPlayerDialog } from './dialogs/add_player_dialog';
import { AltViewerDialog } from './dialogs/alt_viewer_dialog';
import { BanDialog } from './dialogs/ban_dialog';
import { BulkMethodPromptDialog } from './dialogs/bulk_method_prompt_dialog';
import { BulkShotDialog } from './dialogs/bulk_shot_dialog';
import { ConfirmDialog, type ConfirmPayload } from './dialogs/confirm_dialog';
import { DetectionViewerDialog } from './dialogs/detection_viewer_dialog';
import { EditPlayerDialog } from './dialogs/edit_player_dialog';
import { MethodPromptDialog } from './dialogs/method_prompt_dialog';
import { PinDisplayDialog } from './dialogs/pin_display_dialog';
import { ProcessBrowserDialog } from './dialogs/process_browser_dialog';
import { ReasonPromptDialog, type ReasonPromptPayload } from './dialogs/reason_prompt_dialog';
import { ReasonViewerDialog } from './dialogs/reason_viewer_dialog';
import { ScansDialog } from './dialogs/scans_dialog';
import { ShotViewerDialog } from './dialogs/shot_viewer_dialog';
import { SuspendDialog } from './dialogs/suspend_dialog';
import { SysInfoDialog, type SysInfoState } from './dialogs/sysinfo_dialog';
import { ToolsDialog, type ToolsDialogState } from './dialogs/tools_dialog';
import { PlayerActionsMenu } from './players/player_actions_menu';
import type {
  BulkShotEntry,
  BulkShotState,
  Detection,
  EvasionFlag,
  LookupResult,
  MenuState,
  Pin,
  PinFilter,
  Player,
  PlayerFilter,
  ProcessBrowserState,
  ScansState,
  ShotViewerState,
  StatRow,
  ToastPayload,
  View,
} from './types';
import { PLAYERS_API } from './types';
import { DetectionsView } from './views/detections_view';
import { EvasionView } from './views/evasion_view';
import { PinsView } from './views/pins_view';
import { PlayersView } from './views/players_view';
import { StatsView } from './views/stats_view';

export default function DashboardClient({
  name,
  username,
  avatar,
  email,
  players: initialPlayers,
  apiKey,
  hasElevatedAccess = false,
}: {
  name: string;
  username: string;
  avatar: string;
  email: string | null;
  players: Player[];
  apiKey: string;
  hasElevatedAccess?: boolean;
}) {
  const [view, setView] = useState<View>('players');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [players, setPlayers] = useState<Player[]>(initialPlayers);
  const [playersLoading, setPlayersLoading] = useState(true);
  const [playersQuery, setPlayersQuery] = useState('');
  const [playersFilter, setPlayersFilter] = useState<PlayerFilter>('all');
  const [playersPage, setPlayersPage] = useState(0);
  const [pins, setPins] = useState<Pin[]>([]);
  const [pinsLoading, setPinsLoading] = useState(true);
  const [pinsQuery, setPinsQuery] = useState('');
  const [pinsFilter, setPinsFilter] = useState<PinFilter>('all');
  const [pinsPage, setPinsPage] = useState(0);
  const [pinCode, setPinCode] = useState<string | null>(null);
  const [stats, setStats] = useState<StatRow[]>([]);
  const [statsLoading, setStatsLoading] = useState(true);
  const [statsQuery, setStatsQuery] = useState('');
  const [statsPage, setStatsPage] = useState(0);
  const [evasion, setEvasion] = useState<EvasionFlag[]>([]);
  const [evasionLoading, setEvasionLoading] = useState(true);
  const [evasionQuery, setEvasionQuery] = useState('');
  const [evasionPage, setEvasionPage] = useState(0);
  const DETECTIONS_PAGE_SIZE = 30;
  const [detections, setDetections] = useState<Detection[]>([]);
  const [detectionsTotal, setDetectionsTotal] = useState(0);
  const [detectionTypes, setDetectionTypes] = useState<
    {
      value: string;
      count: number;
    }[]
  >([]);
  const [detectionsLoading, setDetectionsLoading] = useState(true);
  const [detectionsQuery, setDetectionsQuery] = useState('');
  const [detectionTypeFilter, setDetectionTypeFilter] = useState<string>('');
  const [detectionSteamFilter, setDetectionSteamFilter] = useState<string>('');
  const [detectionsPage, setDetectionsPage] = useState(0);
  const [detectionViewer, setDetectionViewer] = useState<Detection | null>(null);
  const [sysInfo, setSysInfo] = useState<SysInfoState>(null);
  const [tools, setTools] = useState<ToolsDialogState>(null);
  const [downloadingDump, setDownloadingDump] = useState<string | null>(null);
  const loadPciTree = useCallback(async (steam: string) => {
    setTools({ steam, tool: 'pci', state: 'loading' });
    try {
      const res = await fetch('/api/players/pci-tree', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ steam_hex: steam }),
      });
      const data = (await res.json().catch(() => null)) as {
        ok: boolean;
        tree?: unknown;
        error?: string;
      } | null;
      if (data?.ok && data.tree) {
        setTools({ steam, tool: 'pci', state: 'ready', data: data.tree as never });
      } else {
        setTools({ steam, tool: 'pci', state: 'error', error: data?.error ?? 'Unknown error' });
      }
    } catch (e) {
      setTools({ steam, tool: 'pci', state: 'error', error: (e as Error).message });
    }
  }, []);
  const downloadDump = useCallback(async (steam: string, name: string) => {
    setDownloadingDump(name);
    try {
      const res = await fetch('/api/players/dump-file', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ steam_hex: steam, name }),
      });
      if (!res.ok) {
        let msg = 'Download failed';
        try {
          const data = (await res.json()) as {
            error?: string;
          };
          if (data?.error) msg = data.error;
        } catch {}
        setToast({ message: msg });
        return;
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 4000);
    } catch (e) {
      setToast({ message: (e as Error).message });
    } finally {
      setDownloadingDump(null);
    }
  }, []);
  const loadMinidumps = useCallback(async (steam: string) => {
    setTools({ steam, tool: 'minidumps', state: 'loading' });
    try {
      const res = await fetch('/api/players/minidumps', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ steam_hex: steam }),
      });
      const data = (await res.json().catch(() => null)) as {
        ok: boolean;
        dumps?: unknown;
        error?: string;
      } | null;
      if (data?.ok && data.dumps) {
        setTools({ steam, tool: 'minidumps', state: 'ready', data: data.dumps as never });
      } else {
        setTools({
          steam,
          tool: 'minidumps',
          state: 'error',
          error: data?.error ?? 'Unknown error',
        });
      }
    } catch (e) {
      setTools({ steam, tool: 'minidumps', state: 'error', error: (e as Error).message });
    }
  }, []);
  const requestSystemInfo = useCallback(async (p: Player) => {
    setSysInfo({ state: 'loading', steam: p.steam });
    try {
      const res = await fetch('/api/players/system-info', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ steam_hex: p.steam }),
      });
      const data = (await res.json().catch(() => null)) as {
        ok: boolean;
        info?: unknown;
        error?: string;
      } | null;
      if (data?.ok && data.info) {
        setSysInfo({ state: 'ready', steam: p.steam, info: data.info as never });
      } else {
        setSysInfo({ state: 'error', steam: p.steam, error: data?.error ?? 'Unknown error' });
      }
    } catch (e) {
      setSysInfo({ state: 'error', steam: p.steam, error: (e as Error).message });
    }
  }, []);
  const [lookups, setLookups] = useState<Record<string, LookupResult>>({});
  const [busy, setBusy] = useState(false);
  const [toast, setToast] = useState<ToastPayload>(null);
  const [menu, setMenu] = useState<MenuState>(null);
  const [showAdd, setShowAdd] = useState(false);
  const [addForm, setAddForm] = useState<{
    steam: string;
    discord: string;
  }>({ steam: '', discord: '' });
  const [editPlayer, setEditPlayer] = useState<Player | null>(null);
  const [editForm, setEditForm] = useState({ discord: '' });
  const [confirm, setConfirm] = useState<ConfirmPayload>(null);
  const [reasonPrompt, setReasonPrompt] = useState<ReasonPromptPayload>(null);
  const [reasonText, setReasonText] = useState('');
  const [reasonBusy, setReasonBusy] = useState(false);
  const [methodPrompt, setMethodPrompt] = useState<Player | null>(null);
  const [shotViewer, setShotViewer] = useState<ShotViewerState>(null);
  const [procBrowser, setProcBrowser] = useState<ProcessBrowserState>(null);
  const [scans, setScans] = useState<ScansState>(null);
  const [bulkShot, setBulkShot] = useState<BulkShotState>(null);
  const [bulkMethodPrompt, setBulkMethodPrompt] = useState(false);
  const [banTarget, setBanTarget] = useState<Player | null>(null);
  const [banMode, setBanMode] = useState<'create' | 'edit'>('create');
  const [suspendTarget, setSuspendTarget] = useState<Player | null>(null);
  const [suspendMode, setSuspendMode] = useState<'create' | 'edit'>('create');
  const [reasonView, setReasonView] = useState<Player | null>(null);
  const [altsTarget, setAltsTarget] = useState<Player | null>(null);
  const [enforcementBusy, setEnforcementBusy] = useState(false);
  const flash = useCallback(
    (message: string, duration?: number) => setToast({ message, duration }),
    [],
  );
  useEffect(() => {
    setPlayersPage(0);
  }, [playersQuery, playersFilter]);
  useEffect(() => {
    setPinsPage(0);
  }, [pinsQuery, pinsFilter]);
  const filteredPlayers = useMemo(() => {
    const q = playersQuery.trim().toLowerCase();
    return players.filter((p) => {
      if (playersFilter === 'online' && !(p.online && !p.banned && !p.suspended)) return false;
      if (playersFilter === 'offline' && !(!p.online && !p.banned && !p.suspended)) return false;
      if (playersFilter === 'suspended' && !(p.suspended && !p.banned)) return false;
      if (playersFilter === 'banned' && !p.banned) return false;
      if (!q) return true;
      const info = lookups[`${p.steam}|${p.discord}`] ?? {};
      const cachedSteamName = (info.steamName ?? p.steamName ?? '').toLowerCase();
      const cachedDiscordName = (info.discordName ?? p.discordName ?? '').toLowerCase();
      return (
        p.steam.toLowerCase().includes(q) ||
        p.discord.toLowerCase().includes(q) ||
        cachedSteamName.includes(q) ||
        cachedDiscordName.includes(q)
      );
    });
  }, [players, playersQuery, playersFilter, lookups]);
  const lookupTargets = useMemo(() => {
    if (playersQuery.trim()) return filteredPlayers;
    return filteredPlayers.slice(playersPage * 15, (playersPage + 1) * 15);
  }, [playersQuery, filteredPlayers, playersPage]);
  useEffect(() => {
    if (view !== 'players') return;
    let cancelled = false;
    const refetch = async (isFirst = false) => {
      try {
        const data = await fetchPlayersDecrypted(PLAYERS_API);
        if (cancelled || !data?.ok || !Array.isArray(data.players)) {
          if (isFirst && !cancelled) setPlayersLoading(false);
          return;
        }
        const list = data.players;
        if (isFirst) await sleep(MIN_LOAD);
        if (cancelled) return;
        setPlayers((prev) => (playersEqual(prev, list) ? prev : list));
        if (isFirst) setPlayersLoading(false);
      } catch {
        if (isFirst && !cancelled) setPlayersLoading(false);
      }
    };
    refetch(true);
    const id = setInterval(() => refetch(false), 5000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [view]);
  useEffect(() => {
    if (view !== 'players' || lookupTargets.length === 0) return;
    let cancelled = false;
    prefetchPlayerLookups(lookupTargets).then((next) => {
      if (!cancelled) setLookups((prev) => mergeLookups(prev, next));
    });
    return () => {
      cancelled = true;
    };
  }, [view, lookupTargets]);
  const loadPins = useCallback(
    async (bg = false) => {
      setPinsLoading(true);
      try {
        const [res] = await Promise.all([
          fetch('/api/pins'),
          bg ? Promise.resolve() : sleep(MIN_LOAD),
        ]);
        if (!res.ok) {
          const d = await res.json().catch(() => ({}));
          if (!bg) flash(d.error || 'Failed to load PIN codes. Please try again.');
          return;
        }
        const sealed = (await res.text()).trim();
        const payload = await decryptSealed<{
          pins: Pin[];
        }>(apiKey, sealed);
        const list = payload.pins ?? [];
        setPins(list);
        setPinsPage(0);
        const creatorIds = [...new Set(list.map((p) => p.createdBy).filter(Boolean) as string[])];
        if (creatorIds.length > 0) {
          const results = await Promise.all(
            creatorIds.map((id) => fetchLookup(undefined, id).then((d) => [`|${id}`, d] as const)),
          );
          setLookups((prev) => mergeLookups(prev, Object.fromEntries(results)));
        }
      } catch {
        if (!bg) flash('Network error. Check your connection and try again.');
      } finally {
        setPinsLoading(false);
      }
    },
    [apiKey, flash],
  );
  const loadStats = useCallback(
    async (q?: string, bg = false) => {
      setStatsLoading(true);
      try {
        const url = '/api/stats' + (q && q.trim() ? '?q=' + encodeURIComponent(q.trim()) : '');
        const [payload] = await Promise.all([
          fetchPlayersDecrypted(url) as Promise<{
            ok: boolean;
            stats?: StatRow[];
          } | null>,
          bg ? Promise.resolve() : sleep(MIN_LOAD),
        ]);
        if (!payload || !payload.ok) {
          if (!bg) flash('Failed to load player statistics. Please try again.');
          return;
        }
        setStats(payload.stats ?? []);
        setStatsPage(0);
      } catch {
        if (!bg) flash('Network error. Check your connection and try again.');
      } finally {
        setStatsLoading(false);
      }
    },
    [flash],
  );
  const loadDetections = useCallback(
    async (q?: string, type?: string, steam?: string, page?: number, bg = false) => {
      setDetectionsLoading(true);
      try {
        const params = new URLSearchParams();
        if (q && q.trim()) params.set('q', q.trim());
        if (type) params.set('type', type);
        if (steam && steam.trim()) params.set('steam', steam.trim().toLowerCase());
        params.set('page', String(page ?? 0));
        params.set('pageSize', String(DETECTIONS_PAGE_SIZE));
        const url = '/api/detections?' + params.toString();
        const [payload] = await Promise.all([
          fetchPlayersDecrypted(url) as Promise<{
            ok: boolean;
            detections?: Detection[];
            total?: number;
            types?: {
              value: string;
              count: number;
            }[];
          } | null>,
          bg ? Promise.resolve() : sleep(MIN_LOAD),
        ]);
        if (!payload || !payload.ok) {
          if (!bg) flash('Failed to load detections. Please try again.');
          return;
        }
        setDetections(payload.detections ?? []);
        setDetectionsTotal(payload.total ?? payload.detections?.length ?? 0);
        if (Array.isArray(payload.types)) setDetectionTypes(payload.types);
      } catch {
        if (!bg) flash('Network error. Check your connection and try again.');
      } finally {
        setDetectionsLoading(false);
      }
    },
    [flash],
  );
  const loadEvasion = useCallback(
    async (q?: string, bg = false) => {
      setEvasionLoading(true);
      try {
        const url =
          '/api/evasion-flags' + (q && q.trim() ? '?q=' + encodeURIComponent(q.trim()) : '');
        const [payload] = await Promise.all([
          fetchPlayersDecrypted(url) as Promise<{
            ok: boolean;
            flags?: EvasionFlag[];
          } | null>,
          bg ? Promise.resolve() : sleep(MIN_LOAD),
        ]);
        if (!payload || !payload.ok) {
          if (!bg) flash('Failed to load ban evasion flags. Please try again.');
          return;
        }
        setEvasion(payload.flags ?? []);
        setEvasionPage(0);
      } catch {
        if (!bg) flash('Network error. Check your connection and try again.');
      } finally {
        setEvasionLoading(false);
      }
    },
    [flash],
  );
  useEffect(() => {
    loadPins(true);
    loadStats(undefined, true);
    loadEvasion(undefined, true);
    loadDetections(undefined, undefined, undefined, 0, true);
  }, [loadPins, loadStats, loadEvasion, loadDetections]);
  useEffect(() => {
    setDetectionsPage(0);
  }, [detectionTypeFilter, detectionSteamFilter]);
  useEffect(() => {
    if (view !== 'detections') return;
    loadDetections(
      detectionsQuery,
      detectionTypeFilter,
      detectionSteamFilter,
      detectionsPage,
      true,
    );
  }, [view, detectionTypeFilter, detectionSteamFilter, detectionsPage]);
  const refreshPlayersOnce = useCallback(async () => {
    try {
      const j = await fetchPlayersDecrypted(PLAYERS_API);
      if (j?.ok && Array.isArray(j.players)) setPlayers(j.players);
    } catch {}
  }, []);
  const callApi = useCallback(
    async (method: string, body: Record<string, unknown>) => {
      setBusy(true);
      try {
        const res = await fetch('/api/players', {
          method,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || data.ok === false) {
          flash(data.error || 'Operation failed. Please try again.');
          return false;
        }
        await refreshPlayersOnce();
        return true;
      } catch {
        flash('Network error. Check your connection and try again.');
        return false;
      } finally {
        setBusy(false);
      }
    },
    [flash, refreshPlayersOnce],
  );
  const openMenu = (player: Player, e: React.MouseEvent<HTMLButtonElement>) => {
    if (menu && menu.player.steam === player.steam) {
      setMenu(null);
      return;
    }
    const r = e.currentTarget.getBoundingClientRect();
    setMenu({ player, top: r.bottom + 6, right: window.innerWidth - r.right });
  };
  const openEdit = (p: Player) => {
    setEditForm({ discord: p.discord });
    setEditPlayer(p);
  };
  const toggleSuspend = (p: Player) => {
    if (p.suspended) {
      setConfirm({
        title: 'Resume anticheat',
        description: `${p.steam} will need PhoenixAC running again to join.`,
        confirmLabel: 'Resume',
        onConfirm: async () => {
          try {
            const res = await fetch('/api/players/unsuspend', {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ steam_hex: p.steam }),
            });
            const d = (await res.json().catch(() => null)) as {
              ok: boolean;
              error?: string;
            } | null;
            if (!d?.ok) throw new Error(d?.error || 'Error');
            await refreshPlayersOnce();
            flash('Anticheat resumed. The player must run PhoenixAC again to join.');
          } catch (e) {
            flash((e as Error).message);
          }
        },
      });
      return;
    }
    setSuspendMode('create');
    setSuspendTarget(p);
  };
  const editSuspend = (p: Player) => {
    setSuspendMode('edit');
    setSuspendTarget(p);
  };
  const submitSuspend = async (reason: string) => {
    if (!suspendTarget) return;
    setEnforcementBusy(true);
    const url = suspendMode === 'edit' ? '/api/players/suspend/update' : '/api/players/suspend';
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ steam_hex: suspendTarget.steam, reason }),
      });
      const d = (await res.json().catch(() => null)) as {
        ok: boolean;
        error?: string;
      } | null;
      if (!d?.ok) throw new Error(d?.error || 'Error');
      setSuspendTarget(null);
      await refreshPlayersOnce();
      flash(
        suspendMode === 'edit'
          ? 'Suspend reason updated successfully.'
          : 'Player suspended. They can now join the server without running PhoenixAC.',
      );
    } catch (e) {
      flash((e as Error).message);
    } finally {
      setEnforcementBusy(false);
    }
  };
  const setPlayerMode = (p: Player, mode: 'usermode' | 'kernel') => {
    if (p.online) {
      flash('Player is online. Set mode only while offline.');
      return;
    }
    if (p.agentMode === mode) {
      flash(mode === 'kernel' ? 'Already on kernel.' : 'Already on usermode.');
      return;
    }
    const label = mode === 'kernel' ? 'kernel' : 'usermode';
    setConfirm({
      title: 'Set mode',
      description: `Assign ${label} to ${p.steam}? They can only launch that launcher until you change it again.`,
      confirmLabel: 'Set mode',
      onConfirm: async () => {
        try {
          const res = await fetch('/api/players/setmode', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ steam_hex: p.steam, mode }),
          });
          const d = (await res.json().catch(() => null)) as {
            ok: boolean;
            error?: string;
          } | null;
          if (!d?.ok) throw new Error(d?.error || 'Error');
          await refreshPlayersOnce();
          flash(mode === 'kernel' ? 'Mode set to kernel.' : 'Mode set to usermode.');
        } catch (e) {
          flash((e as Error).message);
        }
      },
    });
  };
  const setPlayerPosture = (p: Player, field: 'secure_boot' | 'hvci', allowOff: boolean) => {
    const label = field === 'secure_boot' ? 'Secure Boot' : 'Core Isolation';
    setConfirm({
      title: allowOff ? `Allow no ${label}` : `Require ${label}`,
      description: allowOff
        ? `${p.steam} will be able to launch without ${label}. Takes effect on next launch.`
        : `${p.steam} must have ${label} enabled again. Takes effect on next launch.`,
      confirmLabel: allowOff ? 'Allow' : 'Require',
      onConfirm: async () => {
        try {
          const res = await fetch('/api/players/posture', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              steam_hex: p.steam,
              allow_no_secure_boot: field === 'secure_boot' ? allowOff : undefined,
              allow_no_hvci: field === 'hvci' ? allowOff : undefined,
            }),
          });
          const d = (await res.json().catch(() => null)) as {
            ok: boolean;
            error?: string;
          } | null;
          if (!d?.ok) throw new Error(d?.error || 'Error');
          await refreshPlayersOnce();
          flash(allowOff ? `${label} exception on.` : `${label} required again.`);
        } catch (e) {
          flash((e as Error).message);
        }
      },
    });
  };
  const resetHwid = (p: Player) => {
    setConfirm({
      title: 'Reset hardware ID',
      description: `Clear the stored hardware ID for ${p.steam}? They will get re-fingerprinted on their next launch.`,
      confirmLabel: 'Reset',
      onConfirm: async () => {
        try {
          const res = await fetch('/api/players/reset-hwid', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ steam_hex: p.steam }),
          });
          const d = (await res.json().catch(() => null)) as {
            ok: boolean;
            error?: string;
          } | null;
          if (!d?.ok) throw new Error(d?.error || 'Error');
          await refreshPlayersOnce();
          flash('Hardware ID cleared. Next launch will re-fingerprint the client.');
        } catch (e) {
          flash((e as Error).message);
        }
      },
    });
  };
  const removePlayer = (p: Player) => {
    setConfirm({
      title: 'Delete player',
      description: `Permanently remove ${p.steam} from the database?`,
      confirmLabel: 'Delete',
      destructive: true,
      onConfirm: () => {
        void callApi('DELETE', { steam_hex: p.steam });
      },
    });
  };
  const kickPlayer = (p: Player) => {
    setReasonText('');
    setReasonPrompt({
      title: 'Kick player',
      description: `${p.steam}'s live session will be terminated immediately. They may rejoin later.`,
      confirmLabel: 'Kick',
      destructive: true,
      placeholder: 'Reason (optional)',
      requireReason: false,
      onConfirm: async (reason) => {
        setReasonBusy(true);
        try {
          const res = await fetch('/api/players/kick', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ steam_hex: p.steam, reason }),
          });
          const d = (await res.json().catch(() => null)) as {
            ok: boolean;
            error?: string;
          } | null;
          if (!d?.ok) throw new Error(d?.error || 'Error');
          setReasonPrompt(null);
          await refreshPlayersOnce();
        } catch (e) {
          flash((e as Error).message);
        } finally {
          setReasonBusy(false);
        }
      },
    });
  };
  const toggleBan = (p: Player) => {
    if (p.banned) {
      setConfirm({
        title: 'Remove ban',
        description: `Unban ${p.steam}?`,
        confirmLabel: 'Unban',
        onConfirm: async () => {
          try {
            const res = await fetch('/api/players/unban', {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ steam_hex: p.steam }),
            });
            const d = (await res.json().catch(() => null)) as {
              ok: boolean;
              error?: string;
            } | null;
            if (!d?.ok) throw new Error(d?.error || 'Error');
            await refreshPlayersOnce();
            flash('Ban removed. The player can now rejoin the server.');
          } catch (e) {
            flash((e as Error).message);
          }
        },
      });
      return;
    }
    setBanMode('create');
    setBanTarget(p);
  };
  const editBan = (p: Player) => {
    setBanMode('edit');
    setBanTarget(p);
  };
  const submitBan = async ({
    category,
    reason,
    reasonPublic,
  }: {
    category: string;
    reason: string;
    reasonPublic: boolean;
  }) => {
    if (!banTarget) return;
    setEnforcementBusy(true);
    const url = banMode === 'edit' ? '/api/players/ban/update' : '/api/players/ban';
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          steam_hex: banTarget.steam,
          reason,
          category,
          reason_public: reasonPublic,
        }),
      });
      const d = (await res.json().catch(() => null)) as {
        ok: boolean;
        error?: string;
      } | null;
      if (!d?.ok) throw new Error(d?.error || 'Error');
      setBanTarget(null);
      await refreshPlayersOnce();
      flash(
        banMode === 'edit'
          ? 'Ban details updated successfully.'
          : 'Player banned and kicked from the server.',
      );
    } catch (e) {
      flash((e as Error).message);
    } finally {
      setEnforcementBusy(false);
    }
  };
  const requestScreenshot = useCallback(
    async (p: Player, method: 'nvidia' | 'gdi' | 'auto' = 'auto') => {
      setShotViewer({ steam: p.steam, state: 'loading', method });
      try {
        const res = await fetch('/api/players/screenshot', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ steam_hex: p.steam, method }),
        });
        const data = (await res.json().catch(() => null)) as {
          ok: boolean;
          path?: string;
          error?: string;
          method?: string;
          fallback?: string;
          fallback_reason?: string;
        } | null;
        if (data?.ok && data.path) {
          const used =
            data.method === 'nvidia' || data.method === 'gdi' || data.method === 'auto'
              ? (data.method as 'nvidia' | 'gdi' | 'auto')
              : method;
          setShotViewer({
            steam: p.steam,
            state: 'ready',
            path: data.path,
            method,
            usedMethod: used,
          });
          if (data.fallback) {
            flash(`NVIDIA capture failed — used ${data.fallback.toUpperCase()} as fallback`, 6000);
          }
        } else {
          setShotViewer({
            steam: p.steam,
            state: 'error',
            error: data?.error ?? 'Unknown error',
            method,
          });
        }
      } catch (e) {
        setShotViewer({ steam: p.steam, state: 'error', error: (e as Error).message, method });
      }
    },
    [flash],
  );
  const captureOne = useCallback(
    async (steam: string, methodOverride?: 'nvidia' | 'gdi' | 'auto') => {
      let effectiveMethod: 'nvidia' | 'gdi' | 'auto' = methodOverride ?? 'auto';
      setBulkShot((prev) => {
        if (!prev) return prev;
        if (!methodOverride) effectiveMethod = prev.method;
        return {
          ...prev,
          entries: {
            ...prev.entries,
            [steam]: {
              ...prev.entries[steam],
              state: 'loading',
              path: undefined,
              error: undefined,
            },
          },
        };
      });
      try {
        const res = await fetch('/api/players/screenshot', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ steam_hex: steam, method: effectiveMethod }),
        });
        const data = (await res.json().catch(() => null)) as {
          ok: boolean;
          path?: string;
          error?: string;
        } | null;
        setBulkShot((prev) => {
          if (!prev) return prev;
          const cur = prev.entries[steam];
          if (!cur) return prev;
          const nextEntry: BulkShotEntry =
            data?.ok && data.path
              ? { ...cur, state: 'ready', path: data.path, error: undefined }
              : { ...cur, state: 'error', path: undefined, error: data?.error ?? 'Unknown error' };
          return {
            ...prev,
            entries: { ...prev.entries, [steam]: nextEntry },
            done: Object.values({ ...prev.entries, [steam]: nextEntry }).filter(
              (e) => e.state !== 'loading',
            ).length,
          };
        });
      } catch (e) {
        setBulkShot((prev) => {
          if (!prev) return prev;
          const cur = prev.entries[steam];
          if (!cur) return prev;
          const nextEntry: BulkShotEntry = {
            ...cur,
            state: 'error',
            path: undefined,
            error: (e as Error).message,
          };
          return {
            ...prev,
            entries: { ...prev.entries, [steam]: nextEntry },
            done: Object.values({ ...prev.entries, [steam]: nextEntry }).filter(
              (en) => en.state !== 'loading',
            ).length,
          };
        });
      }
    },
    [],
  );
  const screenshotAllOnline = useCallback(
    async (method: 'nvidia' | 'gdi' | 'auto') => {
      const online = players.filter((p) => p.online && !p.banned && !p.suspended);
      if (online.length === 0) {
        flash('No online players to capture.');
        return;
      }
      const entries: Record<string, BulkShotEntry> = {};
      for (const p of online) {
        const info = lookups[`${p.steam}|${p.discord}`] ?? {};
        entries[p.steam] = {
          steam: p.steam,
          displayName: info.steamName ?? undefined,
          avatar: info.steamAvatar ?? undefined,
          state: 'loading',
        };
      }
      setBulkShot({ entries, total: online.length, done: 0, method });
      const CONCURRENCY = 4;
      const queue = online.map((p) => p.steam);
      const workers: Promise<void>[] = [];
      let idx = 0;
      const next = async (): Promise<void> => {
        while (idx < queue.length) {
          const my = idx++;
          await captureOne(queue[my]);
        }
      };
      for (let i = 0; i < Math.min(CONCURRENCY, queue.length); i++) workers.push(next());
      await Promise.all(workers);
    },
    [players, lookups, flash, captureOne],
  );
  const submitAdd = async () => {
    if (!addForm.steam.trim()) return;
    const ok = await callApi('POST', { steam_hex: addForm.steam, discord_id: addForm.discord });
    if (ok) {
      setShowAdd(false);
      setAddForm({ steam: '', discord: '' });
      flash('Player added to the whitelist.');
    }
  };
  const submitEdit = async () => {
    if (!editPlayer) return;
    const ok = await callApi('PATCH', {
      steam_hex: editPlayer.steam,
      discord_id: editForm.discord.trim() || null,
    });
    if (ok) {
      setEditPlayer(null);
      flash('Player details saved successfully.');
    }
  };
  const generatePinConfirm = () => {
    setConfirm({
      title: 'Generate PIN',
      description: 'A new PIN valid for 24 hours will be generated. Continue?',
      confirmLabel: 'Generate',
      onConfirm: async () => {
        setBusy(true);
        try {
          const res = await fetch('/api/pins', { method: 'POST' });
          const d = await res.json().catch(() => ({}));
          if (res.ok && d.ok) {
            setPinCode(d.code);
            loadPins();
          } else flash(d.error || 'PIN generation failed. Please try again.');
        } catch {
          flash('Network error. Check your connection and try again.');
        } finally {
          setBusy(false);
        }
      },
    });
  };
  const deletePin = (code: string) => {
    setConfirm({
      title: 'Delete PIN',
      description: `Delete PIN ${code}? This cannot be undone.`,
      confirmLabel: 'Delete',
      destructive: true,
      onConfirm: async () => {
        setBusy(true);
        try {
          const res = await fetch('/api/pins', {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code }),
          });
          const d = await res.json().catch(() => ({}));
          if (res.ok && d.ok) {
            setPins((prev) => prev.filter((p) => p.code !== code));
            flash('PIN deleted permanently.');
          } else flash(d.error || 'Operation failed. Please try again.');
        } catch {
          flash('Network error. Check your connection and try again.');
        } finally {
          setBusy(false);
        }
      },
    });
  };
  const copyText = (v: string, msg = 'Copied') => {
    navigator.clipboard?.writeText(v);
    flash(msg, 1500);
  };
  return (
    <div data-phoenix-dashboard>
      <DashboardShell
        view={view}
        onView={setView}
        user={{ name, username, email, avatar }}
        sidebarOpen={sidebarOpen}
        setSidebarOpen={setSidebarOpen}
      >
        {view === 'players' && (
          <PlayersView
            players={players}
            loading={playersLoading}
            query={playersQuery}
            setQuery={setPlayersQuery}
            filter={playersFilter}
            setFilter={setPlayersFilter}
            page={playersPage}
            setPage={setPlayersPage}
            lookups={lookups}
            onAdd={() => setShowAdd(true)}
            onCopy={(v) => copyText(v)}
            onMenu={openMenu}
            onInfo={(p) => setReasonView(p)}
            onScreenshotAll={hasElevatedAccess ? () => setBulkMethodPrompt(true) : undefined}
          />
        )}

        {view === 'pins' && (
          <PinsView
            pins={pins}
            loading={pinsLoading}
            query={pinsQuery}
            setQuery={setPinsQuery}
            filter={pinsFilter}
            setFilter={setPinsFilter}
            page={pinsPage}
            setPage={setPinsPage}
            busy={busy}
            lookups={lookups}
            onRefresh={() => loadPins()}
            onGenerate={generatePinConfirm}
            onCopyPin={(c) => copyText(c, 'PIN copied')}
            onDeletePin={deletePin}
          />
        )}

        {view === 'stats' && (
          <StatsView
            stats={stats}
            loading={statsLoading}
            query={statsQuery}
            setQuery={setStatsQuery}
            page={statsPage}
            setPage={setStatsPage}
            onSearch={(q) => loadStats(q)}
          />
        )}

        {view === 'detections' && (
          <DetectionsView
            detections={detections}
            total={detectionsTotal}
            types={detectionTypes}
            page={detectionsPage}
            pageSize={DETECTIONS_PAGE_SIZE}
            setPage={setDetectionsPage}
            loading={detectionsLoading}
            query={detectionsQuery}
            setQuery={setDetectionsQuery}
            typeFilter={detectionTypeFilter}
            setTypeFilter={setDetectionTypeFilter}
            steamFilter={detectionSteamFilter}
            onClearSteamFilter={() => setDetectionSteamFilter('')}
            onSearch={(q) => {
              setDetectionsPage(0);
              loadDetections(q, detectionTypeFilter, detectionSteamFilter, 0);
            }}
            onRefresh={() =>
              loadDetections(
                detectionsQuery,
                detectionTypeFilter,
                detectionSteamFilter,
                detectionsPage,
              )
            }
            onOpen={(d) => setDetectionViewer(d)}
          />
        )}

        {view === 'evasion' && (
          <EvasionView
            flags={evasion}
            loading={evasionLoading}
            query={evasionQuery}
            setQuery={setEvasionQuery}
            page={evasionPage}
            setPage={setEvasionPage}
            onSearch={(q) => loadEvasion(q)}
          />
        )}
      </DashboardShell>

      <PlayerActionsMenu
        menu={menu}
        onClose={() => setMenu(null)}
        onEdit={openEdit}
        hasElevatedAccess={hasElevatedAccess}
        onScreenshot={(p) => setMethodPrompt(p)}
        onKick={kickPlayer}
        onToggleSuspend={toggleSuspend}
        onToggleBan={toggleBan}
        onDelete={removePlayer}
        onDetectionHistory={(p) => {
          setDetectionSteamFilter(p.steam);
          setDetectionTypeFilter('');
          setDetectionsQuery('');
          setView('detections');
        }}
        onResetHwid={resetHwid}
        onSystemInfo={requestSystemInfo}
        onTools={(p) => loadPciTree(p.steam)}
        onAltAccounts={(p) => setAltsTarget(p)}
        onSetMode={setPlayerMode}
        onSetPosture={setPlayerPosture}
      />

      <AddPlayerDialog
        open={showAdd}
        form={addForm}
        setForm={setAddForm}
        busy={busy}
        onClose={() => setShowAdd(false)}
        onSubmit={submitAdd}
      />

      <EditPlayerDialog
        player={editPlayer}
        form={editForm}
        setForm={setEditForm}
        busy={busy}
        onClose={() => setEditPlayer(null)}
        onSubmit={submitEdit}
      />

      <ConfirmDialog
        payload={confirm}
        onClose={() => setConfirm(null)}
      />

      <ReasonPromptDialog
        payload={reasonPrompt}
        reason={reasonText}
        setReason={setReasonText}
        busy={reasonBusy}
        onClose={() => setReasonPrompt(null)}
      />

      <MethodPromptDialog
        target={methodPrompt}
        onPick={(p, m) => {
          setMethodPrompt(null);
          requestScreenshot(p, m);
        }}
        onClose={() => setMethodPrompt(null)}
      />

      <ShotViewerDialog
        state={shotViewer}
        onClose={() => setShotViewer(null)}
        onRetry={(steam) => {
          const p = players.find((x) => x.steam === steam);
          if (!p) return;
          const m = shotViewer?.method ?? 'auto';
          requestScreenshot(p, m);
        }}
        onRetryDifferent={(steam) => {
          const p = players.find((x) => x.steam === steam);
          if (!p) return;
          setShotViewer(null);
          setMethodPrompt(p);
        }}
      />

      <BulkShotDialog
        state={bulkShot}
        onClose={() => setBulkShot(null)}
        onRetry={(steam) => captureOne(steam)}
      />

      <BulkMethodPromptDialog
        open={bulkMethodPrompt}
        count={players.filter((p) => p.online && !p.banned && !p.suspended).length}
        onClose={() => setBulkMethodPrompt(false)}
        onPick={(m) => {
          setBulkMethodPrompt(false);
          screenshotAllOnline(m);
        }}
      />

      <PinDisplayDialog
        code={pinCode}
        onClose={() => setPinCode(null)}
        onCopy={(c) => copyText(c, 'PIN copied')}
      />

      <BanDialog
        target={banTarget}
        mode={banMode}
        busy={enforcementBusy}
        onClose={() => setBanTarget(null)}
        onSubmit={submitBan}
      />

      <SuspendDialog
        target={suspendTarget}
        mode={suspendMode}
        busy={enforcementBusy}
        onClose={() => setSuspendTarget(null)}
        onSubmit={submitSuspend}
      />

      <ReasonViewerDialog
        player={reasonView}
        lookups={lookups}
        onClose={() => setReasonView(null)}
        onCopy={(v) => copyText(v)}
        onEditBan={editBan}
        onEditSuspend={editSuspend}
      />

      <DetectionViewerDialog
        detection={detectionViewer}
        onClose={() => setDetectionViewer(null)}
        onCopy={(v) => copyText(v)}
      />

      <AltViewerDialog
        player={altsTarget}
        onClose={() => setAltsTarget(null)}
        onCopy={(v) => copyText(v)}
      />

      <SysInfoDialog
        state={sysInfo}
        onClose={() => setSysInfo(null)}
        onRetry={(steam) => {
          const p = players.find((x) => x.steam === steam);
          if (p) requestSystemInfo(p);
        }}
      />

      <ToolsDialog
        state={tools}
        onClose={() => setTools(null)}
        onCopy={(v) => copyText(v)}
        onLoadPci={(steam) => loadPciTree(steam)}
        onLoadMinidumps={(steam) => loadMinidumps(steam)}
        onDownloadDump={(steam, name) => downloadDump(steam, name)}
        downloadingDump={downloadingDump}
        hasElevatedAccess={hasElevatedAccess}
        onOpenProcesses={(steam) => {
          setTools(null);
          setProcBrowser({ steam });
        }}
        onOpenScans={(steam) => {
          setTools(null);
          setScans({ steam });
        }}
      />

      <ScansDialog
        state={scans}
        onClose={() => setScans(null)}
        hasElevatedAccess={hasElevatedAccess}
      />

      <ProcessBrowserDialog
        state={procBrowser}
        onClose={() => setProcBrowser(null)}
        hasElevatedAccess={hasElevatedAccess}
      />

      <ToastNotification
        message={toast?.message ?? null}
        duration={toast?.duration}
        onClear={() => setToast(null)}
      />
    </div>
  );
}
