import { config } from "@/lib/core/config";

type EmbedField = { name: string; value: string; inline?: boolean };

type QueueEntry = { payload: object; tries: number };
const queues: Map<string, QueueEntry[]> = new Map();
const workers: Map<string, boolean> = new Map();

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

async function drain(url: string): Promise<void> {
  if (workers.get(url)) return;
  workers.set(url, true);
  const q = queues.get(url);
  if (!q) { workers.set(url, false); return; }
  while (q.length) {
    const entry = q[0]!;
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(entry.payload),
        signal: AbortSignal.timeout(5000),
      });
      if (res.status === 429) {
        let waitMs = 1000;
        try {
          const j = await res.json() as { retry_after?: number };
          if (typeof j.retry_after === "number" && j.retry_after > 0)
            waitMs = Math.min(Math.ceil(j.retry_after * 1000) + 50, 10_000);
        } catch {}
        entry.tries++;
        if (entry.tries > 5) q.shift();
        await sleep(waitMs);
        continue;
      }
      q.shift();
      await sleep(250);
    } catch {
      entry.tries++;
      if (entry.tries > 3) q.shift();
      else await sleep(500);
    }
  }
  workers.set(url, false);
}

async function postWebhook(url: string | undefined, payload: object): Promise<void> {
  if (!url) return;
  let q = queues.get(url);
  if (!q) { q = []; queues.set(url, q); }
  if (q.length >= 200) return;
  q.push({ payload, tries: 0 });
  void drain(url);
}

export async function postLoginWebhook(opts: {
  steamHex: string;
  diskId: string;
  ip: string;
}): Promise<void> {
  return postWebhook(config.discord_login_webhook, {
    username: "PhoenixAC",
    embeds: [
      {
        title: "Accesso launcher",
        color: 0x36c25f,
        fields: [
          { name: "Steam HEX", value: "`" + (opts.steamHex || "?") + "`", inline: true },
          { name: "Disk ID",   value: "`" + (opts.diskId   || "?") + "`", inline: true },
          { name: "IP",        value: "`" + (opts.ip       || "?") + "`", inline: true },
        ],
        timestamp: new Date().toISOString(),
      },
    ],
  });
}

export type DetectionEventType =
  | "detection"
  | "sweep"
  | "exit"
  | "overlay"
  | "internal"
  | "mapper"
  | "injection"
  | "modfingerprint"
  | "security"
  | "internal_fivem";

export type DetectionEventInput = {
  type: DetectionEventType;
  steamHex: string;
  pid: number | null;
  exe: string | null;
  host: string | null;
  ip: string;
  payload: Record<string, unknown>;
};

const steamProfileUrl = (hex: string): string | null => {
  if (!hex) return null;
  let v = 0n;
  for (const c of hex) {
    const n =
      c >= "0" && c <= "9" ? c.charCodeAt(0) - 48 :
      c >= "a" && c <= "f" ? c.charCodeAt(0) - 87 :
      c >= "A" && c <= "F" ? c.charCodeAt(0) - 55 : -1;
    if (n < 0) return null;
    v = (v << 4n) | BigInt(n);
  }
  return `https://steamcommunity.com/profiles/${v.toString()}`;
};

const code = (s: unknown) => "`" + (s == null || s === "" ? "?" : String(s)) + "`";

const fmtHex = (n: unknown): string => {
  if (typeof n === "number") return "0x" + n.toString(16).toUpperCase();
  if (typeof n === "string" && /^\d+$/.test(n))
    return "0x" + BigInt(n).toString(16).toUpperCase();
  if (typeof n === "string" && n.startsWith("0x")) return n.toUpperCase();
  return "?";
};

const overlayFlagsToString = (flags: number): string => {
  const pairs: Array<[number, string]> = [
    [1 << 0, "Layered"],
    [1 << 1, "Transparent"],
    [1 << 2, "Popup"],
    [1 << 3, "TopMost"],
    [1 << 4, "AlignedGame"],
    [1 << 5, "GameOwner"],
    [1 << 6, "SuspiciousClass"],
    [1 << 7, "GraphicsStack"],
    [1 << 8, "EmptyTitle"],
  ];
  const out: string[] = [];
  for (const [bit, name] of pairs) if (flags & bit) out.push(name);
  return out.length ? out.join(" | ") : "-";
};

const mapperHitTypeName = (t: number) =>
  t === 0 ? "MapperMutex" : t === 1 ? "CtfmonExecMem" : t === 2 ? "DiagTrackFake" : "Unknown";

const mapperHitDesc = (t: number) =>
  t === 0 ? "Mutex `Global\\ApplicationFrameHost_64` presente nel sistema. Manual mapper attivo o recentemente eseguito." :
  t === 1 ? "ctfmon.exe contiene regione MEM_PRIVATE eseguibile. DLL iniettata manualmente rilevata in processo di sistema." :
  t === 2 ? "Servizio DiagTrack ha binary path non-svchost. Mapper ha sostituito il servizio legittimo con eseguibile custom." :
            "Segnale mapper sconosciuto.";

const injectionHitTypeName = (t: number) =>
  t === 0 ? "StompedModule" : t === 1 ? "PrivateExecPE" : "Unknown";

const injectionHitDesc = (t: number) =>
  t === 0 ? "Modulo DLL in FiveM con pagine MEM_PRIVATE al base address. Contenuto originale sovrascritto da attacker code (module stomping / hollowing)." :
  t === 1 ? "Regione MEM_PRIVATE eseguibile con PE header valido in FiveM. DLL manual-mapped rilevata - thread loader gia' uscito o injection threadless (PoolParty / APC)." :
            "Payload iniettato rilevato.";

type FieldRow = { name: string; value: string; inline?: boolean };

const baseFields = (steamHex: string, ip: string): FieldRow[] => {
  const url = steamProfileUrl(steamHex);
  const f: FieldRow[] = [
    { name: "Steam Hex", value: code(steamHex), inline: true },
  ];
  if (url) f.push({ name: "Profilo", value: `[${steamHex}](${url})`, inline: true });
  if (ip)  f.push({ name: "IP",      value: code(ip), inline: true });
  return f;
};

const num = (v: unknown): number => (typeof v === "number" ? v : Number(v) || 0);
const str = (v: unknown): string => (typeof v === "string" ? v : v == null ? "" : String(v));

function buildEmbed(ev: DetectionEventInput): {
  title: string;
  description: string;
  color: number;
  fields: FieldRow[];
  footer: string;
} {
  const p = ev.payload ?? {};
  const f = baseFields(ev.steamHex, ev.ip);
  if (ev.pid != null) f.push({ name: "PID", value: code(ev.pid), inline: true });
  if (ev.exe)         f.push({ name: "Processo", value: code(ev.exe), inline: true });
  if (ev.host)        f.push({ name: "Host", value: code(ev.host), inline: true });

  switch (ev.type) {
    case "detection":
      f.push({ name: "Vettore detection",  value: code(p.via), inline: true });
      f.push({ name: "NtReadVirtualMemory", value: code(fmtHex(p.hookAddr)), inline: true });
      f.push({ name: "Shellcode poison",    value: code(fmtHex(p.scAddr)),   inline: true });
      return {
        title: "🚨 Cheat detected",
        description: "Hook applicato sul processo sospetto. Letture memoria FiveM neutralizzate via syscall poison.",
        color: 0xe74c3c,
        fields: f,
        footer: "PhoenixAC | DETECTION",
      };

    case "sweep":
      f.push({ name: "Anchor azzerati",    value: code(num(p.anchorAcc)), inline: true });
      f.push({ name: "Ptr FiveM azzerati", value: code(num(p.rangeAcc)),  inline: true });
      f.push({ name: "Needles attivi",     value: code(num(p.needleSnap)), inline: true });
      f.push({ name: "Sweep ticks",        value: code(num(p.ticks)),     inline: true });
      return {
        title: "🛡️ Cheat neutralizzato (finestra 60s)",
        description: "Sweep memoria: puntatori FiveM cached nel cheat azzerati. ESP/W2S/bone bloccati.",
        color: 0x3498db,
        fields: f,
        footer: "PhoenixAC | SWEEP",
      };

    case "exit":
      f.push({ name: "Anchor zerati totali",    value: code(num(p.totalA)),     inline: true });
      f.push({ name: "Ptr FiveM zerati totali", value: code(num(p.totalR)),     inline: true });
      f.push({ name: "Durata sotto hook",       value: code(num(p.lifetimeSec) + "s"), inline: true });
      return {
        title: "⚪ Cheat process exited",
        description: "Processo cheat terminato durante la sessione AC. Snapshot finale.",
        color: 0x99aab5,
        fields: f,
        footer: "PhoenixAC | EXIT",
      };

    case "overlay": {
      const flags = num(p.flags);
      f.push({ name: "Window class", value: code(p.windowClass), inline: true });
      f.push({ name: "Score",        value: code(num(p.score)),  inline: true });
      f.push({ name: "Overlap area", value: code((num(p.overlapPct) * 100).toFixed(1) + "%"), inline: true });
      f.push({ name: "Flag mask",    value: code("0x" + flags.toString(16).toUpperCase()), inline: true });
      f.push({ name: "Firme attive", value: overlayFlagsToString(flags), inline: false });
      return {
        title: "👁️ External overlay detected",
        description: "Finestra overlay sospetta sopra a FiveM (D3D11/ImGui/layered popup). Possibile cheat external con ESP renderer su processo terzo.",
        color: 0xffa500,
        fields: f,
        footer: "PhoenixAC | OVERLAY",
      };
    }

    case "internal": {
      const tid = num(p.tid);
      const isThread = tid > 0;
      f.push({ name: "Tipo hit", value: code(str(p.hitType)), inline: true });
      if (isThread) f.push({ name: "Thread ID", value: code(tid), inline: true });
      f.push({ name: "Indirizzo", value: code(fmtHex(p.addr)), inline: true });
      return {
        title: "💉 Internal cheat rilevato",
        description: isThread
          ? "Thread FiveM con start address in MEM_PRIVATE exec. DLL iniettata attiva - invoker + hook in esecuzione."
          : "IDXGISwapChain vtable[8] (Present) punta a MEM_PRIVATE. D3D overlay hook attivo - ESP/ImGui renderer.",
        color: 0x8b0000,
        fields: f,
        footer: "PhoenixAC | INTERNAL",
      };
    }

    case "mapper": {
      const ht = num(p.hitType);
      f.push({ name: "Tipo segnale", value: code(mapperHitTypeName(ht)), inline: true });
      if (num(p.addr)) {
        f.push({ name: "Indirizzo",         value: code(fmtHex(p.addr)),       inline: true });
        f.push({ name: "Dimensione regione", value: code(fmtHex(p.regionSize)), inline: true });
      }
      f.push({ name: "Dettaglio", value: code(str(p.detail)), inline: false });
      return {
        title: "🧩 Manual mapper rilevato",
        description: mapperHitDesc(ht),
        color: 0x990000,
        fields: f,
        footer: "PhoenixAC | MAPPER",
      };
    }

    case "injection": {
      const ht = num(p.hitType);
      f.push({ name: "Tipo hit",           value: code(injectionHitTypeName(ht)), inline: true });
      f.push({ name: "Indirizzo",          value: code(fmtHex(p.addr)),           inline: true });
      f.push({ name: "Dimensione regione", value: code(fmtHex(p.regionSize)),     inline: true });
      f.push({ name: "Dettaglio",          value: code(str(p.detail)),            inline: false });
      return {
        title: "💉 Injection payload in FiveM",
        description: injectionHitDesc(ht),
        color: ht === 0 ? 0xff7700 : 0x990000,
        fields: f,
        footer: "PhoenixAC | INJECTION",
      };
    }

    case "modfingerprint":
      f.push({ name: "DLL hits", value: code(num(p.hits)), inline: true });
      f.push({ name: "Moduli",   value: "```\n" + (str(p.modules) || "?") + "\n```", inline: false });
      return {
        title: "🚨 ModFingerprint - cheat overlay rilevato",
        description: "Processo con `D3DX9_43.dll` + DLL fingerprint cheat. Possibile overlay ImGui/D3D9 (NiggaMEn / espriva).",
        color: 0xe74c3c,
        fields: f,
        footer: "PhoenixAC | MODFINGERPRINT",
      };

    case "security": {
      const sev = num(p.severity);
      const sevTag =
        sev === 0 ? "INFO" : sev === 1 ? "WARN" : sev === 2 ? "HIT" : "KILL";
      const color =
        sev === 0 ? 0x3498db :
        sev === 1 ? 0xffa500 :
        sev === 2 ? 0xe74c3c : 0x990000;
      f.push({ name: "Severity", value: code(sevTag),         inline: true });
      f.push({ name: "Category", value: code(str(p.category)), inline: true });
      f.push({ name: "Label",    value: code(str(p.label)),    inline: true });
      if (p.body) {
        f.push({
          name: "Detail",
          value: "```\n" + str(p.body).slice(0, 1800) + "\n```",
          inline: false,
        });
      }
      if (p.code != null)
        f.push({ name: "Code", value: code(fmtHex(p.code)), inline: true });
      if (p.reason)
        f.push({ name: "Reason", value: code(str(p.reason)), inline: false });
      return {
        title: `[${sevTag}] ${str(p.label) || "Security event"}`,
        description: "Evento di sicurezza interno al launcher (integrity / antitamper / detonator).",
        color,
        fields: f,
        footer: "PhoenixAC | SECURITY",
      };
    }

    default:
      return {
        title: "PhoenixAC event",
        description: "Evento non classificato.",
        color: 0x99aab5,
        fields: f,
        footer: "PhoenixAC | EVENT",
      };
  }
}

function channelFor(type: DetectionEventType): string | undefined {
  if (type === "security") return config.discord_security_webhook;
  return config.discord_detection_webhook;
}

export async function postDetectionEvent(ev: DetectionEventInput): Promise<void> {
  const embed = buildEmbed(ev);
  return postWebhook(channelFor(ev.type), {
    username: "Phoenix-AC",
    embeds: [
      {
        title: embed.title,
        description: embed.description,
        color: embed.color,
        fields: embed.fields,
        timestamp: new Date().toISOString(),
        footer: { text: embed.footer },
      },
    ],
  });
}

export async function postEvasionWebhook(opts: {
  primaryHex: string;
  secondaryHex: string;
  fpType: string;
  fpValue: string;
  primaryName: string | null;
  secondaryName: string | null;
  clientIp: string | null;
}): Promise<void> {
  const fpLabel: Record<string, string> = {
    discord:  "Discord ID",
    license:  "License",
    license2: "License2",
    token:    "FiveM Token",
    ip:       "IP",
  };
  const safe = (s: string | null | undefined) =>
    s == null || s === "" ? "?" : String(s);
  return postWebhook(config.discord_antibanevading_webhook, {
    username: "PhoenixAC AntiBanEvading",
    embeds: [
      {
        title: "🚩 Possibile ban evasion",
        description:
          "Stesso fingerprint rilevato su due Steam HEX diversi. " +
          "Nessun ban automatico - questo è solo un alert.",
        color: 0xffae00,
        fields: [
          { name: "Tipo fingerprint", value: "`" + (fpLabel[opts.fpType] || opts.fpType) + "`", inline: true },
          { name: "Valore",           value: "`" + safe(opts.fpValue).slice(0, 200) + "`", inline: false },
          { name: "Steam HEX #1",     value: "`" + safe(opts.primaryHex) + "`" + (opts.primaryName ? `\n${safe(opts.primaryName)}` : ""), inline: true },
          { name: "Steam HEX #2",     value: "`" + safe(opts.secondaryHex) + "`" + (opts.secondaryName ? `\n${safe(opts.secondaryName)}` : ""), inline: true },
          { name: "IP last seen",     value: "`" + safe(opts.clientIp) + "`", inline: true },
        ],
        timestamp: new Date().toISOString(),
        footer: { text: "PhoenixAC | ANTIBANEVADING" },
      },
    ],
  });
}

export async function postAdminWebhook(opts: {
  title: string;
  color: number;
  actor: { id: string; username: string };
  fields: EmbedField[];
}): Promise<void> {
  return postWebhook(config.discord_admin_webhook, {
    username: "PhoenixAC Admin",
    embeds: [
      {
        title: opts.title,
        color: opts.color,
        author: {
          name: `${opts.actor.username} (${opts.actor.id})`,
        },
        fields: opts.fields,
        timestamp: new Date().toISOString(),
      },
    ],
  });
}
