export function prettyDetectionType(type: string): string {
  switch (type) {
    case "anti-debug":       return "Anti-Debug Trigger";
    case "vuln-drv":         return "Vulnerable Driver";
    case "re-tool":          return "Reverse Engineering Tool";
    case "overlay":          return "Overlay Window";
    case "display-affinity": return "Display Affinity Overlay";
    case "nv-streamproof":   return "NVIDIA StreamProof";
    case "susp-key":         return "Suspicious Hotkey";
    case "proc-access":      return "Protected Process Access";
    case "pci-removed":      return "PCI Device Unplugged";
    case "hvci-spoof":       return "HVCI Spoofed";
    case "cheat-host":       return "Cheat Host";
    case "cheat-dns":        return "Cheat DNS Cache Match";
    case "insecure-boot":    return "Insecure Boot";
    case "manual-mapped-driver": return "Manual-Mapped Driver Thread";
    case "manual-mapped-irp": return "Manual-Mapped IRP Handler";
    default:                 return type;
  }
}

type Tone = { text: string; dot: string; bg: string; border: string };

const TONES: Record<string, Tone> = {
  danger:  { text: "text-red-300/90",    dot: "bg-red-400",    bg: "bg-red-400/[0.07]",    border: "border-red-400/25"    },
  cheat:   { text: "text-orange-300/90", dot: "bg-orange-400", bg: "bg-orange-400/[0.07]", border: "border-orange-400/25" },
  warn:    { text: "text-amber-300/90",  dot: "bg-amber-400",  bg: "bg-amber-400/[0.07]",  border: "border-amber-400/25"  },
  info:    { text: "text-sky-300/90",    dot: "bg-sky-400",    bg: "bg-sky-400/[0.07]",    border: "border-sky-400/25"    },
};

export function detectionTone(type: string): Tone {
  if (type === "hvci-spoof" || type === "cheat-host" || type === "cheat-dns") return TONES.cheat;
  if (type === "anti-debug"   || type === "vuln-drv"    || type === "re-tool" ||
      type === "manual-mapped-driver" || type === "manual-mapped-irp") return TONES.danger;
  if (type === "insecure-boot" || type === "pci-removed") return TONES.info;
  return TONES.warn;
}

// Mirror of backend prettifyExtraKey — keep labels in sync with the Discord webhook.
export function prettifyExtraKey(k: string): string {
  const map: Record<string, string> = {
    className:    "Class Name",
    title:        "Window Title",
    exePath:      "Exe Path",
    pid:          "PID",
    hwnd:         "HWND",
    style:        "Style",
    exStyle:      "Extended Style",
    rect:         "Rect",
    monitor:      "Monitor",
    coveragePct:  "Coverage %",
    trigger:      "Trigger",
    affinity:     "Affinity",
    matchKind:    "Match Kind",
    matchPattern: "Matched Pattern",
    vendor:       "Vendor",
    vid:          "Vendor ID",
    did:          "Device ID",
    subsys:       "Subsystem",
    rev:          "Revision",
    description:  "Description",
    manufacturer: "Manufacturer",
    location:     "Location",
    instance:     "Instance",
    host:         "Host",
    ip:           "IP Address",
    port:         "Port",
    module:       "Module",
    dllPath:      "DLL Path",
    driverName:   "Driver Name",
    driverPath:   "Driver Path",
    signer:       "Signer",
    processName:  "Process Name",
    address:          "Start Address",
    tid:              "Thread ID",
    nearestModule:    "Nearest Module",
    nearestOffset:    "Nearest Offset",
    dumpBytes:        "Dump Bytes",
    dumpHex:          "Dump (hex)",
    majorFunction:    "IRP Major",
    majorIndex:       "IRP Index",
    deviceName:       "Device",
    symlinkName:      "Symbolic Link",
    source:           "Source",
    brand:            "Brand",
  };
  if (map[k]) return map[k];
  return k.charAt(0).toUpperCase() + k.slice(1).replace(/([A-Z])/g, " $1");
}

const WS_FLAGS: [number, string][] = [
  [0x80000000, "WS_POPUP"],
  [0x40000000, "WS_CHILD"],
  [0x20000000, "WS_MINIMIZE"],
  [0x10000000, "WS_VISIBLE"],
  [0x08000000, "WS_DISABLED"],
  [0x04000000, "WS_CLIPSIBLINGS"],
  [0x02000000, "WS_CLIPCHILDREN"],
  [0x01000000, "WS_MAXIMIZE"],
  [0x00800000, "WS_BORDER"],
  [0x00400000, "WS_DLGFRAME"],
  [0x00200000, "WS_VSCROLL"],
  [0x00100000, "WS_HSCROLL"],
  [0x00080000, "WS_SYSMENU"],
  [0x00040000, "WS_THICKFRAME"],
  [0x00020000, "WS_GROUP"],
  [0x00010000, "WS_TABSTOP"],
];

const WS_EX_FLAGS: [number, string][] = [
  [0x00000001, "WS_EX_DLGMODALFRAME"],
  [0x00000004, "WS_EX_NOPARENTNOTIFY"],
  [0x00000008, "WS_EX_TOPMOST"],
  [0x00000010, "WS_EX_ACCEPTFILES"],
  [0x00000020, "WS_EX_TRANSPARENT"],
  [0x00000040, "WS_EX_MDICHILD"],
  [0x00000080, "WS_EX_TOOLWINDOW"],
  [0x00000100, "WS_EX_WINDOWEDGE"],
  [0x00000200, "WS_EX_CLIENTEDGE"],
  [0x00000400, "WS_EX_CONTEXTHELP"],
  [0x00001000, "WS_EX_RIGHT"],
  [0x00002000, "WS_EX_RTLREADING"],
  [0x00004000, "WS_EX_LEFTSCROLLBAR"],
  [0x00010000, "WS_EX_CONTROLPARENT"],
  [0x00020000, "WS_EX_STATICEDGE"],
  [0x00040000, "WS_EX_APPWINDOW"],
  [0x00080000, "WS_EX_LAYERED"],
  [0x00100000, "WS_EX_NOINHERITLAYOUT"],
  [0x00200000, "WS_EX_NOREDIRECTIONBITMAP"],
  [0x00400000, "WS_EX_LAYOUTRTL"],
  [0x02000000, "WS_EX_COMPOSITED"],
  [0x08000000, "WS_EX_NOACTIVATE"],
];

function decodeFlagSet(value: number, table: [number, string][]): string {
  const names: string[] = [];
  for (const [bit, name] of table) {
    if ((value & bit) !== 0) names.push(name);
  }
  return names.length > 0 ? names.join(" | ") : "0";
}

function parseHexOrDec(v: string | number): number {
  if (typeof v === "number") return v;
  const s = v.trim();
  if (/^0x[0-9a-f]+$/i.test(s)) return parseInt(s.slice(2), 16);
  const n = Number(s);
  return Number.isFinite(n) ? n : NaN;
}

export function formatExtraValue(k: string, v: unknown): string {
  if (v === null || v === undefined) return "";
  if (k === "rect" && typeof v === "object") {
    const r = v as { l?: number; t?: number; r?: number; b?: number };
    const l = r.l ?? 0, t = r.t ?? 0, ri = r.r ?? 0, b = r.b ?? 0;
    return `${ri - l}x${b - t} @ ${l},${t}`;
  }
  if (k === "monitor" && typeof v === "object") {
    const m = v as { w?: number; h?: number };
    return `${m.w ?? 0}x${m.h ?? 0}`;
  }
  if (k === "style" && (typeof v === "string" || typeof v === "number")) {
    const n = parseHexOrDec(v);
    if (Number.isFinite(n)) return decodeFlagSet(n, WS_FLAGS);
    return String(v);
  }
  if (k === "exStyle" && (typeof v === "string" || typeof v === "number")) {
    const n = parseHexOrDec(v);
    if (Number.isFinite(n)) return decodeFlagSet(n, WS_EX_FLAGS);
    return String(v);
  }
  if (k === "address" && typeof v === "string") {
    const s = v.trim();
    if (/^0x[0-9a-f]+$/i.test(s)) return s;
    return v;
  }
  if (k === "nearestOffset" && (typeof v === "string" || typeof v === "number")) {
    const n = parseHexOrDec(v);
    if (!Number.isFinite(n)) return String(v);
    return `+0x${n.toString(16).toUpperCase()}`;
  }
  if (k === "dumpHex" && typeof v === "string") {
    const hex = v.replace(/[^0-9a-f]/gi, "");
    if (!hex) return "";
    const bytes: number[] = [];
    for (let i = 0; i + 1 < hex.length; i += 2) {
      bytes.push(parseInt(hex.slice(i, i + 2), 16));
    }
    const lines: string[] = [];
    for (let off = 0; off < bytes.length; off += 16) {
      const chunk = bytes.slice(off, off + 16);
      const hexPart = chunk.map((b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(16 * 3 - 1, " ");
      const asciiPart = chunk.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
      lines.push(`${off.toString(16).padStart(4, "0")}  ${hexPart}  ${asciiPart}`);
    }
    return lines.join("\n");
  }
  if (k === "affinity" && (typeof v === "string" || typeof v === "number")) {
    const n = parseHexOrDec(v);
    if (!Number.isFinite(n)) return String(v);
    const label =
      n === 0x00 ? "WDA_NONE" :
      n === 0x01 ? "WDA_MONITOR" :
      n === 0x11 ? "WDA_EXCLUDEFROMCAPTURE" :
                   `0x${n.toString(16).toUpperCase().padStart(2, "0")}`;
    return `${label} (${n})`;
  }
  if (typeof v === "object") {
    try { return JSON.stringify(v); } catch { return String(v); }
  }
  return String(v);
}

export function formatDetectionReason(type: string, reason: string | null | undefined): string | null {
  if (!reason) return null;
  const r = reason.trim();
  if (!r) return null;

  if (type === "manual-mapped-driver") {
    const m = r.match(/^mapped-thread-(0x[0-9a-fA-F]+)$/);
    if (m) return `Start Address: ${m[1]}`;
  }

  if (type === "manual-mapped-irp") {
    const m = r.match(/^mapped-irp-(0x[0-9a-fA-F]+)$/);
    if (m) return `Handler Address: ${m[1]}`;
  }

  if (type === "cheat-dns") {
    return `Brand: ${r}`;
  }

  if (type === "susp-key") {
    const m = r.match(/^susp-key-(.+)$/);
    if (m) return `Key: ${m[1].toUpperCase()}`;
  }

  if (type === "overlay") {
    const parts: string[] = [];
    const traits: Record<string, string> = {
      "topmost":       "Topmost",
      "layered":       "Layered",
      "transparent":   "Transparent",
      "toolwindow":    "Tool-Window",
      "noactivate":    "No-Activate",
      "fullscreen":    "Fullscreen",
    };
    let rest = r;
    const covMatch = rest.match(/-cov(\d+)$/);
    let coverage: string | null = null;
    if (covMatch) {
      coverage = `${covMatch[1]}%`;
      rest = rest.slice(0, -covMatch[0].length);
    }
    const sizeMatch = rest.match(/^size-minus-(\d+)x(\d+)$/);
    if (sizeMatch) {
      return `Size Trick: -${sizeMatch[1]}×${sizeMatch[2]} px`;
    }
    for (const seg of rest.split("-")) {
      if (traits[seg]) parts.push(traits[seg]);
    }
    if (coverage) parts.push(`Coverage: ${coverage}`);
    if (parts.length) return parts.join(" · ");
  }

  if (type === "display-affinity") {
    if (r === "wda-exclude-capture") return "Affinity: WDA_EXCLUDEFROMCAPTURE";
    if (r === "wda-monitor")         return "Affinity: WDA_MONITOR";
  }

  if (type === "pci-removed") {
    const m = r.match(/^([0-9a-fA-F]{4}):([0-9a-fA-F]{4})$/);
    if (m) return `VID:DID  0x${m[1].toUpperCase()}:0x${m[2].toUpperCase()}`;
  }

  return r;
}

export function readableExtras(extras: Record<string, unknown> | null): { key: string; label: string; value: string }[] {
  if (!extras) return [];
  const out: { key: string; label: string; value: string }[] = [];
  for (const [k, v] of Object.entries(extras)) {
    const value = formatExtraValue(k, v);
    if (!value) continue;
    out.push({ key: k, label: prettifyExtraKey(k), value });
  }
  if (out.length === 0 && Object.keys(extras).length > 0) {
    try {
      out.push({ key: "__raw", label: "Raw JSON", value: JSON.stringify(extras, null, 2) });
    } catch { /* ignore */ }
  }
  return out;
}
