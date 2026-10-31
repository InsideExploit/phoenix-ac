export interface SlotState {
    lastReportMs: number;
    reportCount:  number;
}

export interface LiveAgent {
    requestScreenshot(method?: number, timeoutMs?: number): Promise<Buffer>;
    requestSystemInfo(timeoutMs?: number): Promise<string>;
    requestPciTree(timeoutMs?: number): Promise<string>;
    requestMinidumps(timeoutMs?: number): Promise<string>;
    requestDumpFile(name: string, timeoutMs?: number): Promise<Buffer>;
    kick(reason: string): void;
}

const bySteam = new Map<string, SlotState>();
const agentBySteam = new Map<string, LiveAgent>();

export function registerSession(steamHex: string, _slotKey: Buffer, agent?: LiveAgent): void {
    bySteam.set(steamHex, { lastReportMs: 0, reportCount: 0 });
    if (agent) agentBySteam.set(steamHex, agent);
}

export function unregisterSession(steamHex: string): void {
    bySteam.delete(steamHex);
    agentBySteam.delete(steamHex);
}

export function getLiveAgent(steamHex: string): LiveAgent | null {
    return agentBySteam.get(steamHex) ?? null;
}

export function reportSlot(steamHex: string): { known: boolean } {
    const st = bySteam.get(steamHex);
    if (!st) return { known: false };
    st.lastReportMs = Date.now();
    st.reportCount++;
    return { known: true };
}

export interface SlotSnapshot {
    known:        boolean;
    lastReportMs: number;
    ageMs:        number;
}

export function snapshotSlot(steamHex: string): SlotSnapshot {
    const st = bySteam.get(steamHex);
    if (!st) return { known: false, lastReportMs: 0, ageMs: -1 };
    const ageMs = st.lastReportMs === 0 ? -1 : Date.now() - st.lastReportMs;
    return { known: true, lastReportMs: st.lastReportMs, ageMs };
}
