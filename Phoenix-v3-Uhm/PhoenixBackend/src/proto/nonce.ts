export class NonceCache {
    private readonly seen = new Map<string, number>();
    constructor(private readonly windowMs: number) {}

    check(nonce: Buffer, timestampMs: number, nowMs: number): boolean {
        const drift = Math.abs(nowMs - timestampMs);
        if (drift > this.windowMs) return false;

        this.sweep(nowMs);

        const key = nonce.toString('base64');
        if (this.seen.has(key)) return false;
        this.seen.set(key, timestampMs);
        return true;
    }

    private sweep(nowMs: number): void {
        if (this.seen.size < 1024) return;
        const cutoff = nowMs - this.windowMs;
        for (const [k, ts] of this.seen) {
            if (ts < cutoff) this.seen.delete(k);
        }
    }

    clear(): void {
        this.seen.clear();
    }
}
