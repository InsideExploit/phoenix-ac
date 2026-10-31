import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { config } from '../config.js';
import { log } from '../logger.js';

const EMBED_COLOR = 0xf9601f;
const FOOTER_TEXT = 'PhoenixAC';

const whLog = log.child({ module: 'discord' });

export type DiscordChannel =
    | 'registrations'
    | 'auth'
    | 'sessions'
    | 'hwid-mismatch'
    | 'detections-blocking'
    | 'detections-report'
    | 'detections-cheats'
    | 'errors';

interface EmbedField {
    name: string;
    value: string;
    inline?: boolean;
}

export interface WebhookEmbed {
    title: string;
    description?: string;
    fields?: EmbedField[];
}

interface FinalEmbed extends WebhookEmbed {
    color: number;
    timestamp: string;
    footer: { text: string };
    image?: { url: string };
}

function urlFor(channel: DiscordChannel): string {
    switch (channel) {
        case 'registrations':       return config.webhooks.registrations;
        case 'auth':                return config.webhooks.auth;
        case 'sessions':            return config.webhooks.sessions;
        case 'hwid-mismatch':       return config.webhooks.hwidMismatch;
        case 'detections-blocking': return config.webhooks.detectionsBlocking;
        case 'detections-report':   return config.webhooks.detectionsReport;
        case 'detections-cheats':   return config.webhooks.detectionsCheats;
        case 'errors':              return config.webhooks.errors;
    }
}

export async function postWebhook(
    channel: DiscordChannel,
    embed: WebhookEmbed,
    screenshotPath?: string | null,
): Promise<boolean> {
    if (!config.webhooks.enabled) {
        whLog.warn({ channel }, 'webhook skipped: webhooks disabled');
        return false;
    }
    const url = urlFor(channel);
    if (!url) {
        whLog.error({ channel, env: config.phoenixEnv }, 'webhook skipped: url unset for channel');
        return false;
    }

    const final: FinalEmbed = {
        ...embed,
        color: EMBED_COLOR,
        timestamp: new Date().toISOString(),
        footer: { text: FOOTER_TEXT },
    };

    try {
        if (screenshotPath) {
            let png: Buffer | null = null;
            try { png = await fs.readFile(screenshotPath); } catch { png = null; }
            if (png) {
                const fname = path.basename(screenshotPath).replace(/[^\w.-]/g, '_');
                final.image = { url: `attachment://${fname}` };

                const form = new FormData();
                form.set('payload_json', JSON.stringify({ embeds: [final] }));
                form.set('files[0]', new Blob([png], { type: 'image/png' }), fname);

                const res = await fetch(url, { method: 'POST', body: form });
                if (!res.ok) {
                    whLog.error({ channel, status: res.status }, 'webhook multipart failed');
                    return false;
                }
                return true;
            }
        }

        const res = await fetch(url, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ embeds: [final] }),
        });
        if (!res.ok) {
            const text = await res.text().catch(() => '');
            whLog.error({ channel, status: res.status, body: text.slice(0, 200) }, 'webhook failed');
            return false;
        }
        return true;
    } catch (e) {
        whLog.error({ err: (e as Error).message, channel }, 'webhook error');
        return false;
    }
}

export async function pingAllWebhooks(): Promise<void> {
    if (!config.webhooks.enabled) {
        whLog.warn({ env: config.phoenixEnv }, 'boot ping skipped: webhooks disabled');
        return;
    }
    const channels: DiscordChannel[] = [
        'registrations', 'auth', 'sessions', 'hwid-mismatch',
        'detections-blocking', 'detections-report', 'detections-cheats', 'errors',
    ];
    const results: Record<string, boolean> = {};
    for (const ch of channels) {
        const url = urlFor(ch);
        if (!url) {
            results[ch] = false;
            whLog.error({ channel: ch, env: config.phoenixEnv }, 'boot ping: url unset');
            continue;
        }
        try {
            const res = await fetch(url + '?wait=false', {
                method: 'POST',
                headers: { 'content-type': 'application/json' },
                body: JSON.stringify({
                    embeds: [{
                        title: 'PhoenixAC backend online',
                        description: `Channel: \`${ch}\` · Env: \`${config.phoenixEnv}\``,
                        color: EMBED_COLOR,
                        timestamp: new Date().toISOString(),
                        footer: { text: `${FOOTER_TEXT} boot ping` },
                    }],
                }),
            });
            results[ch] = res.ok;
            if (!res.ok) {
                const text = await res.text().catch(() => '');
                whLog.error({ channel: ch, status: res.status, body: text.slice(0, 200) }, 'boot ping failed');
            }
        } catch (e) {
            results[ch] = false;
            whLog.error({ channel: ch, err: (e as Error).message }, 'boot ping error');
        }
    }
    whLog.info({ results, env: config.phoenixEnv }, 'webhook boot ping complete');
}

export function fire(
    channel: DiscordChannel,
    embed: WebhookEmbed,
    screenshotPath?: string | null,
): void {
    void postWebhook(channel, embed, screenshotPath);
}

export function prettyDetectionType(type: string): string {
    switch (type) {
        case 'anti-debug':       return 'Anti-Debug Trigger';
        case 'vuln-drv':         return 'Vulnerable Driver';
        case 're-tool':          return 'Reverse Engineering Tool';
        case 'overlay':          return 'Overlay Window';
        case 'display-affinity': return 'Display Affinity Overlay';
        case 'nv-streamproof':   return 'NVIDIA StreamProof';
        case 'susp-key':         return 'Suspicious Hotkey';
        case 'proc-access':      return 'Protected Process Access';
        case 'pci-removed':      return 'PCI Device Unplugged';
        case 'hvci-spoof':       return 'HVCI / Core Isolation Spoofed';
        case 'cheat-host':       return 'Cheat';
        case 'cheat-dns':        return 'Cheat DNS Cache Match';
        case 'fivem-sig':        return 'Unsigned FiveM Module';
        case 'insecure-boot':    return 'Insecure Boot Configuration';
        case 'manual-mapped-driver': return 'Manual-Mapped Driver Thread';
        case 'manual-mapped-irp':    return 'Manual-Mapped IRP Handler';
        default:                 return type;
    }
}

export function isBlockingDetection(type: string): boolean {
    return type === 'anti-debug' || type === 'vuln-drv' || type === 're-tool';
}

export function channelForDetection(type: string): DiscordChannel {
    if (type === 'hvci-spoof')   return 'detections-cheats';
    if (type === 'cheat-host')   return 'detections-cheats';
    if (type === 'cheat-dns')    return 'detections-cheats';
    if (type === 'fivem-sig')    return 'detections-cheats';
    if (isBlockingDetection(type)) return 'detections-blocking';
    return 'detections-report';
}

export function detectionAttribution(type: string): string | null {
    switch (type) {
        case 'hvci-spoof':
            return 'This user is very likely running the **ecstasy.zip** cheat.';
        case 'insecure-boot':
            return 'This user attempted to launch PhoenixAC while their Windows boot configuration is in an insecure state. See the `Reason` field below for the specific setting.';
        default:
            return null;
    }
}
