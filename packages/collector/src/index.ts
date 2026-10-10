import type { CheckResponse, ClientSignals } from '@bdl/scoring';
import { automation } from './automation.ts';
import { BehaviorTracker } from './behavior.ts';
import { fingerprint, uaHints } from './fingerprint.ts';
import { lies } from './lies.ts';
import { attempt } from './util.ts';
import { webrtc } from './webrtc.ts';

export { BehaviorTracker } from './behavior.ts';
export const COLLECTOR_VERSION = 1;

export interface CollectOptions {
  stun?: string;          // STUN server for the WebRTC check; '' turns it off
  tracker?: BehaviorTracker;
}

/** Run every client-side check. Takes ~1-3 s, mostly waiting for STUN and the audio render. */
export async function collect(opts: CollectOptions = {}): Promise<ClientSignals> {
  const t0 = performance.now();
  const rtc = opts.stun === '' ? Promise.resolve({ supported: false, publicIps: [], localIps: [], error: 'Disabled by the site.' }) : webrtc(opts.stun);
  const [fp, hints, auto] = await Promise.all([fingerprint(), uaHints(), automation()]);
  const lie = await lies(fp.webglRenderer);
  return {
    version: COLLECTOR_VERSION,
    userAgent: navigator.userAgent,
    uaHints: hints,
    fingerprint: fp,
    automation: auto,
    lies: lie,
    webrtc: await rtc,
    behavior: opts.tracker?.summary() ?? null,
    collectMs: Math.round(performance.now() - t0),
    clientTime: Date.now(),
    locale: attempt(() => Intl.DateTimeFormat().resolvedOptions().locale, ''),
  };
}

export interface BotCheckOptions {
  endpoint?: string; // origin of the bot-detection-lab API, '' = same origin
  site?: string;     // free-form label stored with the visit (which site / page embedded the script)
  stun?: string;
}

/** Collects signals, posts them to the API and keeps watching behaviour for a follow-up score. */
export class BotCheck {
  readonly tracker = new BehaviorTracker();
  visitId: string | null = null;
  last: CheckResponse | null = null;

  constructor(private opts: BotCheckOptions = {}) {}

  private url(path: string) {
    return `${(this.opts.endpoint ?? '').replace(/\/$/, '')}${path}`;
  }

  async run(): Promise<CheckResponse> {
    const signals = await collect({ stun: this.opts.stun, tracker: this.tracker });
    signals.clientTime = Date.now();
    const res = await fetch(this.url('/api/collect'), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ signals, site: this.opts.site ?? location.hostname }),
      credentials: 'omit',
    });
    if (!res.ok) throw new Error(`bot check failed: HTTP ${res.status}`);
    this.last = (await res.json()) as CheckResponse;
    this.visitId = this.last.visitId;
    return this.last;
  }

  /** Re-score with the behaviour recorded so far. */
  async sendBehavior(): Promise<CheckResponse | null> {
    if (!this.visitId) return null;
    const res = await fetch(this.url(`/api/collect/${this.visitId}/behavior`), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ behavior: this.tracker.summary() }),
      credentials: 'omit',
    });
    if (!res.ok) return null;
    this.last = (await res.json()) as CheckResponse;
    return this.last;
  }

  /** Fire-and-forget version for page unload. */
  beaconBehavior() {
    if (!this.visitId || !this.tracker.interacted) return;
    navigator.sendBeacon?.(this.url(`/api/collect/${this.visitId}/behavior`), JSON.stringify({ behavior: this.tracker.summary() }));
  }
}
