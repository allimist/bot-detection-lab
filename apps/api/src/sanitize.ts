// The collector runs on the client, so anything can arrive. Coerce it into the expected shape
// (wrong types become defaults) so the rules never crash on hostile input.
import type { BehaviorSignals, ClientSignals } from '@bdl/scoring';

type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : {});
const str = (v: unknown, max = 512): string => (typeof v === 'string' ? v.slice(0, max) : '');
const strOrNull = (v: unknown, max = 512): string | null => (typeof v === 'string' ? v.slice(0, max) : null);
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const int = (v: unknown): number => Math.max(0, Math.round(num(v) ?? 0));
const bool = (v: unknown): boolean => v === true;
const boolOrNull = (v: unknown): boolean | null => (typeof v === 'boolean' ? v : null);
const strs = (v: unknown, max = 100): string[] => (Array.isArray(v) ? v.filter((x) => typeof x === 'string').slice(0, max).map((x) => (x as string).slice(0, 200)) : []);

export function sanitizeBehavior(v: unknown): BehaviorSignals | null {
  if (!v || typeof v !== 'object') return null;
  const b = obj(v);
  return {
    durationMs: int(b.durationMs),
    mouseMoves: int(b.mouseMoves),
    clicks: int(b.clicks),
    keys: int(b.keys),
    scrolls: int(b.scrolls),
    untrustedEvents: int(b.untrustedEvents),
    straightness: num(b.straightness),
    speedVariance: num(b.speedVariance),
    keyIntervalStdMs: num(b.keyIntervalStdMs),
    clicksWithoutMove: int(b.clicksWithoutMove),
    firstInteractionMs: num(b.firstInteractionMs),
  };
}

export function sanitizeClient(v: unknown): ClientSignals | null {
  if (!v || typeof v !== 'object') return null;
  const c = obj(v);
  const f = obj(c.fingerprint);
  const a = obj(c.automation);
  const l = obj(c.lies);
  const r = obj(c.webrtc);
  const h = c.uaHints ? obj(c.uaHints) : null;
  const engine = ['blink', 'gecko', 'webkit'].includes(l.engine as string) ? (l.engine as ClientSignals['lies']['engine']) : 'unknown';
  const outer = Array.isArray(a.outerSize) ? a.outerSize : [];
  return {
    version: int(c.version),
    userAgent: str(c.userAgent, 1024),
    uaHints: h && {
      brands: strs(h.brands, 10),
      mobile: bool(h.mobile),
      platform: str(h.platform, 64),
      platformVersion: strOrNull(h.platformVersion, 64) ?? undefined,
      architecture: strOrNull(h.architecture, 64) ?? undefined,
      model: strOrNull(h.model, 64) ?? undefined,
      fullVersion: strOrNull(h.fullVersion, 64) ?? undefined,
    },
    fingerprint: {
      canvas: strOrNull(f.canvas, 64),
      canvasNoise: bool(f.canvasNoise),
      webglVendor: strOrNull(f.webglVendor, 256),
      webglRenderer: strOrNull(f.webglRenderer, 256),
      webglHash: strOrNull(f.webglHash, 64),
      audio: strOrNull(f.audio, 64),
      fonts: strs(f.fonts, 200),
      screen: str(f.screen, 64),
      hardwareConcurrency: num(f.hardwareConcurrency),
      deviceMemory: num(f.deviceMemory),
      timezone: str(f.timezone, 64),
      timezoneOffset: num(f.timezoneOffset) ?? 0,
      languages: strs(f.languages, 20),
      platform: str(f.platform, 64),
      touchPoints: int(f.touchPoints),
      math: str(f.math, 64),
    },
    automation: {
      webdriver: boolOrNull(a.webdriver),
      webdriverInNavigator: a.webdriverInNavigator !== false,
      automationGlobals: strs(a.automationGlobals, 30),
      cdpDetected: bool(a.cdpDetected),
      headlessUa: bool(a.headlessUa),
      pluginsLength: int(a.pluginsLength),
      pdfViewerEnabled: boolOrNull(a.pdfViewerEnabled),
      outerSize: [int(outer[0]), int(outer[1])],
      pageHidden: bool(a.pageHidden),
      notificationPermission: strOrNull(a.notificationPermission, 16),
      permissionsNotifications: strOrNull(a.permissionsNotifications, 16),
      chromeObject: bool(a.chromeObject),
      chromeKeys: strs(a.chromeKeys, 20),
      mediaDevices: num(a.mediaDevices),
      voices: num(a.voices),
      connectionRtt: num(a.connectionRtt),
    },
    lies: {
      patchedFunctions: strs(l.patchedFunctions, 50),
      ownPropertyOverrides: strs(l.ownPropertyOverrides, 20),
      iframeMismatch: strs(l.iframeMismatch, 20),
      workerMismatch: strs(l.workerMismatch, 20),
      engine,
    },
    webrtc: {
      supported: bool(r.supported),
      publicIps: strs(r.publicIps, 5),
      localIps: strs(r.localIps, 5),
      ...(typeof r.error === 'string' ? { error: r.error.slice(0, 200) } : {}),
    },
    behavior: sanitizeBehavior(c.behavior),
    collectMs: int(c.collectMs),
  };
}
