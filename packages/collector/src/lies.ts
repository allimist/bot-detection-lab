import type { LieSignals } from '@bdl/scoring';
import { webglInfo } from './fingerprint.ts';
import { attempt, nav, withTimeout } from './util.ts';

type Target = [label: string, get: () => unknown, name: string];

const proto = (o: object | undefined, key: string, kind: 'get' | 'value' = 'value') => () => {
  const d = o ? Object.getOwnPropertyDescriptor(o, key) : undefined;
  return kind === 'get' ? d?.get : d?.value;
};

// Native APIs that spoofing tools like to replace. [label, how to read it, the name its source must show]
const g = globalThis as unknown as Record<string, { prototype: object } | undefined>;
const TARGETS: Target[] = [
  ['HTMLCanvasElement.toDataURL', proto(g.HTMLCanvasElement?.prototype, 'toDataURL'), 'toDataURL'],
  ['HTMLCanvasElement.getContext', proto(g.HTMLCanvasElement?.prototype, 'getContext'), 'getContext'],
  ['CanvasRenderingContext2D.getImageData', proto(g.CanvasRenderingContext2D?.prototype, 'getImageData'), 'getImageData'],
  ['CanvasRenderingContext2D.measureText', proto(g.CanvasRenderingContext2D?.prototype, 'measureText'), 'measureText'],
  ['WebGLRenderingContext.getParameter', proto(g.WebGLRenderingContext?.prototype, 'getParameter'), 'getParameter'],
  ['WebGL2RenderingContext.getParameter', proto(g.WebGL2RenderingContext?.prototype, 'getParameter'), 'getParameter'],
  ['AudioBuffer.getChannelData', proto(g.AudioBuffer?.prototype, 'getChannelData'), 'getChannelData'],
  ['Navigator.userAgent', proto(g.Navigator?.prototype, 'userAgent', 'get'), 'userAgent'],
  ['Navigator.platform', proto(g.Navigator?.prototype, 'platform', 'get'), 'platform'],
  ['Navigator.languages', proto(g.Navigator?.prototype, 'languages', 'get'), 'languages'],
  ['Navigator.hardwareConcurrency', proto(g.Navigator?.prototype, 'hardwareConcurrency', 'get'), 'hardwareConcurrency'],
  ['Navigator.deviceMemory', proto(g.Navigator?.prototype, 'deviceMemory', 'get'), 'deviceMemory'],
  ['Navigator.webdriver', proto(g.Navigator?.prototype, 'webdriver', 'get'), 'webdriver'],
  ['Navigator.plugins', proto(g.Navigator?.prototype, 'plugins', 'get'), 'plugins'],
  ['Screen.width', proto(g.Screen?.prototype, 'width', 'get'), 'width'],
  ['Screen.height', proto(g.Screen?.prototype, 'height', 'get'), 'height'],
  ['Permissions.query', proto(g.Permissions?.prototype, 'query'), 'query'],
  ['MediaDevices.enumerateDevices', proto(g.MediaDevices?.prototype, 'enumerateDevices'), 'enumerateDevices'],
  ['Date.getTimezoneOffset', proto(Date.prototype, 'getTimezoneOffset'), 'getTimezoneOffset'],
  ['Intl.DateTimeFormat.resolvedOptions', proto(Intl.DateTimeFormat.prototype, 'resolvedOptions'), 'resolvedOptions'],
  ['Function.toString', proto(Function.prototype, 'toString'), 'toString'],
];

/**
 * A native function's source is "function name() { [native code] }", it has no `prototype`,
 * and it can't be called with `new`. Replacements written in JS usually break one of these.
 * `foreignToString` comes from a fresh iframe, so patching our Function.prototype.toString doesn't help.
 * A Proxy around a native shows up there as "function () { [native code] }" — the name is gone.
 */
function looksPatched(fn: unknown, name: string, foreignToString: ((this: unknown) => string) | null): boolean {
  if (typeof fn !== 'function') return false;
  const native = new RegExp(`^function (get |set )?${name}\\(\\) \\{\\s*\\[native code\\]\\s*\\}$`);
  const own = attempt(() => Function.prototype.toString.call(fn), '');
  if (!native.test(own)) return true;
  if (foreignToString) {
    const foreign = attempt(() => foreignToString.call(fn), null);
    if (foreign !== null && !native.test(foreign)) return true;
  }
  if ('prototype' in fn) return true;
  if (Object.prototype.hasOwnProperty.call(fn, 'arguments') || Object.prototype.hasOwnProperty.call(fn, 'caller')) return true;
  let constructed = false;
  attempt(() => {
    new (fn as unknown as new () => unknown)();
    constructed = true;
  }, undefined);
  return constructed;
}

const NAV_PROPS = ['userAgent', 'platform', 'languages', 'hardwareConcurrency', 'deviceMemory', 'webdriver', 'plugins', 'vendor', 'maxTouchPoints'];

function ownPropertyOverrides(): string[] {
  return NAV_PROPS.filter((p) => Object.prototype.hasOwnProperty.call(navigator, p));
}

interface Snapshot {
  userAgent: string;
  platform: string;
  languages: string;
  hardwareConcurrency: number | null;
  deviceMemory: number | null;
  webdriver: boolean | null;
  timezone: string;
  webglRenderer: string | null;
}

function snapshot(n: typeof nav, i: typeof Intl, renderer: string | null): Snapshot {
  return {
    userAgent: n.userAgent,
    platform: n.platform,
    languages: [...(n.languages ?? [])].join(','),
    hardwareConcurrency: n.hardwareConcurrency ?? null,
    deviceMemory: n.deviceMemory ?? null,
    webdriver: n.webdriver ?? null,
    timezone: i.DateTimeFormat().resolvedOptions().timeZone,
    webglRenderer: renderer,
  };
}

function diff(a: Snapshot, b: Partial<Snapshot>): string[] {
  return (Object.keys(b) as (keyof Snapshot)[]).filter((k) => b[k] !== undefined && b[k] !== null && a[k] !== null && b[k] !== a[k]);
}

function openIframe(): HTMLIFrameElement | null {
  return attempt(() => {
    const f = document.createElement('iframe');
    f.style.display = 'none';
    f.setAttribute('aria-hidden', 'true');
    document.body.appendChild(f);
    return f;
  }, null);
}

// The worker reports the same fields from a separate JS realm that page-level spoofing rarely reaches.
const WORKER_SRC = `
let renderer = null;
try {
  const gl = new OffscreenCanvas(1, 1).getContext('webgl');
  if (gl) {
    const ext = gl.getExtension('WEBGL_debug_renderer_info');
    renderer = String(gl.getParameter(ext ? ext.UNMASKED_RENDERER_WEBGL : gl.RENDERER));
  }
} catch (e) {}
postMessage({
  userAgent: navigator.userAgent,
  platform: navigator.platform,
  languages: [...(navigator.languages || [])].join(','),
  hardwareConcurrency: navigator.hardwareConcurrency ?? null,
  deviceMemory: navigator.deviceMemory ?? null,
  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  webglRenderer: renderer,
});`;

function workerSnapshot(): Promise<Partial<Snapshot> | null> {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(new Blob([WORKER_SRC], { type: 'text/javascript' }));
    const w = new Worker(url);
    w.onmessage = (e) => {
      resolve(e.data as Partial<Snapshot>);
      w.terminate();
      URL.revokeObjectURL(url);
    };
    w.onerror = (e) => {
      reject(e);
      w.terminate();
    };
  });
}

/** Which engine runs this script, judged by behaviour rather than by the user agent. */
function engine(): LieSignals['engine'] {
  const stack = attempt(() => new Error('x').stack ?? '', '');
  if (/\n\s+at /.test(stack)) return 'blink';
  if (attempt(() => CSS.supports('-moz-appearance', 'none'), false)) return 'gecko';
  if (/@/.test(stack)) return 'webkit';
  return 'unknown';
}

export async function lies(mainRenderer: string | null): Promise<LieSignals> {
  const frame = openIframe();
  const fw = frame?.contentWindow as (Window & typeof globalThis) | null | undefined;
  const foreignToString = attempt(() => (fw ? (fw.Function.prototype.toString as (this: unknown) => string) : null), null);

  const patchedFunctions = TARGETS.filter(([, get, name]) => looksPatched(attempt(get, undefined), name, foreignToString)).map(([label]) => label);

  const main = snapshot(nav, Intl, mainRenderer);
  const iframeMismatch = fw
    ? attempt(() => {
        const r = webglInfo(fw.document.createElement('canvas').getContext('webgl') as WebGLRenderingContext | null).renderer;
        return diff(main, snapshot(fw.navigator as typeof nav, fw.Intl, r));
      }, [] as string[])
    : [];
  frame?.remove();

  const worker = await withTimeout(workerSnapshot, 1500, null);
  const workerMismatch = worker ? diff(main, worker) : [];

  return { patchedFunctions, ownPropertyOverrides: ownPropertyOverrides(), iframeMismatch, workerMismatch, engine: engine() };
}
