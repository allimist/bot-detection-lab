import type { FingerprintComponents, UaClientHints } from '@bdl/scoring';
import { attempt, hash, nav, withTimeout } from './util.ts';

function drawCanvas(): string | null {
  const c = document.createElement('canvas');
  c.width = 260;
  c.height = 64;
  const x = c.getContext('2d');
  if (!x) return null;
  const text = 'Bot check \u{1F916} <canvas> 1.0 éßæ';
  x.textBaseline = 'top';
  x.font = '15px Arial';
  x.fillStyle = '#f60';
  x.fillRect(130, 1, 62, 20);
  x.fillStyle = '#069';
  x.fillText(text, 2, 15);
  x.fillStyle = 'rgba(102, 204, 0, 0.7)';
  x.fillText(text, 4, 17);
  x.globalCompositeOperation = 'multiply';
  for (const [color, cx] of [['#f2f', 40], ['#2ff', 80], ['#ff2', 60]] as const) {
    x.fillStyle = color;
    x.beginPath();
    x.arc(cx, 40, 22, 0, Math.PI * 2, true);
    x.closePath();
    x.fill();
  }
  return c.toDataURL();
}

function canvas(): { canvas: string | null; canvasNoise: boolean } {
  const a = attempt(drawCanvas, null);
  if (!a) return { canvas: null, canvasNoise: false };
  const b = attempt(drawCanvas, null);
  return { canvas: hash(a), canvasNoise: a !== b };
}

export function webglInfo(gl: WebGLRenderingContext | WebGL2RenderingContext | null) {
  if (!gl) return { vendor: null, renderer: null, params: '' };
  const ext = gl.getExtension('WEBGL_debug_renderer_info');
  const vendor = String(gl.getParameter(ext ? ext.UNMASKED_VENDOR_WEBGL : gl.VENDOR));
  const renderer = String(gl.getParameter(ext ? ext.UNMASKED_RENDERER_WEBGL : gl.RENDERER));
  const keys = [
    gl.MAX_TEXTURE_SIZE, gl.MAX_RENDERBUFFER_SIZE, gl.MAX_VIEWPORT_DIMS, gl.MAX_VERTEX_ATTRIBS,
    gl.MAX_VERTEX_UNIFORM_VECTORS, gl.MAX_FRAGMENT_UNIFORM_VECTORS, gl.MAX_COMBINED_TEXTURE_IMAGE_UNITS,
    gl.ALIASED_LINE_WIDTH_RANGE, gl.ALIASED_POINT_SIZE_RANGE, gl.SHADING_LANGUAGE_VERSION, gl.VERSION,
  ];
  const params = keys.map((k) => String(gl.getParameter(k))).join('|') + '|' + (gl.getSupportedExtensions() ?? []).join(',');
  return { vendor, renderer, params };
}

function webgl() {
  return attempt(() => {
    const c = document.createElement('canvas');
    const info = webglInfo(c.getContext('webgl') as WebGLRenderingContext | null);
    return { webglVendor: info.vendor, webglRenderer: info.renderer, webglHash: info.params ? hash(info.params) : null };
  }, { webglVendor: null, webglRenderer: null, webglHash: null });
}

async function audio(): Promise<string | null> {
  const Ctx = window.OfflineAudioContext ?? (window as unknown as { webkitOfflineAudioContext?: typeof OfflineAudioContext }).webkitOfflineAudioContext;
  if (!Ctx) return null;
  const ctx = new Ctx(1, 5000, 44100);
  const osc = ctx.createOscillator();
  osc.type = 'triangle';
  osc.frequency.value = 10000;
  const comp = ctx.createDynamicsCompressor();
  comp.threshold.value = -50;
  comp.knee.value = 40;
  comp.ratio.value = 12;
  comp.attack.value = 0;
  comp.release.value = 0.25;
  osc.connect(comp);
  comp.connect(ctx.destination);
  osc.start(0);
  const buf = await ctx.startRendering();
  const data = buf.getChannelData(0);
  let sum = 0;
  for (let i = 4500; i < 5000; i++) sum += Math.abs(data[i]!);
  return hash(sum.toString());
}

const FONTS = [
  'Arial', 'Arial Black', 'Arial Narrow', 'Calibri', 'Cambria', 'Candara', 'Comic Sans MS', 'Consolas', 'Constantia',
  'Corbel', 'Courier New', 'Franklin Gothic Medium', 'Gabriola', 'Georgia', 'Impact', 'Lucida Console', 'Lucida Sans Unicode',
  'Microsoft Sans Serif', 'Palatino Linotype', 'Segoe Print', 'Segoe Script', 'Segoe UI', 'Segoe UI Emoji', 'Sylfaen',
  'Tahoma', 'Times New Roman', 'Trebuchet MS', 'Verdana', 'Webdings', 'Wingdings',
  'American Typewriter', 'Avenir', 'Avenir Next', 'Baskerville', 'Chalkboard', 'Futura', 'Geneva', 'Gill Sans',
  'Helvetica', 'Helvetica Neue', 'Hoefler Text', 'Lucida Grande', 'Menlo', 'Monaco', 'Optima', 'SF Pro', 'Skia', 'Apple Color Emoji',
  'DejaVu Sans', 'DejaVu Serif', 'Liberation Mono', 'Liberation Sans', 'Noto Color Emoji', 'Noto Sans', 'Ubuntu', 'Cantarell',
  'Roboto', 'Droid Sans', 'Open Sans', 'Source Code Pro', 'Fira Sans', 'Inter', 'Lato', 'Montserrat',
];

function fonts(): string[] {
  return attempt(() => {
    const x = document.createElement('canvas').getContext('2d');
    if (!x) return [];
    const sample = 'mmmmmmmmmmlli WwQq@#\u{1F600}';
    const bases = ['monospace', 'sans-serif', 'serif'];
    const width = (font: string) => {
      x.font = `72px ${font}`;
      const m = x.measureText(sample);
      return `${m.width}|${m.actualBoundingBoxAscent}|${m.actualBoundingBoxDescent}`;
    };
    const baseWidths = bases.map(width);
    return FONTS.filter((f) => bases.some((b, i) => width(`"${f}", ${b}`) !== baseWidths[i]));
  }, []);
}

function math(): string {
  const values = [
    Math.tan(-1e300), Math.acosh(1e300), Math.sinh(1), Math.expm1(1), Math.cbrt(100),
    Math.log1p(10), Math.atanh(0.5), Math.cos(21 * Math.LN2), Math.exp(-1e-300 * 1e300 + 1),
  ];
  return hash(values.join(','));
}

export async function uaHints(): Promise<UaClientHints | null> {
  const d = nav.userAgentData;
  if (!d) return null;
  const base: UaClientHints = { brands: d.brands.map((b) => b.brand), mobile: d.mobile, platform: d.platform };
  const high = await withTimeout(() => d.getHighEntropyValues(['platformVersion', 'architecture', 'model', 'uaFullVersion']), 800, {} as Record<string, unknown>);
  return {
    ...base,
    platformVersion: high.platformVersion as string | undefined,
    architecture: high.architecture as string | undefined,
    model: high.model as string | undefined,
    fullVersion: high.uaFullVersion as string | undefined,
  };
}

export async function fingerprint(): Promise<FingerprintComponents> {
  const audioHash = withTimeout(audio, 1500, null);
  const intl = attempt(() => Intl.DateTimeFormat().resolvedOptions().timeZone, '');
  return {
    ...canvas(),
    ...webgl(),
    audio: await audioHash,
    fonts: fonts(),
    screen: `${screen.width}x${screen.height}x${screen.colorDepth}@${window.devicePixelRatio}`,
    hardwareConcurrency: nav.hardwareConcurrency ?? null,
    deviceMemory: nav.deviceMemory ?? null,
    timezone: intl,
    timezoneOffset: new Date().getTimezoneOffset(),
    languages: [...(nav.languages ?? [])],
    platform: nav.platform ?? '',
    touchPoints: nav.maxTouchPoints ?? 0,
    math: math(),
  };
}
