// Tiny user-agent parser: only the parts the rules compare against other signals.

export type Browser = 'chrome' | 'edge' | 'opera' | 'samsung' | 'firefox' | 'safari' | 'other';
export type Os = 'windows' | 'mac' | 'linux' | 'android' | 'ios' | 'chromeos' | 'other';
export type Engine = 'blink' | 'gecko' | 'webkit' | 'unknown';

export interface ParsedUa {
  browser: Browser;
  engine: Engine;
  os: Os;
  version: number | null; // major version of the browser
  mobile: boolean;
  isBrowser: boolean;     // looks like a real browser at all ("Mozilla/5.0 ...")
  tool: string | null;    // curl, python-requests, Go-http-client, ... when it says so itself
}

const TOOL_PATTERNS: [RegExp, string][] = [
  [/^curl\//i, 'curl'],
  [/^wget\//i, 'wget'],
  [/python-requests/i, 'python-requests'],
  [/python-urllib|^python\//i, 'python-urllib'],
  [/aiohttp/i, 'aiohttp'],
  [/httpx/i, 'httpx'],
  [/scrapy/i, 'scrapy'],
  [/go-http-client/i, 'Go-http-client'],
  [/^node|undici|node-fetch/i, 'node'],
  [/axios/i, 'axios'],
  [/okhttp/i, 'okhttp'],
  [/java\//i, 'java'],
  [/libwww-perl/i, 'perl'],
  [/postmanruntime/i, 'postman'],
  [/insomnia/i, 'insomnia'],
  [/headlesschrome/i, 'HeadlessChrome'],
  [/phantomjs/i, 'PhantomJS'],
  [/bot\b|crawler|spider|slurp/i, 'crawler'],
];

export function parseUa(ua: string | null | undefined): ParsedUa {
  const s = ua ?? '';
  const tool = TOOL_PATTERNS.find(([re]) => re.test(s))?.[1] ?? null;

  let os: Os = 'other';
  if (/windows nt/i.test(s)) os = 'windows';
  else if (/iphone|ipad|ipod/i.test(s)) os = 'ios';
  else if (/android/i.test(s)) os = 'android';
  else if (/cros/i.test(s)) os = 'chromeos';
  else if (/mac os x|macintosh/i.test(s)) os = 'mac';
  else if (/linux|x11/i.test(s)) os = 'linux';

  let browser: Browser = 'other';
  let version: number | null = null;
  const m = (re: RegExp) => {
    const r = re.exec(s);
    return r ? Number(r[1]) : null;
  };
  if (/edg(e|a|ios)?\//i.test(s)) { browser = 'edge'; version = m(/edg(?:e|a|ios)?\/(\d+)/i); }
  else if (/opr\/|opera/i.test(s)) { browser = 'opera'; version = m(/opr\/(\d+)/i); }
  else if (/samsungbrowser/i.test(s)) { browser = 'samsung'; version = m(/samsungbrowser\/(\d+)/i); }
  else if (/firefox\/|fxios\//i.test(s)) { browser = 'firefox'; version = m(/(?:firefox|fxios)\/(\d+)/i); }
  else if (/chrome\/|crios\/|headlesschrome\//i.test(s)) { browser = 'chrome'; version = m(/(?:headlesschrome|chrome|crios)\/(\d+)/i); }
  else if (/safari\//i.test(s) && /version\//i.test(s)) { browser = 'safari'; version = m(/version\/(\d+)/i); }

  // Every browser on iOS is WebKit underneath, whatever it calls itself.
  let engine: Engine = 'unknown';
  if (os === 'ios') engine = 'webkit';
  else if (browser === 'firefox') engine = 'gecko';
  else if (browser === 'safari') engine = 'webkit';
  else if (browser !== 'other') engine = 'blink';

  return {
    browser,
    engine,
    os,
    version,
    mobile: /mobile|android|iphone|ipod/i.test(s),
    isBrowser: /^Mozilla\/5\.0 \(/.test(s) && browser !== 'other' && (tool === null || tool === 'HeadlessChrome'),
    tool,
  };
}

/** Which OS does navigator.platform / UA-CH platform name? */
export function osFromPlatform(platform: string | null | undefined): Os | null {
  const p = (platform ?? '').toLowerCase();
  if (!p) return null;
  if (p.startsWith('win')) return 'windows';
  if (p === 'macintel' || p === 'macos' || p.startsWith('mac')) return 'mac';
  if (p === 'iphone' || p === 'ipad' || p === 'ipod' || p === 'ios') return 'ios';
  if (p === 'android') return 'android';
  if (p.includes('cros') || p === 'chrome os' || p === 'chromium os') return 'chromeos';
  if (p.startsWith('linux')) return 'linux';
  return null;
}

/** Is the claimed OS compatible with what navigator.platform says? */
export function platformMatches(uaOs: Os, platformOs: Os | null): boolean {
  if (platformOs === null || uaOs === 'other') return true;
  if (uaOs === platformOs) return true;
  if (uaOs === 'android' && platformOs === 'linux') return true; // navigator.platform is "Linux armv8l" on Android
  if (uaOs === 'chromeos' && platformOs === 'linux') return true;
  if (uaOs === 'ios' && platformOs === 'mac') return true;       // iPadOS asks for desktop sites as MacIntel
  if (uaOs === 'mac' && platformOs === 'ios') return true;       // ...and the other way round
  return false;
}
