// Everything the scoring engine looks at. The collector fills `ClientSignals` in the browser,
// the API fills `ServerSignals` from the request, the IP datasets and its own visit history.

export interface FingerprintComponents {
  canvas: string | null;          // hash of a drawn canvas
  canvasNoise: boolean;           // two identical draws gave different pixels (Brave / Firefox RFP)
  webglVendor: string | null;     // UNMASKED_VENDOR_WEBGL
  webglRenderer: string | null;   // UNMASKED_RENDERER_WEBGL
  webglHash: string | null;       // hash of WebGL parameters + extensions
  audio: string | null;           // hash of an OfflineAudioContext render
  fonts: string[];                // installed fonts found by measuring text
  screen: string;                 // "1920x1080x24@2"
  hardwareConcurrency: number | null;
  deviceMemory: number | null;
  timezone: string;
  timezoneOffset: number;         // minutes, as Date#getTimezoneOffset
  languages: string[];
  platform: string;
  touchPoints: number;
  math: string;                   // hash of a few Math results that differ per engine
}

export interface UaClientHints {
  brands: string[];
  mobile: boolean;
  platform: string;
  platformVersion?: string;
  architecture?: string;
  model?: string;
  fullVersion?: string;
}

export interface AutomationSignals {
  webdriver: boolean | null;          // navigator.webdriver
  webdriverInNavigator: boolean;      // real Chromium has the property (false); some stealth patches delete it
  automationGlobals: string[];        // cdc_*, __playwright*, _phantom, callSelenium, ...
  cdpDetected: boolean;               // console serialised an Error -> DevTools protocol Runtime is enabled
  headlessUa: boolean;                // "HeadlessChrome" in the user agent
  pluginsLength: number;
  pdfViewerEnabled: boolean | null;
  outerSize: [number, number];        // outerWidth, outerHeight (0 in some headless setups)
  pageHidden: boolean;                // loaded in a background tab: outer size is 0 there too
  notificationPermission: string | null;
  permissionsNotifications: string | null; // permissions.query({name:'notifications'})
  chromeObject: boolean;              // window.chrome exists
  chromeKeys: string[];
  mediaDevices: number | null;        // count of enumerateDevices()
  voices: number | null;              // speechSynthesis voices
  connectionRtt: number | null;
}

export interface LieSignals {
  patchedFunctions: string[];   // native APIs whose toString/shape says they were replaced in JS
  ownPropertyOverrides: string[]; // navigator props defined on the instance instead of the prototype
  iframeMismatch: string[];     // fields that differ between the page and a fresh iframe
  workerMismatch: string[];     // fields that differ between the page and a Web Worker
  engine: 'blink' | 'gecko' | 'webkit' | 'unknown'; // engine detected from features, not from the UA
}

export interface WebRtcSignals {
  supported: boolean;
  publicIps: string[];   // srflx candidates from STUN
  localIps: string[];    // host candidates that are real IPs (not mDNS .local)
  error?: string;
}

export interface BehaviorSignals {
  durationMs: number;
  mouseMoves: number;
  clicks: number;
  keys: number;
  scrolls: number;
  untrustedEvents: number;      // events with isTrusted === false
  straightness: number | null;  // 0..1, share of mouse segments on a perfectly straight line
  speedVariance: number | null; // coefficient of variation of mouse speed
  keyIntervalStdMs: number | null;
  clicksWithoutMove: number;    // clicks that had no mouse movement before them
  firstInteractionMs: number | null;
}

export interface ClientSignals {
  version: number;
  userAgent: string;
  uaHints: UaClientHints | null;
  fingerprint: FingerprintComponents;
  automation: AutomationSignals;
  lies: LieSignals;
  webrtc: WebRtcSignals;
  behavior: BehaviorSignals | null;
  collectMs: number;
}

export interface IpIntel {
  ip: string;
  isPrivate: boolean;
  country: string | null;
  city: string | null;
  timezone: string | null;   // from the geo database when it has one
  asn: number | null;
  asOrg: string | null;
  datacenter: boolean;       // ASN or range is a hosting / cloud provider
  vpnRange: boolean;         // range is on a known VPN list
  tor: boolean;              // Tor exit node
}

export interface TlsSignals {
  ja4: string;
  alpn: string;          // first ALPN value or ""
  ciphers: number;
  extensions: number;
  grease: boolean;       // GREASE values present (Chromium, Safari)
  cipherHash: string;    // JA4_b
}

export interface HeaderSignals {
  userAgent: string | null;
  acceptLanguage: string | null;
  accept: string | null;
  secChUa: string | null;
  secChUaPlatform: string | null;
  secFetchSite: string | null;
  secFetchMode: string | null;
  secure: boolean;       // request came over https or to localhost (client hints only sent there)
  proxyHeaders: string[]; // via, forwarded, x-forwarded-for, ... (only when we don't sit behind our own proxy)
  order: string[];       // header names in the order they arrived
}

export interface VelocitySignals {
  ipsForFingerprint24h: number;     // distinct IPs that sent this fingerprint
  fingerprintsForIp1h: number;      // distinct fingerprints from this IP
  visitsForFingerprint10m: number;
}

export interface ServerSignals {
  ip: IpIntel;
  webrtcIp: IpIntel | null;   // intel for the first WebRTC public IP when it differs from `ip`
  headers: HeaderSignals;
  tls: TlsSignals | null;
  velocity: VelocitySignals | null;
  tzCountry: string | null;   // country of the browser's IANA timezone (from tzdb zone.tab)
}

export interface Signals {
  client: ClientSignals | null; // null when no JavaScript ran (curl, scrapers, /api/inspect)
  server: ServerSignals;
}

export type Category = 'network' | 'automation' | 'consistency' | 'fingerprint' | 'behavior' | 'tls';
export type Status = 'pass' | 'info' | 'warn' | 'fail';
export type Flag = 'vpn' | 'proxy' | 'tor' | 'datacenter' | 'automation' | 'tampering' | 'headless' | 'noJs';

export interface Finding {
  id: string;
  category: Category;
  status: Status;
  points: number;    // added to the bot risk score
  title: string;
  detail: string;
  flags?: Flag[];
}

export type Verdict = 'human' | 'suspicious' | 'bot';

export interface ScoreResult {
  score: number;       // bot risk 0..100
  verdict: Verdict;
  flags: Flag[];
  findings: Finding[];
}

/** What /api/collect, /api/check/:id and /api/inspect return. */
export interface CheckResponse {
  visitId: string;
  fingerprintId: string | null;
  createdAt: string;
  ip: IpIntel;
  webrtcIp: IpIntel | null;
  tls: TlsSignals | null;
  result: ScoreResult;
  rarity?: Record<string, { count: number; total: number }>; // how many stored visits share each fingerprint component
}
