import type { ClientSignals, IpIntel, ServerSignals, Signals } from '../src/index.ts';

export const CHROME_UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';

export const homeIp = (over: Partial<IpIntel> = {}): IpIntel => ({
  ip: '84.229.10.20', isPrivate: false, country: 'IL', city: 'Tel Aviv', timezone: null,
  asn: 1680, asOrg: 'Cellcom', datacenter: false, vpnRange: false, tor: false, ...over,
});

export function chromeClient(over: Partial<ClientSignals> = {}): ClientSignals {
  return {
    version: 1,
    userAgent: CHROME_UA,
    uaHints: { brands: ['Google Chrome', 'Chromium', 'Not=A?Brand'], mobile: false, platform: 'macOS', platformVersion: '15.1.0', architecture: 'arm', model: '', fullVersion: '141.0.7390.55' },
    fingerprint: {
      canvas: 'c1', canvasNoise: false, webglVendor: 'Google Inc. (Apple)', webglRenderer: 'ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)',
      webglHash: 'w1', audio: 'a1', fonts: ['Arial', 'Helvetica', 'Menlo'], screen: '1728x1117x30@2',
      hardwareConcurrency: 8, deviceMemory: 8, timezone: 'Asia/Jerusalem', timezoneOffset: tzOffset('Asia/Jerusalem'),
      languages: ['en-US', 'he'], platform: 'MacIntel', touchPoints: 0, math: 'm1',
    },
    automation: {
      webdriver: false, webdriverInNavigator: true, automationGlobals: [], cdpDetected: false, headlessUa: false,
      pluginsLength: 5, pdfViewerEnabled: true, outerSize: [1728, 1050], pageHidden: false, notificationPermission: 'default',
      permissionsNotifications: 'prompt', chromeObject: true, chromeKeys: ['loadTimes', 'csi', 'app'],
      mediaDevices: 3, voices: 170, connectionRtt: 50,
    },
    lies: { patchedFunctions: [], ownPropertyOverrides: [], iframeMismatch: [], workerMismatch: [], engine: 'blink' },
    webrtc: { supported: true, publicIps: ['84.229.10.20'], localIps: [] },
    behavior: null,
    collectMs: 120,
    ...over,
  };
}

export function chromeServer(over: Partial<ServerSignals> = {}): ServerSignals {
  return {
    ip: homeIp(),
    webrtcIp: null,
    headers: {
      userAgent: CHROME_UA, acceptLanguage: 'en-US,en;q=0.9,he;q=0.8', accept: '*/*',
      secChUa: '"Google Chrome";v="141", "Chromium";v="141"', secChUaPlatform: '"macOS"',
      secFetchSite: 'same-origin', secFetchMode: 'cors', secure: true, proxyHeaders: [], order: [],
    },
    tls: { ja4: 't13d1516h2_8daaf6152771_d8a2da3f94cd', alpn: 'h2', ciphers: 15, extensions: 16, grease: true, cipherHash: '8daaf6152771' },
    velocity: { ipsForFingerprint24h: 1, fingerprintsForIp1h: 1, visitsForFingerprint10m: 1 },
    tzCountry: 'IL',
    ...over,
  };
}

export const human = (): Signals => ({ client: chromeClient(), server: chromeServer() });

function tzOffset(tz: string): number {
  const name = new Intl.DateTimeFormat('en-US', { timeZone: tz, timeZoneName: 'longOffset' })
    .formatToParts(new Date()).find((p) => p.type === 'timeZoneName')!.value;
  const m = /GMT([+-])(\d{2}):(\d{2})/.exec(name);
  if (!m) return 0;
  const minutes = Number(m[2]) * 60 + Number(m[3]);
  return m[1] === '+' ? -minutes : minutes;
}
