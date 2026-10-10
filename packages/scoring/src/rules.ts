import type { Finding, IpIntel, Signals } from './types.ts';
import { osFromPlatform, parseUa, platformMatches, type ParsedUa } from './ua.ts';

// JA4_b (sorted cipher suites) of every Chromium browser since ~2020 (Chrome, Edge, Opera, Brave, ...).
export const CHROMIUM_CIPHER_HASH = '8daaf6152771';
// JA4_b of current Firefox.
export const FIREFOX_CIPHER_HASH = '5b57614c22b0';

export interface Ctx {
  s: Signals;
  ua: ParsedUa;        // parsed from navigator.userAgent, or from the header when no JS ran
  headerUa: ParsedUa;
  net: IpIntel;        // the IP we judge: the HTTP IP, or the WebRTC IP when HTTP came from a private network
  desktop: boolean;
}

export type Rule = (ctx: Ctx) => Finding | Finding[] | null;

const pass = (id: string, category: Finding['category'], title: string, detail: string): Finding =>
  ({ id, category, status: 'pass', points: 0, title, detail });
const info = (id: string, category: Finding['category'], title: string, detail: string): Finding =>
  ({ id, category, status: 'info', points: 0, title, detail });

const ipLabel = (ip: IpIntel) =>
  [ip.ip, ip.asOrg && `${ip.asOrg}${ip.asn ? ` (AS${ip.asn})` : ''}`, ip.country].filter(Boolean).join(', ');

// ---------------------------------------------------------------- network

const tor: Rule = ({ net }) =>
  net.tor
    ? { id: 'net.tor', category: 'network', status: 'fail', points: 35, flags: ['tor'], title: 'Tor exit node', detail: `${net.ip} is on the Tor Project's list of exit relays.` }
    : null;

const datacenter: Rule = ({ net }) => {
  if (net.isPrivate) return null;
  if (net.datacenter)
    return { id: 'net.datacenter', category: 'network', status: 'fail', points: 30, flags: ['datacenter'], title: 'Datacenter IP', detail: `${ipLabel(net)} is a hosting / cloud network. Real customers browse from home, office or mobile ISPs; scrapers and VPN servers live in datacenters.` };
  return pass('net.datacenter', 'network', 'Residential or mobile network', `${ipLabel(net)} is not a known hosting provider.`);
};

const vpnRange: Rule = ({ net }) =>
  net.vpnRange
    ? { id: 'net.vpn', category: 'network', status: 'warn', points: 20, flags: ['vpn'], title: 'Known VPN range', detail: `${net.ip} is inside a range published as a commercial VPN.` }
    : null;

const webrtcLeak: Rule = ({ s }) => {
  const { ip, webrtcIp } = s.server;
  const rtc = s.client?.webrtc;
  if (!rtc) return null;
  if (!rtc.supported) return info('net.webrtc', 'network', 'WebRTC unavailable', rtc.error ?? 'The browser has no RTCPeerConnection or it is disabled (common with privacy extensions).');
  if (rtc.publicIps.length === 0) return info('net.webrtc', 'network', 'No WebRTC public IP', 'STUN returned no public address (blocked, or WebRTC IP handling is restricted).');
  if (ip.isPrivate) return info('net.webrtc', 'network', 'WebRTC public IP', `You reached the server from a private network (${ip.ip}); STUN says your public IP is ${rtc.publicIps.join(', ')}. The network checks use that one.`);
  if (!rtc.publicIps.includes(ip.ip)) {
    const where = webrtcIp ? ` (${ipLabel(webrtcIp)})` : '';
    return { id: 'net.webrtc', category: 'network', status: 'warn', points: 20, flags: ['vpn', 'proxy'], title: 'WebRTC leaks a different IP', detail: `HTTP came from ${ipLabel(ip)}, but STUN sees ${rtc.publicIps.join(', ')}${where}. The page goes through a proxy or VPN that does not cover UDP.` };
  }
  return pass('net.webrtc', 'network', 'WebRTC IP matches', `STUN and HTTP both see ${ip.ip}.`);
};

const timezoneMatch: Rule = ({ s, net }) => {
  const c = s.client;
  if (!c || net.isPrivate || !net.country || !s.server.tzCountry) return null;
  if (net.timezone && net.timezone === c.fingerprint.timezone) return pass('net.timezone', 'network', 'Timezone matches IP', `${c.fingerprint.timezone} is the timezone of ${net.city ?? net.country}.`);
  if (s.server.tzCountry === net.country) return pass('net.timezone', 'network', 'Timezone matches IP', `${c.fingerprint.timezone} is in ${net.country}, like the IP.`);
  return { id: 'net.timezone', category: 'network', status: 'warn', points: 15, flags: ['vpn'], title: 'Timezone does not match IP country', detail: `The browser clock is set to ${c.fingerprint.timezone} (${s.server.tzCountry}), but the IP is in ${net.country}. Typical of a VPN / proxy exit in another country.` };
};

const languageMatch: Rule = ({ s, net }) => {
  const c = s.client;
  if (!c || !net.country || net.isPrivate) return null;
  const regions = c.fingerprint.languages.map((l) => l.split('-')[1]?.toUpperCase()).filter(Boolean);
  if (regions.length === 0 || regions.includes(net.country)) return null;
  return info('net.language', 'network', 'Language region differs from IP', `Languages ${c.fingerprint.languages.join(', ')} vs IP country ${net.country}. Common for travellers and expats, so it adds no points on its own.`);
};

const proxyHeaders: Rule = ({ s }) =>
  s.server.headers.proxyHeaders.length
    ? { id: 'net.proxy-headers', category: 'network', status: 'warn', points: 15, flags: ['proxy'], title: 'Proxy headers', detail: `The request carries ${s.server.headers.proxyHeaders.join(', ')}: it passed through an HTTP proxy.` }
    : null;

const privateNet: Rule = ({ s, net }) =>
  net.isPrivate
    ? info('net.private', 'network', 'Private network', `The server sees ${s.server.ip.ip} (localhost / LAN) and has no public IP to check. Open the page from the internet, or allow WebRTC, to run the IP checks.`)
    : null;

// ---------------------------------------------------------------- automation

const noJs: Rule = ({ s, headerUa }) => {
  if (s.client) return null;
  const out: Finding[] = [{ id: 'auto.no-js', category: 'automation', status: 'fail', points: 40, flags: ['noJs'], title: 'No JavaScript', detail: 'Only the HTTP request was seen. Browsers run the page script; HTTP libraries and simple scrapers do not.' }];
  if (!s.server.headers.userAgent)
    out.push({ id: 'auto.no-ua', category: 'automation', status: 'fail', points: 40, flags: ['automation'], title: 'No User-Agent', detail: 'Every browser sends a User-Agent header.' });
  else if (headerUa.tool && headerUa.tool !== 'HeadlessChrome')
    out.push({ id: 'auto.tool-ua', category: 'automation', status: 'fail', points: 50, flags: ['automation'], title: `User-Agent says ${headerUa.tool}`, detail: `"${s.server.headers.userAgent}" is an HTTP library or crawler, not a browser.` });
  if (!s.server.headers.acceptLanguage)
    out.push({ id: 'auto.no-accept-language', category: 'automation', status: 'warn', points: 15, title: 'No Accept-Language', detail: 'Browsers always say which languages they prefer.' });
  return out;
};

const webdriver: Rule = ({ s }) => {
  const a = s.client?.automation;
  if (!a) return null;
  if (a.webdriver) return { id: 'auto.webdriver', category: 'automation', status: 'fail', points: 60, flags: ['automation'], title: 'navigator.webdriver is true', detail: 'The browser says it is controlled by WebDriver / CDP automation (Selenium, Puppeteer, Playwright).' };
  return pass('auto.webdriver', 'automation', 'navigator.webdriver is false', 'The browser does not announce automation.');
};

const globals: Rule = ({ s }) => {
  const g = s.client?.automation.automationGlobals ?? [];
  return g.length
    ? { id: 'auto.globals', category: 'automation', status: 'fail', points: 60, flags: ['automation'], title: 'Automation framework found', detail: `Globals left by a driver: ${g.join(', ')}.` }
    : null;
};

const headlessUa: Rule = ({ s, headerUa }) =>
  s.client?.automation.headlessUa || headerUa.tool === 'HeadlessChrome'
    ? { id: 'auto.headless-ua', category: 'automation', status: 'fail', points: 60, flags: ['headless', 'automation'], title: 'HeadlessChrome', detail: 'The user agent itself says headless Chrome.' }
    : null;

const cdp: Rule = ({ s }) =>
  s.client?.automation.cdpDetected
    ? { id: 'auto.cdp', category: 'automation', status: 'warn', points: 30, flags: ['automation'], title: 'DevTools protocol attached', detail: 'console.debug serialised an Error object, which only happens when something listens over the Chrome DevTools Protocol: Puppeteer, Playwright, a debugger extension, or an open DevTools window.' }
    : null;

const webdriverDeleted: Rule = ({ s }) => {
  const c = s.client;
  if (!c || c.lies.engine !== 'blink') return null;
  return c.automation.webdriverInNavigator
    ? null
    : { id: 'auto.webdriver-deleted', category: 'automation', status: 'fail', points: 40, flags: ['tampering', 'automation'], title: 'navigator.webdriver was deleted', detail: 'Chromium always has a webdriver property (false for normal users). Removing it is what stealth plugins do to hide automation.' };
};

const headlessHints: Rule = ({ s, ua, desktop }) => {
  const c = s.client;
  if (!c) return null;
  const a = c.automation;
  const out: Finding[] = [];
  const blink = c.lies.engine === 'blink';
  if (blink && desktop && a.pluginsLength === 0)
    out.push({ id: 'auto.no-plugins', category: 'automation', status: 'warn', points: 20, flags: ['headless'], title: 'No plugins', detail: 'Desktop Chrome always lists 5 built-in PDF viewer plugins; older headless Chrome lists none.' });
  if (a.outerSize[0] === 0 && a.outerSize[1] === 0 && !a.pageHidden)
    out.push({ id: 'auto.outer-size', category: 'automation', status: 'fail', points: 30, flags: ['headless'], title: 'Window has no size', detail: 'outerWidth and outerHeight are 0: there is no real window around the page.' });
  if (a.notificationPermission === 'denied' && a.permissionsNotifications === 'prompt')
    out.push({ id: 'auto.permissions', category: 'automation', status: 'warn', points: 25, flags: ['headless'], title: 'Inconsistent permissions', detail: 'Notification.permission says "denied" while the Permissions API says "prompt" — a known headless Chrome quirk.' });
  if (blink && !a.chromeObject && c.uaHints?.brands.some((b) => /chrom/i.test(b)))
    out.push({ id: 'auto.no-chrome-object', category: 'automation', status: 'warn', points: 15, flags: ['headless'], title: 'window.chrome is missing', detail: 'Chrome defines window.chrome on every page.' });
  if (c.fingerprint.languages.length === 0)
    out.push({ id: 'auto.no-languages', category: 'automation', status: 'fail', points: 30, flags: ['headless'], title: 'No languages', detail: 'navigator.languages is empty; every real browser has at least one.' });
  const r = c.fingerprint.webglRenderer ?? '';
  if (/swiftshader|llvmpipe|softpipe|software/i.test(r))
    out.push({ id: 'auto.software-gpu', category: 'automation', status: 'warn', points: 25, flags: ['headless'], title: 'Software GPU', detail: `WebGL renders on "${r}": a headless browser, a VM or a server without a graphics card.` });
  if (blink && desktop && (ua.version ?? 0) >= 100 && r && !/^ANGLE \(/.test(r) && !/swiftshader|llvmpipe/i.test(r))
    out.push({ id: 'auto.webgl-not-angle', category: 'automation', status: 'warn', points: 20, flags: ['tampering'], title: 'GPU name from an old or spoofed Chrome', detail: `Desktop Chrome has reported its GPU through ANGLE ("ANGLE (Vendor, ...)") for years, but this one says "${r}".` });
  if (c.fingerprint.screen.startsWith('800x600x'))
    out.push({ id: 'auto.screen-800x600', category: 'automation', status: 'warn', points: 15, flags: ['headless'], title: 'Screen is 800×600', detail: 'The default screen of headless Chrome. Real monitors have not been this small for a long time.' });
  if (blink && desktop && a.mediaDevices === 0)
    out.push({ id: 'auto.no-media', category: 'automation', status: 'warn', points: 10, title: 'No media devices', detail: 'No microphone, camera or speaker is visible. Common on servers, rare on laptops and phones.' });
  if (blink && desktop && a.voices === 0)
    out.push({ id: 'auto.no-voices', category: 'automation', status: 'info', points: 5, title: 'No speech voices', detail: 'speechSynthesis has no voices, which is typical for Linux servers.' });
  if (blink && a.connectionRtt === 0 && !s.server.ip.isPrivate)
    out.push({ id: 'auto.rtt-zero', category: 'automation', status: 'info', points: 5, title: 'Network RTT is 0', detail: 'navigator.connection.rtt is 0: headless Chrome, or a very unusual network.' });
  if (out.length === 0) out.push(pass('auto.headless', 'automation', 'Looks like a real window', 'Plugins, window size, permissions, GPU and media devices all look normal.'));
  return out;
};

// ---------------------------------------------------------------- consistency / tampering

const patched: Rule = ({ s }) => {
  const l = s.client?.lies;
  if (!l) return null;
  const out: Finding[] = [];
  if (l.patchedFunctions.length)
    out.push({ id: 'lie.patched', category: 'consistency', status: 'fail', points: 35, flags: ['tampering'], title: 'Native functions replaced', detail: `These browser APIs were overridden in JavaScript: ${l.patchedFunctions.join(', ')}. Anti-detect browsers, stealth plugins and spoofing extensions do this.` });
  if (l.ownPropertyOverrides.length)
    out.push({ id: 'lie.own-props', category: 'consistency', status: 'fail', points: 35, flags: ['tampering'], title: 'navigator properties overridden', detail: `Defined on the navigator object instead of its prototype: ${l.ownPropertyOverrides.join(', ')}.` });
  if (l.iframeMismatch.length)
    out.push({ id: 'lie.iframe', category: 'consistency', status: 'fail', points: 30, flags: ['tampering'], title: 'iframe disagrees with the page', detail: `A fresh iframe reports different ${l.iframeMismatch.join(', ')}: the spoofing only patched the main window.` });
  if (l.workerMismatch.length)
    out.push({ id: 'lie.worker', category: 'consistency', status: 'fail', points: 30, flags: ['tampering'], title: 'Web Worker disagrees with the page', detail: `A Web Worker reports different ${l.workerMismatch.join(', ')}: the spoofing does not reach workers.` });
  if (out.length === 0) out.push(pass('lie.none', 'consistency', 'No tampering found', 'Native functions, iframes and workers all tell the same story.'));
  return out;
};

const engineVsUa: Rule = ({ s, ua }) => {
  const c = s.client;
  if (!c || c.lies.engine === 'unknown' || ua.engine === 'unknown') return null;
  if (c.lies.engine !== ua.engine)
    return { id: 'lie.engine', category: 'consistency', status: 'fail', points: 40, flags: ['tampering'], title: 'Browser engine does not match the User-Agent', detail: `The user agent claims ${ua.browser} (${ua.engine}), but the JavaScript engine behaves like ${c.lies.engine}.` };
  return pass('lie.engine', 'consistency', 'Engine matches User-Agent', `Features and error stacks look like ${c.lies.engine}, as the user agent says.`);
};

const uaHeaderVsJs: Rule = ({ s }) => {
  const c = s.client;
  const h = s.server.headers.userAgent;
  if (!c || !h || h === c.userAgent) return null;
  return { id: 'lie.ua-header', category: 'consistency', status: 'fail', points: 35, flags: ['tampering'], title: 'Two different User-Agents', detail: `The HTTP header says "${h}" but navigator.userAgent says "${c.userAgent}".` };
};

const platformVsUa: Rule = ({ s, ua }) => {
  const c = s.client;
  if (!c) return null;
  const out: Finding[] = [];
  if (!platformMatches(ua.os, osFromPlatform(c.fingerprint.platform)))
    out.push({ id: 'lie.platform', category: 'consistency', status: 'fail', points: 25, flags: ['tampering'], title: 'Platform does not match the User-Agent', detail: `The user agent says ${ua.os}, navigator.platform says "${c.fingerprint.platform}".` });
  if (c.uaHints && !platformMatches(ua.os, osFromPlatform(c.uaHints.platform)))
    out.push({ id: 'lie.ua-ch-platform', category: 'consistency', status: 'fail', points: 25, flags: ['tampering'], title: 'Client Hints disagree with the User-Agent', detail: `The user agent says ${ua.os}, User-Agent Client Hints say "${c.uaHints.platform}".` });
  const h = c.uaHints;
  if (h) {
    // Real Chromium fills these from the OS; spoofing tools tend to copy them from the User-Agent string.
    const problems: string[] = [];
    if (h.platform && !UA_CH_PLATFORMS.has(h.platform)) problems.push(`platform "${h.platform}" is not a value Chromium uses`);
    if (h.platformVersion && !/^\d+(\.\d+)*$/.test(h.platformVersion)) problems.push(`platformVersion "${h.platformVersion}" is not dotted numbers`);
    if (h.fullVersion && /^\d+\.0\.0\.0$/.test(h.fullVersion)) problems.push(`fullVersion "${h.fullVersion}" is the frozen User-Agent version, not a real build number`);
    if (problems.length)
      out.push({ id: 'lie.ua-ch-format', category: 'consistency', status: 'fail', points: 30, flags: ['tampering'], title: 'Fake Client Hints', detail: `navigator.userAgentData was overridden: ${problems.join('; ')}.` });
  }
  if (c.uaHints && ua.engine !== 'blink' && ua.engine !== 'unknown')
    out.push({ id: 'lie.ua-ch-engine', category: 'consistency', status: 'fail', points: 30, flags: ['tampering'], title: 'Client Hints on a non-Chromium browser', detail: `navigator.userAgentData only exists in Chromium, but the user agent claims ${ua.browser}.` });
  return out;
};

const UA_CH_PLATFORMS = new Set(['Android', 'Chrome OS', 'Chromium OS', 'Fuchsia', 'iOS', 'Linux', 'macOS', 'Windows', 'Unknown', '']);

export function tzOffsetNow(tz: string, at = new Date()): number | null {
  try {
    const name = new Intl.DateTimeFormat('en-US', { timeZone: tz, timeZoneName: 'longOffset' })
      .formatToParts(at).find((p) => p.type === 'timeZoneName')?.value ?? '';
    if (name === 'GMT') return 0;
    const m = /GMT([+-])(\d{2}):(\d{2})/.exec(name);
    if (!m) return null;
    const minutes = Number(m[2]) * 60 + Number(m[3]);
    return (m[1] === '+' ? -minutes : minutes) || 0; // same sign as Date#getTimezoneOffset, no -0
  } catch {
    return null;
  }
}

const timezoneOffset: Rule = ({ s }) => {
  const f = s.client?.fingerprint;
  if (!f) return null;
  const expected = tzOffsetNow(f.timezone, new Date(s.server.receivedAt ?? Date.now()));
  if (expected === null || expected === f.timezoneOffset) return null;
  return { id: 'lie.tz-offset', category: 'consistency', status: 'fail', points: 25, flags: ['tampering'], title: 'Timezone name and clock disagree', detail: `The timezone is ${f.timezone} (UTC offset ${-expected} min) but Date says ${-f.timezoneOffset} min: one of them is spoofed.` };
};

const clientHintHeaders: Rule = ({ s, headerUa }) => {
  const h = s.server.headers;
  if (!h.secure || !headerUa.isBrowser) return null;
  const out: Finding[] = [];
  const chromium = headerUa.engine === 'blink' && (headerUa.version ?? 0) >= 90;
  if (chromium && !h.secChUa)
    out.push({ id: 'hdr.no-ch', category: 'consistency', status: 'warn', points: 20, flags: ['tampering'], title: 'No Client Hints header', detail: 'The user agent claims Chromium 90+, which always sends sec-ch-ua over HTTPS. HTTP libraries copy the User-Agent but forget this header.' });
  if (h.secChUa && headerUa.engine !== 'blink')
    out.push({ id: 'hdr.ch-non-chromium', category: 'consistency', status: 'fail', points: 30, flags: ['tampering'], title: 'Client Hints from a non-Chromium browser', detail: `sec-ch-ua is present but the user agent claims ${headerUa.browser}.` });
  if (h.secChUaPlatform) {
    const p = osFromPlatform(h.secChUaPlatform.replace(/"/g, ''));
    if (!platformMatches(headerUa.os, p))
      out.push({ id: 'hdr.ch-platform', category: 'consistency', status: 'fail', points: 25, flags: ['tampering'], title: 'sec-ch-ua-platform disagrees', detail: `Header says ${h.secChUaPlatform}, user agent says ${headerUa.os}.` });
  }
  const modernBrowser = (headerUa.engine === 'blink' && (headerUa.version ?? 0) >= 80) || (headerUa.browser === 'firefox' && (headerUa.version ?? 0) >= 90) || (headerUa.browser === 'safari' && (headerUa.version ?? 0) >= 17);
  if (modernBrowser && !h.secFetchMode)
    out.push({ id: 'hdr.no-sec-fetch', category: 'consistency', status: 'warn', points: 15, title: 'No Sec-Fetch headers', detail: 'Modern browsers mark every request with Sec-Fetch-Site / Sec-Fetch-Mode.' });
  return out;
};

// ---------------------------------------------------------------- TLS

const tls: Rule = ({ s, headerUa }) => {
  const t = s.server.tls;
  if (!t) return info('tls.none', 'tls', 'No TLS fingerprint', 'The request did not reach the built-in HTTPS listener (plain HTTP, or TLS ended at a proxy in front of the app).');
  const base = `JA4 ${t.ja4}`;
  if (!headerUa.isBrowser) {
    const lib = t.ciphers >= 25 ? ' The long cipher list is typical of OpenSSL clients (curl, Python, Node).' : '';
    return info('tls.client', 'tls', 'TLS client', `${base}.${lib}`);
  }
  if (!t.alpn)
    return { id: 'tls.no-alpn', category: 'tls', status: 'fail', points: 40, flags: ['automation', 'tampering'], title: 'TLS without ALPN', detail: `${base}. Browsers always offer h2 / http/1.1 through ALPN; this handshake came from an HTTP library wearing a browser's User-Agent.` };
  if (headerUa.engine === 'blink' && t.cipherHash !== CHROMIUM_CIPHER_HASH)
    return { id: 'tls.not-chromium', category: 'tls', status: 'fail', points: 40, flags: ['automation', 'tampering'], title: "TLS handshake isn't Chrome's", detail: `${base}. The user agent claims ${headerUa.browser}, but the cipher suites (${t.cipherHash}) are not Chromium's (${CHROMIUM_CIPHER_HASH}).` };
  if (headerUa.engine === 'blink' && !t.grease)
    return { id: 'tls.no-grease', category: 'tls', status: 'fail', points: 30, flags: ['tampering'], title: 'TLS without GREASE', detail: `${base}. Chromium always adds random GREASE values to its handshake.` };
  if (headerUa.browser === 'firefox' && t.grease)
    return { id: 'tls.firefox-grease', category: 'tls', status: 'warn', points: 20, flags: ['tampering'], title: 'GREASE from "Firefox"', detail: `${base}. Firefox does not use GREASE, Chromium does.` };
  return pass('tls.match', 'tls', 'TLS matches the browser', `${base} fits ${headerUa.browser}.`);
};

// ---------------------------------------------------------------- behaviour

const behavior: Rule = ({ s, desktop }) => {
  const c = s.client;
  if (!c) return null;
  const b = c.behavior;
  if (!b || b.mouseMoves + b.clicks + b.keys + b.scrolls === 0)
    return info('beh.none', 'behavior', 'No interaction yet', 'Move the mouse, scroll or type to add behaviour checks.');
  const out: Finding[] = [];
  if (b.untrustedEvents > 0)
    out.push({ id: 'beh.untrusted', category: 'behavior', status: 'fail', points: 50, flags: ['automation'], title: 'Synthetic events', detail: `${b.untrustedEvents} input events had isTrusted = false: they were dispatched by a script, not by a person.` });
  if (desktop && c.fingerprint.touchPoints === 0 && b.clicks > 0 && b.clicksWithoutMove === b.clicks)
    out.push({ id: 'beh.teleport-click', category: 'behavior', status: 'warn', points: 25, flags: ['automation'], title: 'Clicks without mouse movement', detail: 'Every click landed with no mouse movement before it, like element.click() or a driver jumping to a point.' });
  if (b.straightness !== null && b.mouseMoves >= 20 && b.straightness > 0.9)
    out.push({ id: 'beh.straight', category: 'behavior', status: 'warn', points: 25, flags: ['automation'], title: 'Robotic mouse path', detail: `${Math.round(b.straightness * 100)}% of the mouse path is perfectly straight at constant speed. Hands draw curves and change speed.` });
  if (b.keyIntervalStdMs !== null && b.keys >= 8 && b.keyIntervalStdMs < 8)
    out.push({ id: 'beh.typing', category: 'behavior', status: 'warn', points: 25, flags: ['automation'], title: 'Metronome typing', detail: `Key intervals vary by only ${b.keyIntervalStdMs.toFixed(1)} ms. People type unevenly.` });
  if (out.length === 0)
    out.push(pass('beh.human', 'behavior', 'Natural interaction', `${b.mouseMoves} mouse moves, ${b.clicks} clicks, ${b.keys} keys, ${b.scrolls} scrolls; curves, speed and timing look human.`));
  return out;
};

// ---------------------------------------------------------------- fingerprint

const fingerprint: Rule = ({ s }) => {
  const f = s.client?.fingerprint;
  if (!f) return null;
  const out: Finding[] = [];
  if (f.canvasNoise)
    out.push(info('fp.canvas-noise', 'fingerprint', 'Canvas is randomised', 'Drawing the same image twice gave different pixels: a privacy browser (Brave, Firefox resistFingerprinting, Tor Browser) or an anti-detect tool.'));
  if (f.fonts.length === 0)
    out.push({ id: 'fp.no-fonts', category: 'fingerprint', status: 'warn', points: 10, title: 'No common fonts', detail: 'None of the tested fonts are installed: typical of minimal server images.' });
  return out;
};

const velocity: Rule = ({ s }) => {
  const v = s.server.velocity;
  if (!v) return null;
  const out: Finding[] = [];
  if (v.ipsForFingerprint24h >= 5)
    out.push({ id: 'vel.fp-ips', category: 'network', status: 'warn', points: 20, flags: ['proxy'], title: 'Same device, many IPs', detail: `This fingerprint came from ${v.ipsForFingerprint24h} IPs in 24 hours: rotating proxies.` });
  if (v.fingerprintsForIp1h >= 20)
    out.push({ id: 'vel.ip-fps', category: 'network', status: 'warn', points: 15, title: 'Many devices, one IP', detail: `${v.fingerprintsForIp1h} different fingerprints from this IP in the last hour: a bot farm, or a big shared network.` });
  if (v.visitsForFingerprint10m >= 30)
    out.push({ id: 'vel.rate', category: 'network', status: 'warn', points: 15, title: 'High request rate', detail: `${v.visitsForFingerprint10m} checks from this device in 10 minutes.` });
  return out;
};

export const RULES: Rule[] = [
  tor, datacenter, vpnRange, webrtcLeak, timezoneMatch, languageMatch, proxyHeaders, privateNet, velocity,
  noJs, webdriver, globals, headlessUa, cdp, webdriverDeleted, headlessHints,
  patched, engineVsUa, uaHeaderVsJs, platformVsUa, timezoneOffset, clientHintHeaders,
  tls, behavior, fingerprint,
];
