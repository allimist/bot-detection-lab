import { test } from 'node:test';
import assert from 'node:assert/strict';
import { score, parseUa, tzOffsetNow, type Signals } from '../src/index.ts';
import { chromeClient, chromeServer, homeIp, human } from './fixtures.ts';

const ids = (s: Signals) => score(s).findings.filter((f) => f.points > 0).map((f) => f.id);

test('a normal Chrome user on a home ISP is human with zero risk', () => {
  const r = score(human());
  assert.equal(r.verdict, 'human');
  assert.equal(r.score, 0, JSON.stringify(r.findings.filter((f) => f.points)));
  assert.deepEqual(r.flags, []);
});

test('Puppeteer / Playwright headless with defaults is a bot', () => {
  const ua = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/141.0.0.0 Safari/537.36';
  const c = chromeClient({ userAgent: ua, uaHints: { brands: ['HeadlessChrome', 'Chromium'], mobile: false, platform: 'Linux' } });
  c.fingerprint.platform = 'Linux x86_64';
  c.fingerprint.webglRenderer = 'ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)';
  c.automation = { ...c.automation, webdriver: true, headlessUa: true, cdpDetected: true, mediaDevices: 0, voices: 0, connectionRtt: 0 };
  const s = chromeServer();
  s.headers = { ...s.headers, userAgent: ua, secChUaPlatform: '"Linux"' };
  const r = score({ client: c, server: s });
  assert.equal(r.verdict, 'bot');
  assert.equal(r.score, 100);
  assert.ok(r.flags.includes('automation') && r.flags.includes('headless'));
  for (const id of ['auto.webdriver', 'auto.headless-ua', 'auto.cdp', 'auto.software-gpu']) assert.ok(ids({ client: c, server: s }).includes(id), id);
});

test('stealth plugin: webdriver hidden but deleted from navigator and functions patched', () => {
  const c = chromeClient();
  c.automation.webdriverInNavigator = false;
  c.lies.patchedFunctions = ['WebGLRenderingContext.getParameter'];
  c.lies.workerMismatch = ['userAgent'];
  const r = score({ client: c, server: chromeServer() });
  assert.equal(r.verdict, 'bot');
  assert.ok(r.flags.includes('tampering'));
});

test('stealth plugin: fake Client Hints, old-style GPU string, 800x600 screen', () => {
  const c = chromeClient({ uaHints: { brands: [' Not A;Brand', 'Chromium', 'Google Chrome'], mobile: false, platform: 'Mac OS X', platformVersion: '10_15_7', architecture: 'x86', model: '', fullVersion: '141.0.0.0' } });
  c.fingerprint.webglVendor = 'Intel Inc.';
  c.fingerprint.webglRenderer = 'Intel Iris OpenGL Engine';
  c.fingerprint.screen = '800x600x24@1';
  c.lies.workerMismatch = ['languages', 'hardwareConcurrency', 'webglRenderer'];
  const found = ids({ client: c, server: chromeServer() });
  for (const id of ['lie.ua-ch-format', 'auto.webgl-not-angle', 'auto.screen-800x600', 'lie.worker']) assert.ok(found.includes(id), id);
  assert.equal(score({ client: c, server: chromeServer() }).verdict, 'bot');
});

test('VPN user: datacenter IP, VPN range, timezone from another country, WebRTC leak', () => {
  const vpn = homeIp({ ip: '185.1.2.3', country: 'NL', city: 'Amsterdam', asn: 9009, asOrg: 'M247', datacenter: true, vpnRange: true });
  const s = chromeServer({ ip: vpn, webrtcIp: homeIp() });
  const r = score({ client: chromeClient(), server: s });
  assert.deepEqual(new Set(ids({ client: chromeClient(), server: s })), new Set(['net.datacenter', 'net.vpn', 'net.webrtc', 'net.timezone']));
  assert.ok(r.flags.includes('vpn') && r.flags.includes('datacenter'));
  assert.equal(r.verdict, 'bot'); // 30 + 20 + 20 + 15 = 85
});

test('VPN on a residential exit with matching timezone is only suspicious', () => {
  const s = chromeServer({ ip: homeIp({ ip: '84.229.99.1' }), webrtcIp: homeIp() });
  s.ip.vpnRange = true;
  const r = score({ client: chromeClient(), server: s });
  assert.equal(r.verdict, 'suspicious');
});

test('Tor exit node', () => {
  const s = chromeServer({ ip: homeIp({ ip: '185.220.101.1', tor: true, datacenter: true, country: 'DE' }) });
  const r = score({ client: chromeClient(), server: s });
  assert.ok(r.flags.includes('tor'));
  assert.equal(r.verdict, 'bot');
});

test('curl: no JavaScript, tool user agent, no Accept-Language', () => {
  const s = chromeServer({ tls: { ja4: 't13d3112h2_e8f1e7e78f70_6bebaf5329ac', alpn: 'h2', ciphers: 31, extensions: 12, grease: false, cipherHash: 'e8f1e7e78f70' } });
  s.headers = { ...s.headers, userAgent: 'curl/8.7.1', acceptLanguage: null, secChUa: null, secChUaPlatform: null, secFetchMode: null, secFetchSite: null };
  const r = score({ client: null, server: s });
  assert.equal(r.verdict, 'bot');
  assert.ok(r.flags.includes('noJs'));
  assert.ok(ids({ client: null, server: s }).includes('auto.tool-ua'));
});

test('Python script with a copied Chrome User-Agent is caught by TLS and missing headers', () => {
  const s = chromeServer({ tls: { ja4: 't13d4907h1_0d8feac7bc37_7395dae3b2f3', alpn: '', ciphers: 49, extensions: 7, grease: false, cipherHash: '0d8feac7bc37' } });
  s.headers = { ...s.headers, secChUa: null, secChUaPlatform: null, secFetchMode: null, secFetchSite: null };
  const found = ids({ client: null, server: s });
  for (const id of ['auto.no-js', 'tls.no-alpn', 'hdr.no-ch', 'hdr.no-sec-fetch']) assert.ok(found.includes(id), id);
  assert.equal(score({ client: null, server: s }).verdict, 'bot');
});

test('UA switcher extension: header and JS disagree, Firefox UA on a Chromium engine', () => {
  const ff = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0';
  const c = chromeClient({ userAgent: ff });
  const found = ids({ client: c, server: chromeServer() });
  for (const id of ['lie.engine', 'lie.ua-header', 'lie.platform', 'lie.ua-ch-platform', 'lie.ua-ch-engine']) assert.ok(found.includes(id), id);
});

test('timezone spoofed by name only', () => {
  const c = chromeClient();
  c.fingerprint.timezone = 'America/New_York';
  const found = ids({ client: c, server: chromeServer({ tzCountry: 'US' }) });
  assert.ok(found.includes('lie.tz-offset'));
  assert.ok(found.includes('net.timezone'));
});

test('behaviour: synthetic events and straight-line mouse', () => {
  const c = chromeClient({
    behavior: { durationMs: 3000, mouseMoves: 40, clicks: 2, keys: 10, scrolls: 0, untrustedEvents: 3, straightness: 0.98, speedVariance: 0.01, keyIntervalStdMs: 0.5, clicksWithoutMove: 0, firstInteractionMs: 100 },
  });
  const found = ids({ client: c, server: chromeServer() });
  for (const id of ['beh.untrusted', 'beh.straight', 'beh.typing']) assert.ok(found.includes(id), id);
});

test('behaviour: natural movement passes', () => {
  const c = chromeClient({
    behavior: { durationMs: 8000, mouseMoves: 120, clicks: 1, keys: 12, scrolls: 3, untrustedEvents: 0, straightness: 0.2, speedVariance: 0.8, keyIntervalStdMs: 60, clicksWithoutMove: 0, firstInteractionMs: 900 },
  });
  const r = score({ client: c, server: chromeServer() });
  assert.equal(r.score, 0);
  assert.ok(r.findings.some((f) => f.id === 'beh.human'));
});

test('local development: private HTTP IP uses the WebRTC IP for network checks', () => {
  const s = chromeServer({ ip: homeIp({ ip: '127.0.0.1', isPrivate: true, country: null, asn: null, asOrg: null }), webrtcIp: homeIp({ datacenter: true }) });
  const found = ids({ client: chromeClient(), server: s });
  assert.ok(found.includes('net.datacenter'));
  assert.ok(!found.includes('net.webrtc'));
});

test('velocity: one fingerprint from many IPs', () => {
  const s = chromeServer({ velocity: { ipsForFingerprint24h: 12, fingerprintsForIp1h: 1, visitsForFingerprint10m: 2 } });
  assert.ok(ids({ client: chromeClient(), server: s }).includes('vel.fp-ips'));
});

test('score is capped at 100 and findings are sorted fail-first', () => {
  const c = chromeClient();
  c.automation = { ...c.automation, webdriver: true, automationGlobals: ['cdc_x'], headlessUa: true };
  const r = score({ client: c, server: chromeServer() });
  assert.equal(r.score, 100);
  assert.equal(r.findings[0]!.status, 'fail');
});

test('parseUa', () => {
  assert.equal(parseUa('curl/8.7.1').tool, 'curl');
  assert.equal(parseUa('Python-urllib/3.13').tool, 'python-urllib');
  const ios = parseUa('Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/129.0 Mobile/15E148 Safari/604.1');
  assert.equal(ios.engine, 'webkit');
  assert.equal(ios.os, 'ios');
  assert.equal(parseUa('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0').browser, 'edge');
});

test('tzOffsetNow matches Date for the local zone', () => {
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  assert.equal(tzOffsetNow(tz), new Date().getTimezoneOffset());
  assert.equal(tzOffsetNow('UTC'), 0);
});
