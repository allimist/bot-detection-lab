# Architecture

One request flow, three layers:

1. **Collect.** `collector.js` runs in the page for 1–3 s (STUN and the audio render are the slow parts) and posts `ClientSignals` to `POST /api/collect`.
2. **Enrich.** The API adds `ServerSignals`: IP intel for the HTTP IP and for the WebRTC IP, request headers in arrival order, the JA4 of the TLS connection, the browser timezone's country, and velocity counters from SQLite.
3. **Score.** `score({ client, server })` in `packages/scoring` runs every rule. Each rule returns findings (`pass`, `info`, `warn`, `fail`) with points. The sum, capped at 100, is the bot risk: **< 25 human, 25–59 suspicious, ≥ 60 bot**.

The scoring package is a pure function with no I/O, so the same signals always give the same result. That is what makes it testable (`packages/scoring/test`) and lets the dashboard re-score stored visits.

Behaviour comes later: the page keeps recording and re-posts to `POST /api/collect/:id/behavior`, which re-scores the stored visit.

## Signals and rules

### Network

| Rule | Points | Why it works |
|---|---|---|
| Tor exit | 35 | The Tor Project publishes every exit relay. |
| Datacenter IP | 30 | The ASN is on X4BNet's hosting list, or the IP is in one of ~30k datacenter ranges. People browse from ISPs; scrapers, VPN servers and proxies live in clouds. |
| Known VPN range | 20 | Ranges published as commercial VPN exits. |
| WebRTC leaks a different IP | 20 | STUN runs over UDP. Many proxies and some VPN setups only carry TCP/HTTP, so STUN sees the real address. |
| Timezone ≠ IP country | 15 | `Intl` timezone → country via the IANA `zone.tab`, compared with the IP's country. A VPN changes the IP, not the clock. |
| Proxy headers | 15 | `Via`, `Forwarded`, `X-Forwarded-For`… are only checked when the app faces the internet directly (`TRUST_PROXY` off). |
| Velocity | 15–20 | One fingerprint from ≥ 5 IPs in 24 h (proxy rotation), ≥ 20 fingerprints from one IP in 1 h, ≥ 30 checks from one device in 10 min. |

When the server sees a private IP (localhost, LAN), it judges the WebRTC public IP instead, so the network checks also work in local development.

### Automation

| Rule | Points | Why it works |
|---|---|---|
| `navigator.webdriver` true | 60 | Set by WebDriver and CDP automation unless something hides it. |
| Driver globals | 60 | `cdc_…` (ChromeDriver), `__playwright…`, `callPhantom`, `__nightmare`, `domAutomation`… |
| HeadlessChrome UA | 60 | Headless Chrome says so in its User-Agent unless overridden. |
| `webdriver` deleted | 40 | Real Chromium always has the property; old stealth patches `delete` it. |
| DevTools protocol attached | 30 | `console.debug(error)` reads `error.stack` only when a CDP client serialises console messages. Current Chrome mostly closed this leak. |
| Window has no size | 30 | `outerWidth/outerHeight === 0` in a visible tab. Background tabs are excluded: they report 0 too. |
| Inconsistent permissions | 25 | Headless: `Notification.permission` is `denied` while the Permissions API says `prompt`. |
| Software GPU | 25 | SwiftShader / llvmpipe: no real GPU. |
| No plugins / no `window.chrome` / no languages | 15–30 | Things every desktop Chrome has. |
| GPU name not from ANGLE | 20 | Desktop Chrome has reported GPUs as `ANGLE (Vendor, …)` for years. "Intel Iris OpenGL Engine" is what stealth plugins fake. |
| Screen 800×600 | 15 | Headless Chrome's default screen. |
| No media devices / voices, RTT 0 | 5–10 | Weak hints, typical of servers. |

### Consistency (lies)

| Rule | Points | Why it works |
|---|---|---|
| Native functions replaced | 35 | A native function's source is `function name() { [native code] }`, it has no `prototype`, and `new` fails. Each target is also stringified with the `Function.prototype.toString` of a **fresh iframe**, so patching the page's `toString` doesn't hide it. A Proxy shows up there without its name. |
| `navigator` own properties | 35 | Real values live on `Navigator.prototype`; `Object.defineProperty(navigator, …)` spoofing creates own properties. |
| iframe disagrees | 30 | A new iframe is a new realm that page-level patches often miss. |
| **Web Worker disagrees** | 30 | User agent, platform, languages, CPU count, timezone and **WebGL renderer (OffscreenCanvas)** read inside a Worker. Stealth plugins patch the window, not workers. |
| Engine ≠ User-Agent | 40 | V8 stack traces look like `at fn (…)`, SpiderMonkey and JSC like `fn@…`; `-moz-` CSS support separates Gecko from WebKit. A "Firefox" that runs V8 is Chrome in disguise. |
| Two different User-Agents | 35 | Header vs `navigator.userAgent`: extensions often change only one of them. |
| Platform / Client Hints mismatch | 25–30 | UA says Windows, `navigator.platform` says MacIntel; Client Hints on a non-Chromium UA. |
| Fake Client Hints | 30 | Chromium only uses a fixed set of platform names, dotted version numbers and real build numbers. Spoofers copy `Mac OS X`, `10_15_7` and `156.0.0.0` from the UA string. |
| Timezone name ≠ clock | 25 | `Intl` says one zone, `getTimezoneOffset()` disagrees: one of them is spoofed. |
| No Client Hints / Sec-Fetch headers | 15–20 | Chromium 90+ always sends `sec-ch-ua` over HTTPS or to localhost; modern browsers always send `Sec-Fetch-*`. HTTP libraries copy the User-Agent and forget them. |

### TLS (JA4)

The HTTPS port is a raw `net.Server`. It buffers the first TLS record(s), parses the ClientHello, computes [JA4](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md), then `socket.unshift(bytes)` and `httpsServer.emit('connection', socket)`. The HTTPS server reads the hello as if nothing happened. The fingerprint is stored per `remoteAddress|remotePort` until the socket closes, and each request on that connection picks it up. `apps/api/test/tls.test.ts` checks the hash against the spec's own example (`t13d1516h2_8daaf6152771_e5627efa2ab1`).

| Rule | Points | Why it works |
|---|---|---|
| Browser UA, no ALPN | 40 | Every browser offers `h2` / `http/1.1`. Python's `ssl` and Node's `https` don't by default. |
| Chromium UA, cipher hash ≠ `8daaf6152771` | 40 | All Chromium browsers have shared one cipher list for years. OpenSSL / BoringSSL defaults in libraries differ. |
| Chromium UA, no GREASE | 30 | Chromium always adds random GREASE values. |
| Firefox UA with GREASE | 20 | Firefox doesn't send GREASE. |

### Behaviour

| Rule | Points | Why it works |
|---|---|---|
| Synthetic events | 50 | `isTrusted === false`: dispatched by `element.dispatchEvent`, not by a person. |
| Clicks without movement | 25 | Every click landed with no mouse movement before it. |
| Robotic mouse path | 25 | > 90% of mouse segments continue in exactly the same direction with the same length: `page.mouse.move(x, y, { steps })` interpolation. |
| Metronome typing | 25 | Key intervals with < 8 ms standard deviation: `keyboard.type(text, { delay })`. |

### Browser vs IP location (display only)

`packages/scoring/src/geo.ts` puts what the browser says next to where its IP is, row by row, and the page shows mismatches in red. **These rows add no points yet.** The scored overlaps (`net.timezone`, `lie.tz-offset`, `net.webrtc`) stay in the rules above.

The IP's timezone comes from tzdb `zone.tab`. DB-IP Lite has no timezone, so the server takes the zone of the IP country whose reference city is closest to the IP's coordinates. That tells New York from Los Angeles, not only "US".

| Row | Browser | Compared with | Red when | Could it score? |
|---|---|---|---|---|
| Timezone | IANA zone | IP zone | another zone with a different time now | covered by `net.timezone` |
| Local time | clock offset + time | offset + time at the IP | offsets differ | **yes**: hours apart is the clearest VPN sign |
| Timezone country | country of the zone | IP country | different | already +15 |
| Clock (UTC) | `Date.now()` at send | server clock | more than 2 min apart | weak: badly set PCs exist; VMs and farms drift too |
| Language vs country | `navigator.languages` | languages of the IP country | a non-English language set and none fits | no: expats and travellers. English-only fits anywhere |
| Accept-Language | `navigator.languages` | the HTTP header | primary language differs | **yes**: one browser setting feeds both, so a mismatch is a tool |
| Intl locale | `Intl` locale | `navigator.language` | primary language differs | maybe: also happens when the UI and content languages differ |
| WebRTC country | WebRTC IP country | HTTP IP country | different | covered by `net.webrtc` |

### Fingerprint and rarity

`fingerprintId` hashes the stable components (canvas, WebGL vendor/renderer/params, audio, fonts, screen, CPU/RAM, timezone, languages, platform, math, UA-CH platform/arch/model). If the canvas is randomised (Brave, Firefox RFP), the hash uses "noise" instead, so the ID stays stable. The `components` table stores each component per visit, and the Check page shows how many devices share each value.

## Why these choices

- **No external services.** Fingerprinting SaaS products work well, but you can't read their rules. Here every point has a line of code and a sentence behind it.
- **SQLite instead of Postgres/Redis.** The interesting part is the detection, not the storage. `node:sqlite` keeps it to a single `npm start`.
- **JA4 in Node.** Usually you need nginx/HAProxy modules or a Go proxy for TLS fingerprints. Peeking at the socket and handing it on takes about 40 lines.
- **Rules as data plus pure functions.** New signal → new field in `types.ts`, collected in `packages/collector`, judged in `rules.ts`, pinned by a test fixture.
