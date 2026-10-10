// "Does the browser fit the place its IP comes from?" Timezone, clock and language, side by side.
// Display only: these rows add no points. The scored versions live in rules.ts (net.timezone,
// lie.tz-offset, net.webrtc); see ARCHITECTURE.md for which rows could be scored later.
import { countryLanguages } from './country-languages.ts';
import { tzOffsetNow } from './rules.ts';
import type { GeoCheck, IpIntel, Signals } from './types.ts';

const CLOCK_TOLERANCE_MS = 120_000;

/** getTimezoneOffset-style minutes (UTC+3 = -180) as "UTC+3" / "UTC-9:30". */
export function formatOffset(minutes: number): string {
  const east = -minutes;
  const h = Math.floor(Math.abs(east) / 60);
  const m = Math.abs(east) % 60;
  return `UTC${east < 0 ? '-' : '+'}${h}${m ? `:${String(m).padStart(2, '0')}` : ''}`;
}

const localTime = (at: number, offset: number) => new Date(at - offset * 60_000).toISOString().slice(11, 16);
const primary = (tag: string | null | undefined) => (tag ?? '').split(/[-_]/)[0]!.toLowerCase();
const region = (tag: string) => tag.split(/[-_]/)[1]?.toUpperCase();
const hours = (min: number) => {
  const h = Math.abs(min) / 60;
  return `${Number.isInteger(h) ? h : h.toFixed(1)} h`;
};

function row(id: GeoCheck['id'], label: string, browser: string, location: string, match: boolean | null, note: string): GeoCheck {
  return { id, label, browser, location, match, note };
}

export function geoChecks(s: Signals, net: IpIntel): GeoCheck[] {
  const c = s.client;
  if (!c) return [];
  const f = c.fingerprint;
  const at = s.server.receivedAt ?? Date.now();
  const where = net.isPrivate ? 'private network' : [net.city, net.country].filter(Boolean).join(', ') || 'unknown';
  const located = !net.isPrivate && !!net.country;
  const out: GeoCheck[] = [];

  // Timezone name
  const ipOffset = net.timezone ? tzOffsetNow(net.timezone, new Date(at)) : null;
  const browserTzOffset = f.timezone ? tzOffsetNow(f.timezone, new Date(at)) : null;
  if (!located || !net.timezone || !f.timezone) {
    out.push(row('tz', 'Timezone', f.timezone || 'unknown', net.timezone ?? where, null, 'The IP has no known location, so there is nothing to compare with.'));
  } else if (f.timezone === net.timezone) {
    out.push(row('tz', 'Timezone', f.timezone, `${net.timezone} (${where})`, true, 'Same timezone as the IP location.'));
  } else {
    const same = ipOffset !== null && ipOffset === browserTzOffset;
    out.push(row('tz', 'Timezone', f.timezone, `${net.timezone} (${where})`, same,
      same ? 'A different zone name, but the same time right now (e.g. Berlin vs Amsterdam).' : 'The browser is set to a timezone with a different time than the IP location.'));
  }

  // UTC offset and the local time on both sides
  if (!located || ipOffset === null) {
    out.push(row('offset', 'Local time', `${localTime(at, f.timezoneOffset)} (${formatOffset(f.timezoneOffset)})`, where, null, 'Unknown timezone for the IP.'));
  } else {
    const diff = ipOffset - f.timezoneOffset; // > 0: browser is ahead
    out.push(row('offset', 'Local time', `${localTime(at, f.timezoneOffset)} (${formatOffset(f.timezoneOffset)})`, `${localTime(at, ipOffset)} (${formatOffset(ipOffset)})`, diff === 0,
      diff === 0 ? 'The browser clock shows the same local time as the IP location.' : `The browser clock is ${hours(diff)} ${diff > 0 ? 'ahead of' : 'behind'} the local time where the IP is.`));
  }

  // Country of the timezone
  const tzc = s.server.tzCountry;
  out.push(row('tz-country', 'Timezone country', tzc ?? 'unknown', located ? net.country! : where, located && tzc ? tzc === net.country : null,
    !located || !tzc ? 'Cannot compare.' : tzc === net.country ? 'The timezone belongs to the IP country.' : `The timezone is in ${tzc}, the IP is in ${net.country}: typical of a VPN or proxy in another country.`));

  // Browser clock vs server clock, both UTC
  if (c.clientTime === null || s.server.receivedAt === undefined) {
    out.push(row('clock', 'Clock (UTC)', 'unknown', 'server', null, 'This visit has no clock reading.'));
  } else {
    const skew = c.clientTime - s.server.receivedAt;
    const ok = Math.abs(skew) <= CLOCK_TOLERANCE_MS;
    const secs = Math.round(Math.abs(skew) / 1000);
    const amount = secs >= 120 ? `${Math.round(secs / 60)} min` : `${secs} s`;
    out.push(row('clock', 'Clock (UTC)', new Date(c.clientTime).toISOString().slice(11, 19), `${new Date(s.server.receivedAt).toISOString().slice(11, 19)} (server)`, ok,
      ok ? `Within ${amount} of the server clock.` : `The browser clock is ${amount} ${skew > 0 ? 'fast' : 'slow'}. Common on VMs, farms and spoofed environments, but also on badly set PCs.`));
  }

  // Languages vs the IP country
  const langs = f.languages;
  const spoken = countryLanguages(net.country);
  if (!located || !spoken || langs.length === 0) {
    out.push(row('lang-country', 'Language vs country', langs.join(', ') || 'none', located ? net.country! : where, null, 'Cannot compare.'));
  } else {
    // English is the default browser language almost everywhere, so an English-only browser fits any country.
    const englishOnly = langs.every((l) => primary(l) === 'en');
    const ok = englishOnly || langs.some((l) => spoken.includes(primary(l)) || region(l) === net.country);
    out.push(row('lang-country', 'Language vs country', langs.join(', '), `${net.country}: ${spoken.join(', ')}`, ok,
      englishOnly && !langs.some((l) => spoken.includes(primary(l)) || region(l) === net.country)
        ? 'English only: the default browser language in most countries, so it fits anywhere.'
        : ok ? 'The browser uses a language of the IP country.' : 'The browser has languages none of which is spoken in the IP country. Travellers and expats do this too.'));
  }

  // Accept-Language header vs navigator.languages: one browser setting feeds both
  const header = s.server.headers.acceptLanguage;
  const headerFirst = header?.split(',')[0]?.split(';')[0]?.trim() ?? '';
  if (!header || langs.length === 0) {
    out.push(row('accept-language', 'Accept-Language header', langs[0] ?? 'none', header ?? 'missing', null, 'Cannot compare.'));
  } else {
    const ok = primary(headerFirst) === primary(langs[0]);
    out.push(row('accept-language', 'Accept-Language header', langs.join(', '), header, ok,
      ok ? 'The HTTP header and JavaScript agree.' : 'The HTTP header and navigator.languages disagree: one of them was changed by a tool or extension.'));
  }

  // Intl locale vs navigator.language
  if (!c.locale || langs.length === 0) {
    out.push(row('locale', 'Intl locale', c.locale || 'unknown', langs[0] ?? 'none', null, 'Cannot compare.'));
  } else {
    const ok = primary(c.locale) === primary(langs[0]);
    out.push(row('locale', 'Intl locale', c.locale, `${langs[0]} (navigator.language)`, ok,
      ok ? 'Date and number formatting uses the same language as the browser.' : 'Intl formats in a different language than navigator.language. Happens when the browser UI language differs from the preferred language, and when only one of them is spoofed.'));
  }

  // WebRTC exit vs HTTP exit
  const rtc = s.server.webrtcIp;
  if (rtc && !s.server.ip.isPrivate && rtc.country && s.server.ip.country) {
    out.push(row('webrtc-country', 'WebRTC IP country', `${rtc.country} (${rtc.ip})`, `${s.server.ip.country} (${s.server.ip.ip})`, rtc.country === s.server.ip.country,
      rtc.country === s.server.ip.country ? 'A second IP leaks through WebRTC, but in the same country.' : 'WebRTC leaks an IP in another country: the HTTP traffic goes through a VPN or proxy.'));
  }
  return out;
}
