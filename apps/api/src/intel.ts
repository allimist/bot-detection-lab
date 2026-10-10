// Offline IP intelligence from the datasets `npm run data` downloads. Every source is optional:
// a missing file just turns its checks off, and /api/meta says which ones are loaded.
import { existsSync, readFileSync } from 'node:fs';
import { isIP } from 'node:net';
import path from 'node:path';
import maxmind, { type AsnResponse, type CityResponse, type Reader } from 'maxmind';
import type { IpIntel } from '@bdl/scoring';

const PRIVATE_V4: [string, number][] = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.168.0.0', 16], ['198.18.0.0', 15], ['224.0.0.0', 4], ['240.0.0.0', 4],
];

export function v4ToInt(ip: string): number {
  const p = ip.split('.').map(Number);
  return ((p[0]! << 24) | (p[1]! << 16) | (p[2]! << 8) | p[3]!) >>> 0;
}

/** Sorted, merged IPv4 ranges with binary search: 45k CIDRs answer in ~1 µs. */
export class RangeSet {
  private starts: Uint32Array;
  private ends: Uint32Array;

  constructor(cidrs: [string, number][]) {
    const ranges = cidrs
      .filter(([ip]) => isIP(ip) === 4)
      .map(([ip, bits]) => {
        const start = v4ToInt(ip) & (bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0);
        return [start >>> 0, (start + 2 ** (32 - bits) - 1) >>> 0] as [number, number];
      })
      .sort((a, b) => a[0] - b[0]);
    const merged: [number, number][] = [];
    for (const r of ranges) {
      const last = merged[merged.length - 1];
      if (last && r[0] <= last[1] + 1) last[1] = Math.max(last[1], r[1]);
      else merged.push([...r]);
    }
    this.starts = Uint32Array.from(merged.map((r) => r[0]));
    this.ends = Uint32Array.from(merged.map((r) => r[1]));
  }

  get size() {
    return this.starts.length;
  }

  has(ip: string): boolean {
    if (isIP(ip) !== 4) return false;
    const n = v4ToInt(ip);
    let lo = 0;
    let hi = this.starts.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (n < this.starts[mid]!) hi = mid - 1;
      else if (n > this.ends[mid]!) lo = mid + 1;
      else return true;
    }
    return false;
  }

  static fromFile(file: string): RangeSet | null {
    if (!existsSync(file)) return null;
    const cidrs = readFileSync(file, 'utf8').split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'))
      .map((l) => {
        const [ip, bits] = l.split('/');
        return [ip!, bits === undefined ? 32 : Number(bits)] as [string, number];
      });
    return new RangeSet(cidrs);
  }
}

const privateV4 = new RangeSet(PRIVATE_V4);

export function normalizeIp(ip: string): string {
  return ip.startsWith('::ffff:') && isIP(ip.slice(7)) === 4 ? ip.slice(7) : ip;
}

export function isPrivateIp(ip: string): boolean {
  if (isIP(ip) === 4) return privateV4.has(ip);
  const l = ip.toLowerCase();
  return l === '::1' || l === '::' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80:');
}

export interface Zone {
  tz: string;
  lat: number;
  lon: number;
}

/** zone.tab coordinates: "+4230+00131" or "-334200+1510600" (±DDMM[SS]±DDDMM[SS]). */
export function parseZoneCoord(s: string): { lat: number; lon: number } | null {
  const m = /^([+-])(\d{2})(\d{2})(\d{2})?([+-])(\d{3})(\d{2})(\d{2})?$/.exec(s);
  if (!m) return null;
  const deg = (sign: string, d: string, mm: string, ss = '0') => (sign === '-' ? -1 : 1) * (Number(d) + Number(mm) / 60 + Number(ss) / 3600);
  return { lat: deg(m[1]!, m[2]!, m[3]!, m[4]), lon: deg(m[5]!, m[6]!, m[7]!, m[8]) };
}

/** The zone whose reference city is closest to a point. Good enough to tell New York from Los Angeles. */
export function nearestZone(zones: Zone[], lat: number | undefined, lon: number | undefined): string | null {
  if (zones.length === 0) return null;
  if (zones.length === 1 || lat === undefined || lon === undefined) return zones[0]!.tz;
  const cos = Math.cos((lat * Math.PI) / 180);
  let best = zones[0]!;
  let bestD = Infinity;
  for (const z of zones) {
    const dLon = Math.abs(z.lon - lon) % 360;
    const d = (Math.min(dLon, 360 - dLon) * cos) ** 2 + (z.lat - lat) ** 2;
    if (d < bestD) [best, bestD] = [z, d];
  }
  return best.tz;
}

export interface DatasetStatus {
  city: boolean;
  asn: boolean;
  datacenterRanges: number;
  vpnRanges: number;
  datacenterAsns: number;
  torExits: number;
  timezones: number;
}

export class IpIntelService {
  private city: Reader<CityResponse> | null = null;
  private asn: Reader<AsnResponse> | null = null;
  private datacenter: RangeSet | null = null;
  private vpn: RangeSet | null = null;
  private datacenterAsns = new Set<number>();
  private tor = new Set<string>();
  private tzCountries = new Map<string, string>();
  private zonesByCountry = new Map<string, Zone[]>();

  constructor(private dir: string) {}

  async load() {
    const f = (name: string) => path.join(this.dir, name);
    const open = async <T extends CityResponse | AsnResponse>(name: string) =>
      existsSync(f(name)) ? maxmind.open<T>(f(name), { cache: { max: 5000 } }) : null;
    this.city = await open<CityResponse>('dbip-city-lite.mmdb');
    this.asn = await open<AsnResponse>('dbip-asn-lite.mmdb');
    this.datacenter = RangeSet.fromFile(f('datacenter-ipv4.txt'));
    this.vpn = RangeSet.fromFile(f('vpn-ipv4.txt'));
    const lines = (name: string) => (existsSync(f(name)) ? readFileSync(f(name), 'utf8').split('\n') : []);
    this.datacenterAsns = new Set(lines('datacenter-asn.txt').map((l) => /^AS(\d+)/i.exec(l.trim())?.[1]).filter(Boolean).map(Number));
    this.tor = new Set(lines('tor-exits.txt').map((l) => l.trim()).filter((l) => isIP(l)));
    for (const l of lines('zone.tab')) {
      const [cc, coord, tz] = l.split('\t');
      if (!cc || !tz || cc.startsWith('#')) continue;
      this.tzCountries.set(tz, cc);
      const at = parseZoneCoord(coord ?? '');
      if (at) this.zonesByCountry.set(cc, [...(this.zonesByCountry.get(cc) ?? []), { tz, ...at }]);
    }
    for (const l of lines('tz-backward')) {
      const m = /^Link\s+(\S+)\s+(\S+)/.exec(l);
      const cc = m && this.tzCountries.get(m[1]!);
      if (m && cc) this.tzCountries.set(m[2]!, cc);
    }
    return this.status();
  }

  status(): DatasetStatus {
    return {
      city: !!this.city,
      asn: !!this.asn,
      datacenterRanges: this.datacenter?.size ?? 0,
      vpnRanges: this.vpn?.size ?? 0,
      datacenterAsns: this.datacenterAsns.size,
      torExits: this.tor.size,
      timezones: this.tzCountries.size,
    };
  }

  /** ISO country of an IANA timezone ("Asia/Jerusalem" -> "IL"). */
  tzCountry(tz: string | null | undefined): string | null {
    return (tz && this.tzCountries.get(tz)) || null;
  }

  lookup(raw: string): IpIntel {
    const ip = normalizeIp(raw);
    const base: IpIntel = { ip, isPrivate: isPrivateIp(ip), country: null, city: null, timezone: null, asn: null, asOrg: null, datacenter: false, vpnRange: false, tor: false };
    if (base.isPrivate || !isIP(ip)) return base;
    const geo = this.city?.get(ip);
    const as = this.asn?.get(ip);
    const asn = as?.autonomous_system_number ?? null;
    const country = geo?.country?.iso_code ?? null;
    // DB-IP Lite has no time_zone: take the nearest tzdb zone of the IP's country instead.
    const timezone = geo?.location?.time_zone
      ?? (country ? nearestZone(this.zonesByCountry.get(country) ?? [], geo?.location?.latitude, geo?.location?.longitude) : null);
    return {
      ...base,
      country,
      city: geo?.city?.names?.en ?? null,
      timezone,
      asn,
      asOrg: as?.autonomous_system_organization ?? null,
      datacenter: (asn !== null && this.datacenterAsns.has(asn)) || !!this.datacenter?.has(ip),
      vpnRange: !!this.vpn?.has(ip),
      tor: this.tor.has(ip),
    };
  }
}
