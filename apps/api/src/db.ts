// Visit history in SQLite (node:sqlite, built into Node 22.13+): no database server to run.
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { geoChecks, judgedIp, type CheckResponse, type ClientSignals, type ScoreResult, type Signals, type VelocitySignals, type Verdict } from '@bdl/scoring';

export interface VisitRow {
  id: string;
  created_at: number;
  source: 'page' | 'embed' | 'inspect';
  site: string | null;
  ip: string;
  webrtc_ip: string | null;
  fingerprint: string | null;
  user_agent: string | null;
  country: string | null;
  asn: number | null;
  as_org: string | null;
  ja4: string | null;
  score: number;
  verdict: Verdict;
  flags: string;    // JSON Flag[]
  signals: string;  // JSON Signals
  findings: string; // JSON Finding[]
}

// geoMismatches: labels of the red "browser vs IP location" rows, for the dashboard marker.
export type VisitSummary = Omit<VisitRow, 'signals' | 'findings' | 'flags'> & { flags: string[]; geoMismatches: string[] };

// Components whose rarity the "Check me" page shows ("your canvas is shared by 3 of 120 devices").
export function rarityComponents(c: ClientSignals): Record<string, string> {
  const f = c.fingerprint;
  return {
    canvas: f.canvasNoise ? 'noise' : String(f.canvas),
    webgl: `${f.webglVendor}|${f.webglRenderer}`,
    webglParams: String(f.webglHash),
    audio: String(f.audio),
    fonts: f.fonts.join(','),
    screen: f.screen,
    hardware: `${f.hardwareConcurrency}c/${f.deviceMemory}GB`,
    timezone: f.timezone,
    languages: f.languages.join(','),
    platform: f.platform,
    math: f.math,
  };
}

export class Store {
  readonly db: DatabaseSync;

  constructor(file: string) {
    if (file !== ':memory:') mkdirSync(path.dirname(file), { recursive: true });
    this.db = new DatabaseSync(file);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS visits (
        id TEXT PRIMARY KEY,
        created_at INTEGER NOT NULL,
        source TEXT NOT NULL,
        site TEXT,
        ip TEXT NOT NULL,
        webrtc_ip TEXT,
        fingerprint TEXT,
        user_agent TEXT,
        country TEXT,
        asn INTEGER,
        as_org TEXT,
        ja4 TEXT,
        score INTEGER NOT NULL,
        verdict TEXT NOT NULL,
        flags TEXT NOT NULL,
        signals TEXT NOT NULL,
        findings TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS visits_created ON visits (created_at);
      CREATE INDEX IF NOT EXISTS visits_fp ON visits (fingerprint, created_at);
      CREATE INDEX IF NOT EXISTS visits_ip ON visits (ip, created_at);
      CREATE TABLE IF NOT EXISTS components (
        visit_id TEXT NOT NULL REFERENCES visits(id) ON DELETE CASCADE,
        fingerprint TEXT NOT NULL,
        name TEXT NOT NULL,
        value TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS components_value ON components (name, value);
    `);
  }

  velocity(fingerprint: string | null, ip: string, now = Date.now()): VelocitySignals {
    const one = (sql: string, ...args: (string | number)[]) => Number((this.db.prepare(sql).get(...args) as { n: number }).n);
    return {
      ipsForFingerprint24h: fingerprint
        ? one('SELECT COUNT(DISTINCT ip) n FROM (SELECT ip FROM visits WHERE fingerprint = ? AND created_at > ? UNION SELECT ?)', fingerprint, now - 86_400_000, ip)
        : 1,
      fingerprintsForIp1h: one(
        'SELECT COUNT(DISTINCT fingerprint) n FROM (SELECT fingerprint FROM visits WHERE ip = ? AND fingerprint IS NOT NULL AND created_at > ? UNION SELECT ?)',
        ip, now - 3_600_000, fingerprint ?? '',
      ) - (fingerprint ? 0 : 1),
      visitsForFingerprint10m: fingerprint ? one('SELECT COUNT(*) n FROM visits WHERE fingerprint = ? AND created_at > ?', fingerprint, now - 600_000) + 1 : 1,
    };
  }

  insert(v: { id: string; createdAt: number; source: VisitRow['source']; site: string | null; fingerprint: string | null; signals: Signals; result: ScoreResult }) {
    const s = v.signals;
    this.db.prepare(`INSERT INTO visits (id, created_at, source, site, ip, webrtc_ip, fingerprint, user_agent, country, asn, as_org, ja4, score, verdict, flags, signals, findings)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      v.id, v.createdAt, v.source, v.site, s.server.ip.ip, s.server.webrtcIp?.ip ?? s.client?.webrtc.publicIps[0] ?? null, v.fingerprint,
      s.client?.userAgent ?? s.server.headers.userAgent, s.server.ip.country ?? s.server.webrtcIp?.country ?? null,
      s.server.ip.asn ?? s.server.webrtcIp?.asn ?? null, s.server.ip.asOrg ?? s.server.webrtcIp?.asOrg ?? null, s.server.tls?.ja4 ?? null,
      v.result.score, v.result.verdict, JSON.stringify(v.result.flags), JSON.stringify(s), JSON.stringify(v.result.findings),
    );
    if (s.client && v.fingerprint) {
      const ins = this.db.prepare('INSERT INTO components (visit_id, fingerprint, name, value) VALUES (?, ?, ?, ?)');
      for (const [name, value] of Object.entries(rarityComponents(s.client))) ins.run(v.id, v.fingerprint, name, value);
    }
  }

  updateResult(id: string, signals: Signals, result: ScoreResult) {
    this.db.prepare('UPDATE visits SET signals = ?, score = ?, verdict = ?, flags = ?, findings = ? WHERE id = ?')
      .run(JSON.stringify(signals), result.score, result.verdict, JSON.stringify(result.flags), JSON.stringify(result.findings), id);
  }

  get(id: string): VisitRow | undefined {
    return this.db.prepare('SELECT * FROM visits WHERE id = ?').get(id) as VisitRow | undefined;
  }

  /** For each component: how many distinct devices share this value, out of all devices seen. */
  rarity(c: ClientSignals): CheckResponse['rarity'] {
    const total = Number((this.db.prepare('SELECT COUNT(DISTINCT fingerprint) n FROM components').get() as { n: number }).n);
    const q = this.db.prepare('SELECT COUNT(DISTINCT fingerprint) n FROM components WHERE name = ? AND value = ?');
    const out: NonNullable<CheckResponse['rarity']> = {};
    for (const [name, value] of Object.entries(rarityComponents(c))) out[name] = { count: Number((q.get(name, value) as { n: number }).n), total };
    return out;
  }

  list(opts: { verdict?: string; flag?: string; q?: string; limit: number; offset: number }): { rows: VisitSummary[]; total: number } {
    const where: string[] = [];
    const args: (string | number)[] = [];
    if (opts.verdict) { where.push('verdict = ?'); args.push(opts.verdict); }
    if (opts.flag) { where.push('flags LIKE ?'); args.push(`%"${opts.flag}"%`); }
    if (opts.q) { where.push('(ip LIKE ? OR fingerprint LIKE ? OR user_agent LIKE ? OR as_org LIKE ? OR site LIKE ?)'); args.push(...Array(5).fill(`%${opts.q}%`)); }
    const w = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const total = Number((this.db.prepare(`SELECT COUNT(*) n FROM visits ${w}`).get(...args) as { n: number }).n);
    const rows = this.db.prepare(`SELECT id, created_at, source, site, ip, webrtc_ip, fingerprint, user_agent, country, asn, as_org, ja4, score, verdict, flags, signals
      FROM visits ${w} ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(...args, opts.limit, opts.offset) as unknown as (Omit<VisitSummary, 'flags' | 'geoMismatches'> & { flags: string; signals: string })[];
    return {
      rows: rows.map(({ signals, ...r }) => {
        const s = JSON.parse(signals) as Signals;
        return { ...r, flags: JSON.parse(r.flags) as string[], geoMismatches: geoChecks(s, judgedIp(s)).filter((g) => g.match === false).map((g) => g.label) };
      }),
      total,
    };
  }

  stats() {
    const all = <T>(sql: string, ...args: (string | number)[]) => this.db.prepare(sql).all(...args) as T[];
    const dayAgo = Date.now() - 86_400_000;
    return {
      verdicts: all<{ verdict: Verdict; n: number }>('SELECT verdict, COUNT(*) n FROM visits GROUP BY verdict'),
      last24h: all<{ verdict: Verdict; n: number }>('SELECT verdict, COUNT(*) n FROM visits WHERE created_at > ? GROUP BY verdict', dayAgo),
      flags: all<{ flag: string; n: number }>(`SELECT j.value flag, COUNT(*) n FROM visits, json_each(visits.flags) j GROUP BY j.value ORDER BY n DESC`),
      // Same device from many IPs: proxy rotation, or one person on phone + home + office.
      fingerprintClusters: all<{ fingerprint: string; ips: number; visits: number; last: number; userAgent: string }>(
        `SELECT fingerprint, COUNT(DISTINCT ip) ips, COUNT(*) visits, MAX(created_at) last, MAX(user_agent) userAgent
         FROM visits WHERE fingerprint IS NOT NULL GROUP BY fingerprint HAVING ips > 1 ORDER BY ips DESC, visits DESC LIMIT 20`),
      // Many devices from one IP: bot farm, office NAT or carrier-grade NAT.
      ipClusters: all<{ ip: string; fingerprints: number; visits: number; asOrg: string | null; country: string | null }>(
        `SELECT ip, COUNT(DISTINCT fingerprint) fingerprints, COUNT(*) visits, MAX(as_org) asOrg, MAX(country) country
         FROM visits GROUP BY ip HAVING fingerprints > 1 ORDER BY fingerprints DESC LIMIT 20`),
      networks: all<{ asOrg: string; asn: number; visits: number; bots: number }>(
        `SELECT as_org asOrg, asn, COUNT(*) visits, SUM(verdict = 'bot') bots FROM visits WHERE asn IS NOT NULL GROUP BY asn ORDER BY visits DESC LIMIT 15`),
    };
  }

  clear() {
    this.db.exec('DELETE FROM components; DELETE FROM visits;');
  }
}
