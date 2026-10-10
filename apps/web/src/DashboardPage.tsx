import { useCallback, useEffect, useState } from 'react';
import type { CheckResponse, Signals, Verdict } from '@bdl/scoring';
import { FLAG_LABEL, Flags, FindingsByCategory, GeoTable, VerdictChip, shortUa, timeAgo } from './ui.tsx';

interface VisitSummary {
  id: string;
  created_at: number;
  source: string;
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
  flags: string[];
  geoMismatches?: string[]; // missing from servers older than the geo checks
}

interface Stats {
  verdicts: { verdict: Verdict; n: number }[];
  last24h: { verdict: Verdict; n: number }[];
  flags: { flag: string; n: number }[];
  fingerprintClusters: { fingerprint: string; ips: number; visits: number; last: number; userAgent: string }[];
  ipClusters: { ip: string; fingerprints: number; visits: number; asOrg: string | null; country: string | null }[];
  networks: { asOrg: string; asn: number; visits: number; bots: number }[];
}

type Detail = CheckResponse & { signals: Signals; source: string; site: string | null };

function useToken() {
  const [token, setToken] = useState(() => {
    try { return localStorage.getItem('bdl-token') ?? ''; } catch { return ''; }
  });
  const save = (t: string) => {
    setToken(t);
    try { localStorage.setItem('bdl-token', t); } catch { /* private mode */ }
  };
  return [token, save] as const;
}

export function DashboardPage() {
  const [token, setToken] = useToken();
  const [needToken, setNeedToken] = useState(false);
  const [stats, setStats] = useState<Stats | null>(null);
  const [visits, setVisits] = useState<{ rows: VisitSummary[]; total: number } | null>(null);
  const [verdict, setVerdict] = useState('');
  const [flag, setFlag] = useState('');
  const [q, setQ] = useState('');
  const [live, setLive] = useState(true);
  const [open, setOpen] = useState<Detail | null>(null);

  const api = useCallback(
    async <T,>(path: string, init?: RequestInit): Promise<T | null> => {
      const res = await fetch(path, { ...init, headers: token ? { authorization: `Bearer ${token}` } : {} });
      if (res.status === 401) { setNeedToken(true); return null; }
      setNeedToken(false);
      return (await res.json()) as T;
    },
    [token],
  );

  const load = useCallback(async () => {
    const params = new URLSearchParams({ limit: '100' });
    if (verdict) params.set('verdict', verdict);
    if (flag) params.set('flag', flag);
    if (q) params.set('q', q);
    const [s, v] = await Promise.all([api<Stats>('/api/stats'), api<{ rows: VisitSummary[]; total: number }>(`/api/visits?${params}`)]);
    if (s) setStats(s);
    if (v) setVisits(v);
  }, [api, verdict, flag, q]);

  useEffect(() => {
    void load();
    if (!live) return;
    const id = setInterval(load, 4000);
    return () => clearInterval(id);
  }, [load, live]);

  const openVisit = async (id: string) => setOpen(await api<Detail>(`/api/visits/${id}`));
  const clear = async () => {
    if (!window.confirm('Delete every stored visit?')) return;
    await api('/api/visits/clear', { method: 'POST' });
    void load();
  };

  if (needToken)
    return (
      <div className="panel stack" style={{ maxWidth: 460 }}>
        <h2>Dashboard token</h2>
        <p className="muted">This server sets API_TOKEN. Paste it to see stored visits.</p>
        <form className="row" onSubmit={(e) => { e.preventDefault(); setToken(String(new FormData(e.currentTarget).get('t') ?? '')); }}>
          <input name="t" type="password" defaultValue={token} placeholder="API token" style={{ flex: 1 }} />
          <button>Open</button>
        </form>
      </div>
    );

  const count = (list: Stats['verdicts'] | undefined, v: Verdict) => list?.find((x) => x.verdict === v)?.n ?? 0;
  const total = stats ? stats.verdicts.reduce((n, x) => n + x.n, 0) : 0;
  const maxFlag = Math.max(1, ...(stats?.flags.map((f) => f.n) ?? [1]));

  return (
    <div className="stack">
      <div className="grid cols-4">
        <Tile label="Visits" value={total} sub={`${stats ? stats.last24h.reduce((n, x) => n + x.n, 0) : 0} in the last 24 h`} />
        {(['human', 'suspicious', 'bot'] as const).map((v) => (
          <Tile key={v} label={v} value={count(stats?.verdicts, v)} sub={`${total ? Math.round((count(stats?.verdicts, v) / total) * 100) : 0}% · ${count(stats?.last24h, v)} today`} verdict={v} />
        ))}
      </div>

      <div className="grid cols-2">
        <section className="panel">
          <h2>Flags</h2>
          {stats?.flags.length ? (
            <div className="rarity" style={{ gridTemplateColumns: '120px 1fr 50px' }}>
              {stats.flags.map((f) => (
                <div key={f.flag} style={{ display: 'contents' }}>
                  <a href="#" onClick={(e) => { e.preventDefault(); setFlag(flag === f.flag ? '' : f.flag); }}>{FLAG_LABEL[f.flag as keyof typeof FLAG_LABEL] ?? f.flag}</a>
                  <div className="bar"><span style={{ width: `${(f.n / maxFlag) * 100}%`, background: 'var(--fail)' }} /></div>
                  <span className="small muted">{f.n}</span>
                </div>
              ))}
            </div>
          ) : <p className="muted">No flags yet.</p>}
        </section>
        <section className="panel">
          <h2>Networks</h2>
          {stats?.networks.length ? (
            <table>
              <thead><tr><th>Network</th><th>Visits</th><th>Bots</th></tr></thead>
              <tbody>
                {stats.networks.map((n) => (
                  <tr key={n.asn}><td className="truncate">{n.asOrg} <span className="muted small">AS{n.asn}</span></td><td>{n.visits}</td><td>{n.bots}</td></tr>
                ))}
              </tbody>
            </table>
          ) : <p className="muted">No public IPs yet (local visits have none, unless WebRTC gives one).</p>}
        </section>
      </div>

      <section className="panel">
        <div className="row" style={{ justifyContent: 'space-between', marginBottom: 12 }}>
          <h2 style={{ margin: 0 }}>Visits {visits && <span className="muted small">({visits.total})</span>}</h2>
          <div className="row">
            <input placeholder="IP, fingerprint, UA, network…" value={q} onChange={(e) => setQ(e.target.value)} />
            <select value={verdict} onChange={(e) => setVerdict(e.target.value)} aria-label="Verdict">
              <option value="">All verdicts</option>
              <option value="human">Human</option>
              <option value="suspicious">Suspicious</option>
              <option value="bot">Bot</option>
            </select>
            <select value={flag} onChange={(e) => setFlag(e.target.value)} aria-label="Flag">
              <option value="">All flags</option>
              {Object.entries(FLAG_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
            <label className="row small" style={{ gap: 6 }}><input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} /> live</label>
            <button className="ghost" onClick={clear}>Clear</button>
          </div>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>When</th><th>Verdict</th><th>Score</th><th>IP</th><th>Browser</th><th>Fingerprint</th><th>Source</th><th>Flags</th></tr>
            </thead>
            <tbody>
              {visits?.rows.map((v) => (
                <tr key={v.id} className="click" onClick={() => openVisit(v.id)}>
                  <td className="small muted" style={{ whiteSpace: 'nowrap' }}>{timeAgo(v.created_at)}</td>
                  <td><VerdictChip verdict={v.verdict} /></td>
                  <td className="mono">{v.score}</td>
                  <td>
                    <div className="mono small">{v.ip}</div>
                    <div className="small muted truncate" style={{ maxWidth: 200 }}>{[v.country, v.as_org].filter(Boolean).join(' · ')}</div>
                  </td>
                  <td className="small" title={v.user_agent ?? ''}>{shortUa(v.user_agent)}</td>
                  <td className="mono small">{v.fingerprint?.slice(0, 10) ?? '—'}</td>
                  <td className="small muted">{v.source}{v.site ? ` · ${v.site}` : ''}</td>
                  <td>
                    <Flags flags={v.flags} />
                    {!!v.geoMismatches?.length && <span className="chip fail" title={`Browser vs IP location: ${v.geoMismatches.join(', ')}`}>⚑ geo {v.geoMismatches.length}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {visits?.rows.length === 0 && <p className="muted">Nothing yet. Open the Check page, or run <code>npm run bots</code>.</p>}
        </div>
      </section>

      <div className="grid cols-2">
        <section className="panel">
          <h2>Same device, many IPs</h2>
          <p className="muted small" style={{ marginTop: -4 }}>Rotating proxies, or one person moving between networks.</p>
          {stats?.fingerprintClusters.length ? (
            <table>
              <thead><tr><th>Fingerprint</th><th>IPs</th><th>Visits</th><th>Browser</th></tr></thead>
              <tbody>
                {stats.fingerprintClusters.map((c) => (
                  <tr key={c.fingerprint} className="click" onClick={() => setQ(c.fingerprint)}>
                    <td className="mono small">{c.fingerprint.slice(0, 10)}</td><td>{c.ips}</td><td>{c.visits}</td><td className="small">{shortUa(c.userAgent)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <p className="muted">None yet.</p>}
        </section>
        <section className="panel">
          <h2>Many devices, one IP</h2>
          <p className="muted small" style={{ marginTop: -4 }}>Bot farms, or offices and mobile carriers behind NAT.</p>
          {stats?.ipClusters.length ? (
            <table>
              <thead><tr><th>IP</th><th>Devices</th><th>Visits</th><th>Network</th></tr></thead>
              <tbody>
                {stats.ipClusters.map((c) => (
                  <tr key={c.ip} className="click" onClick={() => setQ(c.ip)}>
                    <td className="mono small">{c.ip}</td><td>{c.fingerprints}</td><td>{c.visits}</td><td className="small truncate" style={{ maxWidth: 160 }}>{c.asOrg ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <p className="muted">None yet.</p>}
        </section>
      </div>

      {open && (
        <>
          <div className="drawer-bg" onClick={() => setOpen(null)} />
          <aside className="drawer stack" aria-label="Visit details">
            <div className="row" style={{ justifyContent: 'space-between' }}>
              <div className="row"><VerdictChip verdict={open.result.verdict} /><b>score {open.result.score}</b><span className="muted small">{new Date(open.createdAt).toLocaleString()}</span></div>
              <button className="ghost" onClick={() => setOpen(null)}>Close</button>
            </div>
            <Flags flags={open.result.flags} />
            <dl className="kv panel">
              <dt>Visit</dt><dd className="mono">{open.visitId}</dd>
              <dt>Source</dt><dd>{open.source}{open.site ? ` · ${open.site}` : ''}</dd>
              <dt>IP</dt><dd>{open.ip.ip} {[open.ip.city, open.ip.country, open.ip.asOrg].filter(Boolean).join(' · ')}</dd>
              {open.webrtcIp && <><dt>WebRTC IP</dt><dd>{open.webrtcIp.ip} {[open.webrtcIp.country, open.webrtcIp.asOrg].filter(Boolean).join(' · ')}</dd></>}
              <dt>User-Agent</dt><dd className="small">{open.signals.client?.userAgent ?? open.signals.server.headers.userAgent ?? '—'}</dd>
              <dt>Fingerprint</dt><dd className="mono">{open.fingerprintId ?? '—'}</dd>
              <dt>JA4</dt><dd className="mono">{open.tls?.ja4 ?? '—'}</dd>
            </dl>
            <GeoTable geo={open.result.geo} />
            <FindingsByCategory findings={open.result.findings} />
            <details className="panel">
              <summary>All signals</summary>
              <pre>{JSON.stringify(open.signals, null, 2)}</pre>
            </details>
          </aside>
        </>
      )}
    </div>
  );
}

function Tile({ label, value, sub, verdict }: { label: string; value: number; sub: string; verdict?: Verdict }) {
  return (
    <div className="panel">
      <div className="card-title">{verdict ? <VerdictChip verdict={verdict} /> : label}</div>
      <div style={{ fontSize: 30, fontWeight: 800 }}>{value}</div>
      <div className="muted small">{sub}</div>
    </div>
  );
}
