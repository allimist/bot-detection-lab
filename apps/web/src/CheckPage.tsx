import { useEffect, useMemo, useRef, useState } from 'react';
import { BotCheck } from '@bdl/collector';
import type { CheckResponse, IpIntel } from '@bdl/scoring';
import { Flags, FindingsByCategory, Gauge, GeoTable, VerdictChip } from './ui.tsx';

declare global {
  interface Window {
    __botcheck?: CheckResponse;
  }
}

const HEADLINE = {
  human: 'You look like a real person',
  suspicious: 'Something looks off',
  bot: 'You look like a bot',
} as const;

const SUBLINE = {
  human: 'No automation, no tampering, and the network looks like a normal home or mobile connection.',
  suspicious: 'A real person, maybe, but behind a VPN or proxy, or with something unusual in the browser.',
  bot: 'Several independent signals point at automation or a spoofed browser.',
} as const;

function publish(r: CheckResponse) {
  window.__botcheck = r;
  document.body.dataset.verdict = r.result.verdict;
  document.body.dataset.score = String(r.result.score);
}

export function CheckPage() {
  const check = useMemo(() => new BotCheck({ site: 'check-page' }), []);
  const [res, setRes] = useState<CheckResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [rechecking, setRechecking] = useState(false);
  const [httpsPort, setHttpsPort] = useState<number | null>(null);
  const sent = useRef(0);

  useEffect(() => {
    check.run().then((r) => { publish(r); setRes(r); }, (e) => setError(String(e)));
    fetch('/api/meta').then((r) => r.json()).then((m) => setHttpsPort(m.httpsPort)).catch(() => {});
    return () => check.tracker.stop();
  }, [check]);

  // Re-score with behaviour a moment after the visitor stops interacting.
  useEffect(() => {
    if (!res) return;
    const id = setInterval(() => {
      const b = check.tracker.summary();
      const n = b.mouseMoves + b.clicks + b.keys + b.scrolls;
      if (n > sent.current + 15) {
        sent.current = n;
        check.sendBehavior().then((r) => { if (r) { publish(r); setRes(r); } });
      }
    }, 2500);
    return () => clearInterval(id);
  }, [res, check]);

  const recheck = async () => {
    setRechecking(true);
    const r = await check.sendBehavior();
    if (r) { publish(r); setRes(r); }
    setRechecking(false);
  };

  if (error) return <div className="banner warn">The check failed: {error}</div>;
  if (!res)
    return (
      <div className="panel row" style={{ padding: 28 }}>
        <span className="spinner" /> Running checks: fingerprint, automation, tampering, WebRTC, TLS…
      </div>
    );

  const { result } = res;
  const showHttps = location.protocol === 'http:' && httpsPort && !res.tls;
  return (
    <div className="stack">
      <section className="panel hero">
        <Gauge score={result.score} verdict={result.verdict} />
        <div>
          <div className="row" style={{ marginBottom: 6 }}>
            <VerdictChip verdict={result.verdict} />
            <span className="muted small">visit {res.visitId.slice(0, 8)}</span>
          </div>
          <h1>{HEADLINE[result.verdict]}</h1>
          <p className="muted">{SUBLINE[result.verdict]}</p>
          <Flags flags={result.flags} />
        </div>
      </section>

      <GeoTable geo={result.geo} />

      {showHttps && (
        <div className="banner">
          🔒 The TLS (JA4) fingerprint is only taken over HTTPS. Open{' '}
          <a href={`https://${location.hostname}:${httpsPort}${location.pathname}`}>https://{location.hostname}:{httpsPort}</a>{' '}
          {location.hostname === 'localhost' ? '(self-signed certificate: accept the warning once).' : ''}
        </div>
      )}

      <div className="grid cols-4">
        <IpCard title="Your IP" ip={res.ip.isPrivate && res.webrtcIp ? res.webrtcIp : res.ip} note={res.ip.isPrivate ? `server sees ${res.ip.ip}` : undefined} />
        <div className="panel">
          <div className="card-title">WebRTC</div>
          {res.webrtcIp && !res.ip.isPrivate ? (
            <>
              <div className="big">{res.webrtcIp.ip}</div>
              <div className="muted small">Leaked by STUN: differs from your HTTP IP</div>
            </>
          ) : (
            <>
              <div className="big">{res.result.findings.find((f) => f.id === 'net.webrtc')?.title ?? 'Not checked'}</div>
              <div className="muted small">STUN public address vs HTTP address</div>
            </>
          )}
        </div>
        <div className="panel">
          <div className="card-title">Device fingerprint</div>
          <div className="big mono">{res.fingerprintId ?? '—'}</div>
          <div className="muted small">Hash of canvas, GPU, audio, fonts, screen, hardware, timezone and languages</div>
        </div>
        <div className="panel">
          <div className="card-title">TLS fingerprint (JA4)</div>
          <div className="big mono" style={{ fontSize: 15 }}>{res.tls?.ja4 ?? 'HTTPS only'}</div>
          {res.tls && <div className="muted small">ALPN {res.tls.alpn || 'none'} · {res.tls.ciphers} ciphers · GREASE {res.tls.grease ? 'yes' : 'no'}</div>}
        </div>
      </div>

      <section className="behavior-box">
        <h2>Prove it: move the mouse, scroll, type something</h2>
        <span className="muted small">
          Behaviour is checked as you go: whether the events are real, how straight the mouse moves, how even the typing is. Nothing you type is sent, only timings.
        </span>
        <textarea placeholder="Type a sentence here…" aria-label="Typing test" />
        <div className="row">
          <button onClick={recheck} disabled={rechecking}>{rechecking ? 'Checking…' : 'Re-check with my behaviour'}</button>
          <BehaviorCounter check={check} />
        </div>
      </section>

      <FindingsByCategory findings={result.findings} />

      {res.rarity && <Rarity rarity={res.rarity} />}

      <details className="panel">
        <summary>Raw response</summary>
        <pre>{JSON.stringify(res, null, 2)}</pre>
      </details>
    </div>
  );
}

function BehaviorCounter({ check }: { check: BotCheck }) {
  const [, tick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => tick((n) => n + 1), 500);
    return () => clearInterval(id);
  }, []);
  const b = check.tracker.summary();
  return <span className="muted small">{b.mouseMoves} moves · {b.clicks} clicks · {b.keys} keys · {b.scrolls} scrolls</span>;
}

function IpCard({ title, ip, note }: { title: string; ip: IpIntel; note?: string }) {
  return (
    <div className="panel">
      <div className="card-title">{title}</div>
      <div className="big">{ip.ip}</div>
      <div className="muted small">
        {[ip.city, ip.country].filter(Boolean).join(', ') || (ip.isPrivate ? 'private network' : 'unknown location')}
        {ip.asOrg && <> · {ip.asOrg}{ip.asn ? ` (AS${ip.asn})` : ''}</>}
      </div>
      {note && <div className="muted small">{note}</div>}
      <div className="chips" style={{ marginTop: 6 }}>
        {ip.datacenter && <span className="chip fail">datacenter</span>}
        {ip.vpnRange && <span className="chip warn">VPN range</span>}
        {ip.tor && <span className="chip fail">Tor</span>}
        {!ip.isPrivate && !ip.datacenter && !ip.vpnRange && !ip.tor && ip.asn && <span className="chip pass">ISP</span>}
      </div>
    </div>
  );
}

const RARITY_LABEL: Record<string, string> = {
  canvas: 'Canvas', webgl: 'GPU', webglParams: 'WebGL params', audio: 'Audio', fonts: 'Fonts', screen: 'Screen',
  hardware: 'CPU / RAM', timezone: 'Timezone', languages: 'Languages', platform: 'Platform', math: 'Math engine',
};

function Rarity({ rarity }: { rarity: NonNullable<CheckResponse['rarity']> }) {
  const total = Object.values(rarity)[0]?.total ?? 0;
  return (
    <section className="panel">
      <h2>How unique is your browser?</h2>
      <p className="muted small" style={{ marginTop: -4 }}>
        Share of the {total} device{total === 1 ? '' : 's'} this server has seen that have the same value. The fewer, the easier you are to track.
      </p>
      <div className="rarity">
        {Object.entries(rarity).map(([k, v]) => {
          const pct = v.total ? (v.count / v.total) * 100 : 0;
          return (
            <div key={k} style={{ display: 'contents' }}>
              <span>{RARITY_LABEL[k] ?? k}</span>
              <div className="bar" title={`${pct.toFixed(1)}%`}><span style={{ width: `${Math.max(pct, 2)}%` }} /></div>
              <span className="small muted">{v.count === 1 ? 'only you' : `${v.count} of ${v.total}`}</span>
            </div>
          );
        })}
      </div>
    </section>
  );
}
