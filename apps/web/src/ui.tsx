import type { Category, Finding, Flag, Status, Verdict } from '@bdl/scoring';

export const STATUS_ICON: Record<Status, string> = { pass: '✅', info: 'ℹ️', warn: '⚠️', fail: '❌' };

export const CATEGORY_LABEL: Record<Category, string> = {
  network: 'Network · IP, VPN, proxy',
  automation: 'Automation · headless & drivers',
  consistency: 'Consistency · lies & tampering',
  tls: 'TLS handshake',
  behavior: 'Behaviour',
  fingerprint: 'Fingerprint',
};

export const FLAG_LABEL: Record<Flag, string> = {
  vpn: 'VPN', proxy: 'Proxy', tor: 'Tor', datacenter: 'Datacenter IP', automation: 'Automation',
  tampering: 'Tampering', headless: 'Headless', noJs: 'No JavaScript',
};

export const VERDICT_TEXT: Record<Verdict, string> = { human: 'Human', suspicious: 'Suspicious', bot: 'Bot' };

const VERDICT_COLOR: Record<Verdict, string> = { human: 'var(--pass)', suspicious: 'var(--warn)', bot: 'var(--fail)' };

export function Gauge({ score, verdict }: { score: number; verdict: Verdict }) {
  // Half circle, 0 on the left, 100 on the right.
  const r = 100;
  const len = Math.PI * r;
  return (
    <svg className="gauge" viewBox="0 0 240 140" width="100%" role="img" aria-label={`Bot risk ${score} of 100: ${verdict}`}>
      <path d="M20 120 A100 100 0 0 1 220 120" fill="none" stroke="var(--panel-2)" strokeWidth="18" strokeLinecap="round" />
      <path
        d="M20 120 A100 100 0 0 1 220 120"
        fill="none"
        stroke={VERDICT_COLOR[verdict]}
        strokeWidth="18"
        strokeLinecap="round"
        strokeDasharray={`${(len * Math.max(score, 1)) / 100} ${len}`}
        style={{ transition: 'stroke-dasharray 0.6s ease' }}
      />
      <text x="120" y="104" textAnchor="middle" fontSize="44" fontWeight="800" fill="var(--text)">{score}</text>
      <text x="120" y="128" textAnchor="middle" fontSize="13" fill="var(--muted)">bot risk / 100</text>
    </svg>
  );
}

export function VerdictChip({ verdict }: { verdict: Verdict }) {
  return <span className={`chip ${verdict}`}>{VERDICT_TEXT[verdict]}</span>;
}

export function Flags({ flags }: { flags: (Flag | string)[] }) {
  if (!flags.length) return null;
  return (
    <div className="chips">
      {flags.map((f) => (
        <span key={f} className="chip fail">{FLAG_LABEL[f as Flag] ?? f}</span>
      ))}
    </div>
  );
}

export function FindingList({ findings }: { findings: Finding[] }) {
  return (
    <ul className="findings">
      {findings.map((f) => (
        <li key={f.id + f.title} className="finding">
          <span className="icon" aria-label={f.status}>{STATUS_ICON[f.status]}</span>
          <div>
            <div className="title">{f.title}</div>
            <div className="detail">{f.detail}</div>
          </div>
          <span className={`points${f.points >= 30 ? ' hot' : ''}`}>{f.points ? `+${f.points}` : ''}</span>
        </li>
      ))}
    </ul>
  );
}

const ORDER: Category[] = ['automation', 'consistency', 'network', 'tls', 'behavior', 'fingerprint'];

export function FindingsByCategory({ findings }: { findings: Finding[] }) {
  const groups = ORDER.map((c) => [c, findings.filter((f) => f.category === c)] as const).filter(([, fs]) => fs.length);
  return (
    <div className="grid cols-2">
      {groups.map(([cat, fs]) => {
        const pts = fs.reduce((n, f) => n + f.points, 0);
        return (
          <section key={cat} className="panel">
            <div className="cat-head">
              <h2>{CATEGORY_LABEL[cat]}</h2>
              <span className={`points${pts ? ' hot' : ''}`}>{pts ? `+${pts}` : '0'}</span>
            </div>
            <FindingList findings={fs} />
          </section>
        );
      })}
    </div>
  );
}

export function timeAgo(ms: number): string {
  const s = Math.round((Date.now() - ms) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return new Date(ms).toLocaleDateString();
}

export function shortUa(ua: string | null): string {
  if (!ua) return '—';
  const browser = /(Edg|OPR|Firefox|HeadlessChrome|Chrome|Version)\/(\d+)/.exec(ua);
  const os = /(Windows|Mac OS X|Android|iPhone|iPad|Linux|CrOS)/.exec(ua)?.[1];
  if (!browser) return ua.slice(0, 40);
  const name = browser[1] === 'Version' ? 'Safari' : browser[1] === 'Edg' ? 'Edge' : browser[1] === 'OPR' ? 'Opera' : browser[1];
  return `${name} ${browser[2]}${os ? ` · ${os.replace('Mac OS X', 'macOS')}` : ''}`;
}
