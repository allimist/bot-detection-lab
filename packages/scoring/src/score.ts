import type { Finding, Flag, IpIntel, ScoreResult, Signals, Verdict } from './types.ts';
import { geoChecks } from './geo.ts';
import { RULES, type Ctx } from './rules.ts';
import { parseUa } from './ua.ts';

export const THRESHOLDS = { suspicious: 25, bot: 60 } as const;

export function verdictFor(score: number): Verdict {
  if (score >= THRESHOLDS.bot) return 'bot';
  if (score >= THRESHOLDS.suspicious) return 'suspicious';
  return 'human';
}

/** The IP the network rules judge: the HTTP IP, or the WebRTC IP when HTTP came from a private network. */
export function judgedIp(s: Signals): IpIntel {
  return s.server.ip.isPrivate && s.server.webrtcIp ? s.server.webrtcIp : s.server.ip;
}

const ORDER = { fail: 0, warn: 1, info: 2, pass: 3 } as const;

/** Pure function: same signals in, same result out. */
export function score(s: Signals): ScoreResult {
  const headerUa = parseUa(s.server.headers.userAgent);
  const ua = s.client ? parseUa(s.client.userAgent) : headerUa;
  const net = judgedIp(s);
  const desktop = !ua.mobile && !s.client?.uaHints?.mobile;
  const ctx: Ctx = { s, ua, headerUa, net, desktop };

  const findings: Finding[] = [];
  for (const rule of RULES) {
    const r = rule(ctx);
    if (Array.isArray(r)) findings.push(...r);
    else if (r) findings.push(r);
  }
  findings.sort((a, b) => ORDER[a.status] - ORDER[b.status] || b.points - a.points);

  const total = Math.min(100, findings.reduce((n, f) => n + f.points, 0));
  const flags = [...new Set(findings.flatMap((f) => f.flags ?? []))].sort() as Flag[];
  return { score: total, verdict: verdictFor(total), flags, findings, geo: geoChecks(s, net) };
}
