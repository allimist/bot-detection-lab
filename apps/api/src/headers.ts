import type { FastifyRequest } from 'fastify';
import type { HeaderSignals } from '@bdl/scoring';

const PROXY_HEADERS = ['via', 'forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-real-ip', 'forwarded-for', 'client-ip', 'x-client-ip', 'proxy-connection', 'x-proxy-id', 'x-bluecoat-via'];

export function headerSignals(req: FastifyRequest, trustProxy: boolean): HeaderSignals {
  const h = req.headers;
  const one = (name: string) => {
    const v = h[name];
    return Array.isArray(v) ? v[0] ?? null : v ?? null;
  };
  const host = (one('host') ?? '').replace(/:\d+$/, '');
  const order: string[] = [];
  for (let i = 0; i < req.raw.rawHeaders.length; i += 2) order.push(req.raw.rawHeaders[i]!.toLowerCase());
  return {
    userAgent: one('user-agent'),
    acceptLanguage: one('accept-language'),
    accept: one('accept'),
    secChUa: one('sec-ch-ua'),
    secChUaPlatform: one('sec-ch-ua-platform'),
    secFetchSite: one('sec-fetch-site'),
    secFetchMode: one('sec-fetch-mode'),
    // Browsers only send client hints and Sec-Fetch-* to https or localhost.
    secure: req.protocol === 'https' || host === 'localhost' || host === '127.0.0.1' || host === '[::1]',
    // Behind our own reverse proxy these are expected, so only report them when we face the internet directly.
    proxyHeaders: trustProxy ? PROXY_HEADERS.filter((n) => n === 'via' && h[n]) : PROXY_HEADERS.filter((n) => h[n] !== undefined),
    order,
  };
}
