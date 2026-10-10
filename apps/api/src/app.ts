import { randomUUID, timingSafeEqual } from 'node:crypto';
import { existsSync } from 'node:fs';
import { isIP } from 'node:net';
import Fastify, { type FastifyRequest, type FastifyServerFactory } from 'fastify';
import cors from '@fastify/cors';
import fastifyStatic from '@fastify/static';
import { fingerprintId, geoChecks, judgedIp, score, type CheckResponse, type ClientSignals, type ServerSignals, type Signals, type TlsSignals } from '@bdl/scoring';
import { collectorBundle } from './bundle.ts';
import { Store, type VisitRow } from './db.ts';
import { headerSignals } from './headers.ts';
import { isPrivateIp, type IpIntelService } from './intel.ts';
import { sanitizeBehavior, sanitizeClient } from './sanitize.ts';
import { connKey } from './tls.ts';

export interface AppOptions {
  store: Store;
  intel: IpIntelService;
  tlsStore: Map<string, TlsSignals>;
  trustProxy: boolean;
  dev: boolean;
  token?: string;          // when set, the dashboard API and /api/check need "Authorization: Bearer <token>"
  webDist?: string;        // built SPA to serve
  httpsPort?: number | null;
  serverFactory?: FastifyServerFactory;
  logger?: boolean;
}

const BEHAVIOR_WINDOW_MS = 30 * 60_000;

export async function buildApp(o: AppOptions) {
  const app = Fastify({
    logger: o.logger ? { level: process.env.LOG_LEVEL ?? 'info' } : false,
    trustProxy: o.trustProxy,
    bodyLimit: 256 * 1024,
    ...(o.serverFactory ? { serverFactory: o.serverFactory } : {}),
  });

  await app.register(cors, { origin: process.env.CORS_ORIGIN?.split(',') ?? true, methods: ['GET', 'POST'] });
  // navigator.sendBeacon posts JSON as text/plain.
  app.addContentTypeParser('text/plain', { parseAs: 'string' }, (_req, body, done) => {
    try {
      done(null, JSON.parse(body as string));
    } catch (e) {
      done(e as Error, undefined);
    }
  });

  const authorized = (req: FastifyRequest) => {
    if (!o.token) return true;
    const given = Buffer.from((req.headers.authorization ?? '').replace(/^Bearer\s+/i, '') || String((req.query as { token?: string }).token ?? ''));
    const want = Buffer.from(o.token);
    return given.length === want.length && timingSafeEqual(given, want);
  };

  function serverSignals(req: FastifyRequest, client: ClientSignals | null): ServerSignals {
    const ip = o.intel.lookup(req.ip);
    const rtc = client?.webrtc.publicIps.find((p) => isIP(p) && !isPrivateIp(p));
    return {
      ip,
      webrtcIp: rtc && rtc !== ip.ip ? o.intel.lookup(rtc) : null,
      headers: headerSignals(req, o.trustProxy),
      tls: o.tlsStore.get(connKey(req.raw.socket)) ?? null,
      velocity: null,
      tzCountry: o.intel.tzCountry(client?.fingerprint.timezone),
      receivedAt: Date.now(),
    };
  }

  function response(row: VisitRow, withRarity: boolean): CheckResponse {
    const signals = JSON.parse(row.signals) as Signals;
    return {
      visitId: row.id,
      fingerprintId: row.fingerprint,
      createdAt: new Date(row.created_at).toISOString(),
      ip: signals.server.ip,
      webrtcIp: signals.server.webrtcIp,
      tls: signals.server.tls,
      result: { score: row.score, verdict: row.verdict, flags: JSON.parse(row.flags), findings: JSON.parse(row.findings), geo: geoChecks(signals, judgedIp(signals)) },
      ...(withRarity && signals.client ? { rarity: o.store.rarity(signals.client) } : {}),
    };
  }

  function record(req: FastifyRequest, client: ClientSignals | null, source: VisitRow['source'], site: string | null): VisitRow {
    const server = serverSignals(req, client);
    const fp = client ? fingerprintId(client.fingerprint, client.uaHints) : null;
    server.velocity = o.store.velocity(fp, server.ip.ip);
    const signals: Signals = { client, server };
    const result = score(signals);
    const id = randomUUID();
    o.store.insert({ id, createdAt: Date.now(), source, site, fingerprint: fp, signals, result });
    return o.store.get(id)!;
  }

  app.get('/api/health', async () => ({ ok: true }));

  app.get('/api/meta', async (req) => ({
    datasets: o.intel.status(),
    httpsPort: o.httpsPort ?? null,
    tls: !!o.tlsStore.get(connKey(req.raw.socket)),
    protected: !!o.token,
  }));

  /** Full check: the collector posts its signals, we add the request-side ones and score. */
  app.post('/api/collect', async (req, reply) => {
    const body = (req.body ?? {}) as { signals?: unknown; site?: unknown };
    const client = sanitizeClient(body.signals);
    if (!client) return reply.code(400).send({ error: 'bad_request', message: 'Expected { signals } from the collector.' });
    const origin = req.headers.origin;
    const source = origin && req.headers.host && !origin.endsWith(`//${req.headers.host}`) ? 'embed' : 'page';
    const row = record(req, client, source, typeof body.site === 'string' ? body.site.slice(0, 100) : null);
    return response(row, true);
  });

  /** Follow-up with the behaviour recorded since the first check. */
  app.post<{ Params: { id: string } }>('/api/collect/:id/behavior', async (req, reply) => {
    const row = o.store.get(req.params.id);
    if (!row || row.source === 'inspect') return reply.code(404).send({ error: 'not_found', message: 'Unknown visit.' });
    if (Date.now() - row.created_at > BEHAVIOR_WINDOW_MS) return reply.code(409).send({ error: 'expired', message: 'This visit is too old to update.' });
    const behavior = sanitizeBehavior((req.body as { behavior?: unknown } | undefined)?.behavior);
    if (!behavior) return reply.code(400).send({ error: 'bad_request', message: 'Expected { behavior }.' });
    const signals = JSON.parse(row.signals) as Signals;
    signals.client!.behavior = behavior;
    const result = score(signals);
    o.store.updateResult(row.id, signals, result);
    return response(o.store.get(row.id)!, false);
  });

  /** Server-to-server verification for sites that embed the collector. */
  app.get<{ Params: { id: string } }>('/api/check/:id', async (req, reply) => {
    if (!authorized(req)) return reply.code(401).send({ error: 'unauthorized', message: 'Missing or wrong API token.' });
    const row = o.store.get(req.params.id);
    if (!row) return reply.code(404).send({ error: 'not_found', message: 'Unknown visit.' });
    return response(row, false);
  });

  /** Score the request itself, no JavaScript: what curl, scrapers and HTTP libraries get. */
  app.get('/api/inspect', async (req) => response(record(req, null, 'inspect', null), false));

  app.get<{ Querystring: { verdict?: string; flag?: string; q?: string; limit?: string; offset?: string } }>('/api/visits', async (req, reply) => {
    if (!authorized(req)) return reply.code(401).send({ error: 'unauthorized', message: 'Missing or wrong API token.' });
    const { verdict, flag, q } = req.query;
    const limit = Math.min(200, Math.max(1, Number(req.query.limit) || 50));
    const offset = Math.max(0, Number(req.query.offset) || 0);
    return o.store.list({ verdict, flag, q, limit, offset });
  });

  app.get<{ Params: { id: string } }>('/api/visits/:id', async (req, reply) => {
    if (!authorized(req)) return reply.code(401).send({ error: 'unauthorized', message: 'Missing or wrong API token.' });
    const row = o.store.get(req.params.id);
    if (!row) return reply.code(404).send({ error: 'not_found', message: 'Unknown visit.' });
    return { ...response(row, false), signals: JSON.parse(row.signals) as Signals, source: row.source, site: row.site };
  });

  app.get('/api/stats', async (req, reply) => {
    if (!authorized(req)) return reply.code(401).send({ error: 'unauthorized', message: 'Missing or wrong API token.' });
    return o.store.stats();
  });

  app.post('/api/visits/clear', async (req, reply) => {
    if (!authorized(req)) return reply.code(401).send({ error: 'unauthorized', message: 'Missing or wrong API token.' });
    o.store.clear();
    return { ok: true };
  });

  app.get('/collector.js', async (_req, reply) => {
    reply.header('content-type', 'application/javascript; charset=utf-8');
    reply.header('cache-control', o.dev ? 'no-store' : 'public, max-age=300');
    reply.header('access-control-allow-origin', '*');
    return collectorBundle(o.dev);
  });

  if (o.webDist && existsSync(o.webDist)) {
    await app.register(fastifyStatic, { root: o.webDist, wildcard: false });
    app.setNotFoundHandler((req, reply) => {
      if (req.method === 'GET' && !req.url.startsWith('/api/')) return reply.sendFile('index.html');
      return reply.code(404).send({ error: 'not_found', message: 'Not found.' });
    });
  }

  return app;
}
