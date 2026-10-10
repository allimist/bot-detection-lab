import http from 'node:http';
import https from 'node:https';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import type { TlsSignals } from '@bdl/scoring';
import { buildApp } from './app.ts';
import { Store } from './db.ts';
import { IpIntelService } from './intel.ts';
import { createJa4Listener, loadCertificate } from './tls.ts';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const dataDir = process.env.DATA_DIR ?? path.join(root, 'data');
const port = Number(process.env.PORT ?? 5178);
const httpsPort = process.env.HTTPS_PORT === '0' ? null : Number(process.env.HTTPS_PORT ?? 5443);
const host = process.env.HOST ?? '0.0.0.0';
const dev = process.env.NODE_ENV !== 'production';

const intel = new IpIntelService(dataDir);
const datasets = await intel.load();
const store = new Store(process.env.DB_PATH ?? path.join(dataDir, 'visits.sqlite'));
const tlsStore = new Map<string, TlsSignals>();
const cert = httpsPort ? await loadCertificate(dataDir) : null;

let httpsServer: https.Server | null = null;
const app = await buildApp({
  store,
  intel,
  tlsStore,
  dev,
  trustProxy: process.env.TRUST_PROXY === '1' || process.env.TRUST_PROXY === 'true',
  token: process.env.API_TOKEN || undefined,
  webDist: process.env.WEB_DIST ?? path.join(root, 'apps/web/dist'),
  httpsPort,
  logger: true,
  // One Fastify app behind two servers: plain HTTP, and HTTPS fed by the JA4 listener.
  serverFactory: (handler) => {
    if (cert) httpsServer = https.createServer({ cert: cert.cert, key: cert.key }, handler);
    return http.createServer(handler);
  },
});

if (!datasets.city) app.log.warn('IP datasets missing: run `npm run data` to enable country / ASN / VPN / Tor checks.');
await app.listen({ port, host });
if (httpsServer && httpsPort) {
  const listener = createJa4Listener(httpsServer, tlsStore);
  await new Promise<void>((resolve) => listener.listen(httpsPort, host, resolve));
  app.log.info(`HTTPS with JA4 fingerprinting on https://localhost:${httpsPort}${cert?.selfSigned ? ' (self-signed certificate)' : ''}`);
}

for (const sig of ['SIGINT', 'SIGTERM'] as const)
  process.on(sig, () => {
    void app.close().then(() => process.exit(0));
  });
