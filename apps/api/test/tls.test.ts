import { test } from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import type { TlsSignals } from '@bdl/scoring';
import { connKey, createJa4Listener, ja4, loadCertificate, type ClientHello } from '../src/tls.ts';

test('JA4 of a Chrome-like ClientHello', () => {
  // Cipher and extension lists from the JA4 spec's Chrome example, with GREASE values mixed in.
  const hello: ClientHello = {
    version: 0x0304,
    ciphers: [0x2a2a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035],
    extensions: [0x0a0a, 0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015, 0x1a1a],
    sni: 'example.com',
    alpn: ['h2', 'http/1.1'],
    signatureAlgorithms: [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
  };
  const t = ja4(hello);
  assert.equal(t.ja4, 't13d1516h2_8daaf6152771_e5627efa2ab1');
  assert.equal(t.grease, true);
});

test('the listener fingerprints a real TLS handshake and still serves HTTPS', async () => {
  const { cert, key } = await loadCertificate(mkdtempSync(path.join(tmpdir(), 'bdl-')));
  const store = new Map<string, TlsSignals>();
  let seen: TlsSignals | undefined;
  const server = https.createServer({ cert, key }, (req, res) => {
    seen = store.get(connKey(req.socket));
    res.end('ok');
  });
  const listener = createJa4Listener(server, store);
  await new Promise<void>((r) => listener.listen(0, '127.0.0.1', r));
  const port = (listener.address() as AddressInfo).port;
  const body = await new Promise<string>((resolve, reject) => {
    https.get({ host: '127.0.0.1', port, path: '/', rejectUnauthorized: false, servername: 'localhost', ALPNProtocols: ['http/1.1'] } as https.RequestOptions, (res) => {
      let d = '';
      res.on('data', (c) => (d += c));
      res.on('end', () => resolve(d));
    }).on('error', reject);
  });
  listener.close();
  assert.equal(body, 'ok');
  assert.ok(seen, 'fingerprint stored for the connection');
  assert.match(seen!.ja4, /^t13d\d{4}h1_[0-9a-f]{12}_[0-9a-f]{12}$/);
  assert.equal(seen!.alpn, 'http/1.1');
  assert.equal(seen!.grease, false); // OpenSSL doesn't GREASE
});
