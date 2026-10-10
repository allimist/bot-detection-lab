// JA4 TLS fingerprinting without a proxy in front: a raw TCP listener reads the ClientHello,
// computes JA4, puts the bytes back and hands the socket to the normal HTTPS server.
// Spec: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import type https from 'node:https';
import path from 'node:path';
import type { TlsSignals } from '@bdl/scoring';

const isGrease = (v: number) => (v & 0x0f0f) === 0x0a0a && v >> 8 === (v & 0xff);
const hex4 = (v: number) => v.toString(16).padStart(4, '0');
const sha12 = (s: string) => createHash('sha256').update(s).digest('hex').slice(0, 12);
const VERSIONS: Record<number, string> = { 0x0304: '13', 0x0303: '12', 0x0302: '11', 0x0301: '10', 0x0300: 's3' };

export interface ClientHello {
  version: number;          // highest supported version
  ciphers: number[];
  extensions: number[];     // in order, GREASE included
  sni: string | null;
  alpn: string[];
  signatureAlgorithms: number[];
}

/** Bytes needed for the whole first handshake message: -1 = not TLS, 0 = don't know yet. */
export function helloBytesNeeded(buf: Buffer): number {
  if (buf.length < 1) return 0;
  if (buf[0] !== 0x16) return -1;
  if (buf.length < 9) return 0;
  const handshakeLen = buf.readUIntBE(6, 3);
  const recordLen = buf.readUInt16BE(3);
  // The handshake can span several records; each extra record adds a 5-byte header.
  const records = Math.max(1, Math.ceil((handshakeLen + 4) / Math.max(recordLen, 1)));
  return handshakeLen + 4 + records * 5;
}

/** Join the handshake fragments of consecutive TLS records. */
function handshakeBytes(buf: Buffer): Buffer {
  const parts: Buffer[] = [];
  let off = 0;
  while (off + 5 <= buf.length && buf[off] === 0x16) {
    const len = buf.readUInt16BE(off + 3);
    parts.push(buf.subarray(off + 5, Math.min(off + 5 + len, buf.length)));
    off += 5 + len;
  }
  return Buffer.concat(parts);
}

export function parseClientHello(record: Buffer): ClientHello {
  const hs = handshakeBytes(record);
  if (hs[0] !== 0x01) throw new Error('not a ClientHello');
  let p = 4;
  const legacyVersion = hs.readUInt16BE(p);
  p += 2 + 32; // version + random
  p += 1 + hs[p]!; // session id
  const cipherLen = hs.readUInt16BE(p);
  p += 2;
  const ciphers: number[] = [];
  for (let i = 0; i < cipherLen; i += 2) ciphers.push(hs.readUInt16BE(p + i));
  p += cipherLen;
  p += 1 + hs[p]!; // compression methods

  const hello: ClientHello = { version: legacyVersion, ciphers, extensions: [], sni: null, alpn: [], signatureAlgorithms: [] };
  if (p + 2 > hs.length) return hello;
  const end = Math.min(hs.length, p + 2 + hs.readUInt16BE(p));
  p += 2;
  let maxVersion = 0;
  while (p + 4 <= end) {
    const type = hs.readUInt16BE(p);
    const len = hs.readUInt16BE(p + 2);
    const data = hs.subarray(p + 4, p + 4 + len);
    p += 4 + len;
    hello.extensions.push(type);
    if (type === 0x0000 && data.length > 5) hello.sni = data.subarray(5, 5 + data.readUInt16BE(3)).toString('latin1');
    if (type === 0x0010 && data.length > 2) {
      for (let q = 2; q < data.length; ) {
        const l = data[q]!;
        hello.alpn.push(data.subarray(q + 1, q + 1 + l).toString('latin1'));
        q += 1 + l;
      }
    }
    if (type === 0x002b && data.length > 1) {
      for (let q = 1; q + 1 < data.length; q += 2) {
        const v = data.readUInt16BE(q);
        if (!isGrease(v)) maxVersion = Math.max(maxVersion, v);
      }
    }
    if (type === 0x000d && data.length > 2) {
      for (let q = 2; q + 1 < data.length; q += 2) hello.signatureAlgorithms.push(data.readUInt16BE(q));
    }
  }
  if (maxVersion) hello.version = maxVersion;
  return hello;
}

function alpnChars(alpn: string | undefined): string {
  if (!alpn) return '00';
  const first = alpn[0]!;
  const last = alpn[alpn.length - 1]!;
  if (/[a-z0-9]/i.test(first) && /[a-z0-9]/i.test(last)) return first + last;
  const h = Buffer.from(alpn, 'latin1').toString('hex');
  return h[0]! + h[h.length - 1]!;
}

export function ja4(h: ClientHello, transport: 't' | 'q' = 't'): TlsSignals {
  const ciphers = h.ciphers.filter((c) => !isGrease(c));
  const exts = h.extensions.filter((e) => !isGrease(e));
  const two = (n: number) => String(Math.min(n, 99)).padStart(2, '0');
  const a = `${transport}${VERSIONS[h.version] ?? '00'}${h.sni ? 'd' : 'i'}${two(ciphers.length)}${two(exts.length)}${alpnChars(h.alpn[0])}`;
  const b = ciphers.length ? sha12(ciphers.map(hex4).sort().join(',')) : '000000000000';
  const extList = exts.filter((e) => e !== 0x0000 && e !== 0x0010).map(hex4).sort().join(',');
  const sigs = h.signatureAlgorithms.map(hex4).join(',');
  const c = extList ? sha12(sigs ? `${extList}_${sigs}` : extList) : '000000000000';
  return {
    ja4: `${a}_${b}_${c}`,
    alpn: h.alpn[0] ?? '',
    ciphers: ciphers.length,
    extensions: exts.length,
    grease: h.ciphers.some(isGrease) || h.extensions.some(isGrease),
    cipherHash: b,
  };
}

export const connKey = (s: { remoteAddress?: string; remotePort?: number }) => `${s.remoteAddress}|${s.remotePort}`;

/**
 * A TCP server that fingerprints each TLS handshake and passes the connection on to `httpsServer`.
 * Fingerprints are kept in `store` (keyed by remote address + port) until the socket closes.
 */
export function createJa4Listener(httpsServer: https.Server, store: Map<string, TlsSignals>) {
  return net.createServer((sock) => {
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => sock.destroy(), 10_000);
    const onData = (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      const need = helloBytesNeeded(buf);
      if (need === 0 || (need > 0 && buf.length < need && buf.length < 65_536)) return;
      clearTimeout(timer);
      sock.removeListener('data', onData);
      sock.pause();
      if (need > 0) {
        try {
          const key = connKey(sock);
          store.set(key, ja4(parseClientHello(buf)));
          sock.once('close', () => store.delete(key));
        } catch {
          // malformed hello: let the TLS server reject it
        }
      }
      sock.unshift(buf);
      httpsServer.emit('connection', sock);
      process.nextTick(() => sock.resume());
    };
    sock.on('data', onData);
    sock.on('error', () => sock.destroy());
  });
}

/** Use TLS_CERT / TLS_KEY when given, otherwise a self-signed localhost certificate cached in data/tls. */
export async function loadCertificate(dataDir: string): Promise<{ cert: string; key: string; selfSigned: boolean }> {
  if (process.env.TLS_CERT && process.env.TLS_KEY)
    return { cert: readFileSync(process.env.TLS_CERT, 'utf8'), key: readFileSync(process.env.TLS_KEY, 'utf8'), selfSigned: false };
  const dir = path.join(dataDir, 'tls');
  const certPath = path.join(dir, 'localhost.crt');
  const keyPath = path.join(dir, 'localhost.key');
  if (!existsSync(certPath)) {
    const { generate } = await import('selfsigned');
    const notAfter = new Date();
    notAfter.setFullYear(notAfter.getFullYear() + 2);
    const pems = await generate([{ name: 'commonName', value: 'localhost' }], {
      keySize: 2048,
      algorithm: 'sha256',
      notAfterDate: notAfter,
      extensions: [{ name: 'subjectAltName', altNames: [{ type: 2, value: 'localhost' }, { type: 7, ip: '127.0.0.1' }, { type: 7, ip: '::1' }] }],
    });
    mkdirSync(dir, { recursive: true });
    writeFileSync(certPath, pems.cert);
    writeFileSync(keyPath, pems.private);
  }
  return { cert: readFileSync(certPath, 'utf8'), key: readFileSync(keyPath, 'utf8'), selfSigned: true };
}
