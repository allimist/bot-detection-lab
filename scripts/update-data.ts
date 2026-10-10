// Downloads the free IP datasets the API uses into ./data. Run monthly: `npm run data`.
//
//   DB-IP Lite city + ASN (CC BY 4.0)        https://db-ip.com/db/lite.php
//   X4BNet datacenter / VPN ranges (MIT)     https://github.com/X4BNet/lists_vpn
//   Tor exit relays                          https://check.torproject.org/torbulkexitlist
//   IANA tz database zone.tab + backward     https://github.com/eggert/tz
import { mkdirSync, writeFileSync, renameSync, existsSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DATA = process.env.DATA_DIR ?? fileURLToPath(new URL('../data/', import.meta.url));
mkdirSync(DATA, { recursive: true });

const month = (back: number) => {
  const d = new Date();
  d.setUTCDate(1);
  d.setUTCMonth(d.getUTCMonth() - back);
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
};

async function get(url: string): Promise<Buffer> {
  const res = await fetch(url, { headers: { 'user-agent': 'bot-detection-lab data updater' } });
  if (!res.ok) throw new Error(`${res.status} ${url}`);
  return Buffer.from(await res.arrayBuffer());
}

function save(name: string, data: Buffer | string) {
  const tmp = path.join(DATA, `${name}.tmp`);
  writeFileSync(tmp, data);
  renameSync(tmp, path.join(DATA, name));
  console.log(`  ✓ ${name} (${(Buffer.byteLength(data) / 1024 / 1024).toFixed(1)} MB)`);
}

async function dbip(kind: 'city' | 'asn') {
  // A new file appears at the start of each month; fall back to last month's if it's not out yet.
  for (const back of [0, 1, 2]) {
    try {
      const gz = await get(`https://download.db-ip.com/free/dbip-${kind}-lite-${month(back)}.mmdb.gz`);
      return save(`dbip-${kind}-lite.mmdb`, gunzipSync(gz));
    } catch (e) {
      if (back === 2) throw e;
    }
  }
}

const jobs: [string, () => Promise<unknown>][] = [
  ['DB-IP city', () => dbip('city')],
  ['DB-IP ASN', () => dbip('asn')],
  ['datacenter ranges', async () => save('datacenter-ipv4.txt', await get('https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt'))],
  ['VPN ranges', async () => save('vpn-ipv4.txt', await get('https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt'))],
  ['datacenter ASNs', async () => save('datacenter-asn.txt', await get('https://raw.githubusercontent.com/X4BNet/lists_vpn/main/input/datacenter/ASN.txt'))],
  ['Tor exits', async () => save('tor-exits.txt', await get('https://check.torproject.org/torbulkexitlist'))],
  ['tz zone.tab', async () => save('zone.tab', await get('https://raw.githubusercontent.com/eggert/tz/main/zone.tab'))],
  ['tz backward', async () => save('tz-backward', await get('https://raw.githubusercontent.com/eggert/tz/main/backward'))],
];

let failed = 0;
for (const [label, job] of jobs) {
  console.log(`${label}…`);
  try {
    await job();
  } catch (e) {
    failed++;
    console.error(`  ✗ ${label}: ${(e as Error).message}`);
  }
}
console.log(failed ? `\n${failed} download(s) failed; the API runs without them.` : `\nAll datasets saved to ${DATA}`);
if (failed && !existsSync(path.join(DATA, 'dbip-city-lite.mmdb'))) process.exitCode = 1;
