import type { FingerprintComponents, UaClientHints } from './types.ts';

/** cyrb53: small, fast, good-enough 53-bit string hash (no crypto.subtle, so it works on plain http). */
export function hash(input: string, seed = 0): string {
  let h1 = 0xdeadbeef ^ seed;
  let h2 = 0x41c6ce57 ^ seed;
  for (let i = 0; i < input.length; i++) {
    const ch = input.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16).padStart(14, '0');
}

/** Stable device id: only components that don't change between visits. */
export function fingerprintId(f: FingerprintComponents, hints: UaClientHints | null): string {
  return hash(JSON.stringify([
    f.canvasNoise ? 'noise' : f.canvas, f.webglVendor, f.webglRenderer, f.webglHash, f.audio, f.fonts, f.screen,
    f.hardwareConcurrency, f.deviceMemory, f.timezone, f.languages, f.platform, f.touchPoints, f.math,
    hints?.platform, hints?.architecture, hints?.model,
  ]));
}
