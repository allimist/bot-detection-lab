// Builds packages/collector into the standalone /collector.js that other sites embed.
import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';

const entry = fileURLToPath(new URL('../../../packages/collector/src/embed.ts', import.meta.url));
let cached: Promise<string> | null = null;

export function collectorBundle(dev: boolean): Promise<string> {
  if (!cached || dev) {
    cached = build({ entryPoints: [entry], bundle: true, format: 'iife', minify: !dev, target: 'es2020', write: false, legalComments: 'none' })
      .then((r) => r.outputFiles[0]!.text);
  }
  return cached;
}
