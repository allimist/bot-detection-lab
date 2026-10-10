export { hash } from '@bdl/scoring';

/** Resolve to `fallback` if the promise is slower than `ms` or throws. */
export function withTimeout<T>(p: Promise<T> | (() => Promise<T>), ms: number, fallback: T): Promise<T> {
  const promise = typeof p === 'function' ? safe(p) : p;
  return new Promise((resolve) => {
    const t = setTimeout(() => resolve(fallback), ms);
    promise.then(
      (v) => { clearTimeout(t); resolve(v); },
      () => { clearTimeout(t); resolve(fallback); },
    );
  });
}

function safe<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return fn();
  } catch (e) {
    return Promise.reject(e);
  }
}

export function attempt<T>(fn: () => T, fallback: T): T {
  try {
    return fn();
  } catch {
    return fallback;
  }
}

export const nav = navigator as Navigator & {
  deviceMemory?: number;
  userAgentData?: {
    brands: { brand: string; version: string }[];
    mobile: boolean;
    platform: string;
    getHighEntropyValues(hints: string[]): Promise<Record<string, unknown>>;
  };
  connection?: { rtt?: number };
  pdfViewerEnabled?: boolean;
};
