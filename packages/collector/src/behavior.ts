import type { BehaviorSignals } from '@bdl/scoring';

interface Point { x: number; y: number; t: number }

const MAX_POINTS = 400;

/** Records mouse, keyboard and scroll input from now on, and summarises it on demand. */
export class BehaviorTracker {
  private start = performance.now();
  private points: Point[] = [];
  private keyTimes: number[] = [];
  private mouseMoves = 0;
  private clicks = 0;
  private keys = 0;
  private scrolls = 0;
  private untrusted = 0;
  private clicksWithoutMove = 0;
  private movedSinceClick = false;
  private first: number | null = null;
  private listeners: [string, EventListener][] = [];

  constructor(private target: Window = window) {
    this.on('mousemove', (e) => {
      const m = e as MouseEvent;
      this.mouseMoves++;
      this.movedSinceClick = true;
      this.points.push({ x: m.clientX, y: m.clientY, t: m.timeStamp });
      if (this.points.length > MAX_POINTS) this.points.shift();
    });
    this.on('click', () => {
      this.clicks++;
      if (!this.movedSinceClick) this.clicksWithoutMove++;
      this.movedSinceClick = false;
    });
    this.on('keydown', (e) => {
      this.keys++;
      this.keyTimes.push(e.timeStamp);
      if (this.keyTimes.length > 100) this.keyTimes.shift();
    });
    this.on('scroll', () => this.scrolls++);
    this.on('touchstart', () => { this.movedSinceClick = true; });
  }

  private on(type: string, handler: (e: Event) => void) {
    const wrapped: EventListener = (e) => {
      if (!e.isTrusted) this.untrusted++;
      if (this.first === null && type !== 'scroll') this.first = performance.now() - this.start;
      handler(e);
    };
    this.target.addEventListener(type, wrapped, { capture: true, passive: true });
    this.listeners.push([type, wrapped]);
  }

  stop() {
    for (const [type, fn] of this.listeners) this.target.removeEventListener(type, fn, { capture: true });
    this.listeners = [];
  }

  get interacted() {
    return this.mouseMoves + this.clicks + this.keys + this.scrolls > 0;
  }

  summary(): BehaviorSignals {
    return {
      durationMs: Math.round(performance.now() - this.start),
      mouseMoves: this.mouseMoves,
      clicks: this.clicks,
      keys: this.keys,
      scrolls: this.scrolls,
      untrustedEvents: this.untrusted,
      straightness: straightness(this.points),
      speedVariance: speedVariance(this.points),
      keyIntervalStdMs: keyStd(this.keyTimes),
      clicksWithoutMove: this.clicksWithoutMove,
      firstInteractionMs: this.first === null ? null : Math.round(this.first),
    };
  }
}

/** Share of consecutive segments that continue in exactly the same direction with the same length. */
export function straightness(p: Point[]): number | null {
  if (p.length < 6) return null;
  let robotic = 0;
  let total = 0;
  for (let i = 2; i < p.length; i++) {
    const a = { x: p[i - 1]!.x - p[i - 2]!.x, y: p[i - 1]!.y - p[i - 2]!.y };
    const b = { x: p[i]!.x - p[i - 1]!.x, y: p[i]!.y - p[i - 1]!.y };
    const la = Math.hypot(a.x, a.y);
    const lb = Math.hypot(b.x, b.y);
    if (la === 0 || lb === 0 || (la < 3 && lb < 3)) continue; // pixel-sized steps are always "straight"; too short to judge
    total++;
    const sin = Math.abs(a.x * b.y - a.y * b.x) / (la * lb);
    const cos = (a.x * b.x + a.y * b.y) / (la * lb);
    if (sin < 0.02 && cos > 0 && Math.abs(la - lb) / Math.max(la, lb) < 0.1) robotic++;
  }
  return total < 5 ? null : robotic / total;
}

function speedVariance(p: Point[]): number | null {
  const speeds: number[] = [];
  for (let i = 1; i < p.length; i++) {
    const dt = p[i]!.t - p[i - 1]!.t;
    if (dt > 0) speeds.push(Math.hypot(p[i]!.x - p[i - 1]!.x, p[i]!.y - p[i - 1]!.y) / dt);
  }
  if (speeds.length < 5) return null;
  const mean = speeds.reduce((a, b) => a + b, 0) / speeds.length;
  if (mean === 0) return null;
  const sd = Math.sqrt(speeds.reduce((a, s) => a + (s - mean) ** 2, 0) / speeds.length);
  return sd / mean;
}

function keyStd(times: number[]): number | null {
  if (times.length < 4) return null;
  const gaps = times.slice(1).map((t, i) => t - times[i]!).filter((g) => g < 2000);
  if (gaps.length < 3) return null;
  const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
  return Math.sqrt(gaps.reduce((a, g) => a + (g - mean) ** 2, 0) / gaps.length);
}
