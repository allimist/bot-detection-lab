// Entry for the standalone <script src="/collector.js"> bundle.
//
//   <script src="https://your-host/collector.js" data-auto data-site="shop"></script>
//   window.addEventListener('botcheck', (e) => console.log(e.detail.visitId, e.detail.result.verdict));
//
// Then verify on your server: GET https://your-host/api/check/<visitId>
import { BotCheck, collect } from './index.ts';

const script = document.currentScript as HTMLScriptElement | null;
const endpoint = script?.src ? new URL(script.src).origin : '';

const api = {
  BotCheck,
  collect,
  /** One-call helper: run the check and resolve with the API response. */
  run(opts: ConstructorParameters<typeof BotCheck>[0] = {}) {
    const check = new BotCheck({ endpoint, ...opts });
    addEventListener('pagehide', () => check.beaconBehavior());
    return check.run().then((r) => {
      dispatchEvent(new CustomEvent('botcheck', { detail: r }));
      return r;
    });
  },
};

(window as unknown as { BotCheck: typeof api }).BotCheck = api;

if (script?.hasAttribute('data-auto')) {
  const go = () => api.run({ site: script.dataset.site, stun: script.dataset.stun }).catch((e) => console.warn(e));
  if (document.readyState === 'loading') addEventListener('DOMContentLoaded', go, { once: true });
  else go();
}
