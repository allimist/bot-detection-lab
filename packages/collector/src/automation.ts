import type { AutomationSignals } from '@bdl/scoring';
import { attempt, nav, withTimeout } from './util.ts';

// Names that WebDriver, Puppeteer, Playwright, PhantomJS, Nightmare and friends leave on window / document.
const DRIVER_NAME = /^(\$?cdc_|\$wdc_|__webdriver|__selenium|__driver_|__fxdriver|_selenium|callSelenium|_Selenium_IDE|__playwright|__pwInitScripts|__puppeteer|_phantom$|callPhantom$|__nightmare|domAutomation|__lastWatirAlert|__webdriverFunc|webdriver$)/i;

function automationGlobals(): string[] {
  const found = new Set<string>();
  const scan = (obj: object, prefix: string) => {
    for (const key of attempt(() => Object.getOwnPropertyNames(obj), [] as string[]))
      if (DRIVER_NAME.test(key)) found.add(prefix + key);
  };
  scan(window, '');
  scan(document, 'document.');
  for (const attr of ['webdriver', 'driver', 'selenium'])
    if (document.documentElement.getAttribute(attr) !== null) found.add(`<html ${attr}>`);
  return [...found];
}

/**
 * When something listens over the Chrome DevTools Protocol with the Runtime domain on
 * (Puppeteer, Playwright, an open DevTools window), console calls serialise their arguments,
 * which reads `error.stack`. A normal page never triggers the getter.
 */
function cdpDetected(): boolean {
  let hit = false;
  attempt(() => {
    const e = new Error('bot-check');
    Object.defineProperty(e, 'stack', {
      configurable: true,
      get() {
        hit = true;
        return '';
      },
    });
    console.debug(e);
  }, undefined);
  return hit;
}

async function permissionsNotifications(): Promise<string | null> {
  if (!nav.permissions?.query) return null;
  const s = await nav.permissions.query({ name: 'notifications' as PermissionName });
  return s.state;
}

async function voices(): Promise<number | null> {
  if (!('speechSynthesis' in window)) return null;
  const now = speechSynthesis.getVoices().length;
  if (now > 0) return now;
  // Chrome loads the list asynchronously.
  return new Promise((resolve) => {
    const done = () => resolve(speechSynthesis.getVoices().length);
    speechSynthesis.addEventListener('voiceschanged', done, { once: true });
    setTimeout(done, 700);
  });
}

export async function automation(): Promise<AutomationSignals> {
  const w = window as unknown as { chrome?: object };
  const [perm, devices, voiceCount] = await Promise.all([
    withTimeout(permissionsNotifications, 500, null),
    withTimeout(async () => (nav.mediaDevices?.enumerateDevices ? (await nav.mediaDevices.enumerateDevices()).length : null), 800, null),
    withTimeout(voices, 900, null),
  ]);
  return {
    webdriver: attempt(() => nav.webdriver ?? null, null),
    webdriverInNavigator: 'webdriver' in nav,
    automationGlobals: automationGlobals(),
    cdpDetected: cdpDetected(),
    headlessUa: /HeadlessChrome/.test(nav.userAgent),
    pluginsLength: attempt(() => nav.plugins.length, 0),
    pdfViewerEnabled: nav.pdfViewerEnabled ?? null,
    outerSize: [window.outerWidth, window.outerHeight],
    pageHidden: document.visibilityState === 'hidden',
    notificationPermission: 'Notification' in window ? Notification.permission : null,
    permissionsNotifications: perm,
    chromeObject: typeof w.chrome === 'object' && w.chrome !== null,
    chromeKeys: w.chrome ? Object.keys(w.chrome) : [],
    mediaDevices: devices,
    voices: voiceCount,
    connectionRtt: nav.connection?.rtt ?? null,
  };
}
