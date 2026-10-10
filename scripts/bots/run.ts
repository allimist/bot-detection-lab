// Attack the running app with the usual bot toolkits and print what each one gets.
//
//   npm start                 # in another terminal (serves https://localhost:5443)
//   npm run bots              # all scenarios
//   npm run bots -- --ci      # exit 1 if any automated client is scored "human"
//   npm run bots -- --only=stealth,curl
//
// Results are also written to docs/bot-results.md for the README.
import { execFile } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import https from 'node:https';
import { promisify } from 'node:util';
import type { CheckResponse } from '@bdl/scoring';

const run = promisify(execFile);
const BASE = (process.env.BASE_URL ?? 'https://localhost:5443').replace(/\/$/, '');
const args = process.argv.slice(2);
const CI = args.includes('--ci');
const ONLY = args.find((a) => a.startsWith('--only='))?.slice(7).split(',');
const HEADFUL = !args.includes('--no-headful');

const CHROME_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';

interface Scenario {
  id: string;
  name: string;
  run: () => Promise<CheckResponse>;
}

// ---------------------------------------------------------------- plain HTTP clients

const scenarios: Scenario[] = [
  {
    id: 'curl',
    name: 'curl',
    run: async () => JSON.parse((await run('curl', ['-sk', `${BASE}/api/inspect`])).stdout),
  },
  {
    id: 'python',
    name: 'Python urllib',
    run: async () => {
      const code = `import urllib.request,ssl,sys;print(urllib.request.urlopen(sys.argv[1],context=ssl._create_unverified_context()).read().decode())`;
      return JSON.parse((await run('python3', ['-c', code, `${BASE}/api/inspect`])).stdout);
    },
  },
  {
    id: 'python-chrome-ua',
    name: 'Python with copied Chrome headers',
    run: async () => {
      const code = `import urllib.request,ssl,sys
r=urllib.request.Request(sys.argv[1],headers={'User-Agent':sys.argv[2],'Accept':'*/*','Accept-Language':'en-US,en;q=0.9','sec-ch-ua':'"Chromium";v="141"','sec-ch-ua-platform':'"Windows"','sec-fetch-mode':'cors','sec-fetch-site':'same-origin'})
print(urllib.request.urlopen(r,context=ssl._create_unverified_context()).read().decode())`;
      return JSON.parse((await run('python3', ['-c', code, `${BASE}/api/inspect`, CHROME_UA])).stdout);
    },
  },
  {
    id: 'node-chrome-ua',
    name: 'Node https with Chrome User-Agent',
    run: () =>
      new Promise((resolve, reject) => {
        https
          .get(`${BASE}/api/inspect`, { rejectUnauthorized: false, headers: { 'user-agent': CHROME_UA, 'accept-language': 'en-US,en;q=0.9', accept: '*/*' } }, (res) => {
            let body = '';
            res.on('data', (c) => (body += c));
            res.on('end', () => resolve(JSON.parse(body)));
          })
          .on('error', reject);
      }),
  },
];

// ---------------------------------------------------------------- real browsers driven by automation

async function waitForVerdict(evaluate: (fn: string) => Promise<unknown>): Promise<CheckResponse> {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    const r = await evaluate('window.__botcheck ? JSON.stringify(window.__botcheck) : null');
    if (typeof r === 'string') return JSON.parse(r);
    await new Promise((res) => setTimeout(res, 250));
  }
  throw new Error('no verdict within 20 s');
}

async function playwright(opts: { headless: boolean; channel?: string; human?: boolean }): Promise<CheckResponse> {
  const { chromium } = await import('playwright');
  const browser = await chromium.launch({ headless: opts.headless, channel: opts.channel });
  try {
    const page = await (await browser.newContext({ ignoreHTTPSErrors: true })).newPage();
    await page.goto(`${BASE}/`);
    const first = await waitForVerdict((fn) => page.evaluate(fn));
    if (!opts.human) return first;
    // Scripted "human": straight-line mouse moves and evenly-timed typing, then ask for a re-score.
    await page.mouse.move(100, 100);
    await page.mouse.move(700, 400, { steps: 40 });
    await page.mouse.move(300, 600, { steps: 30 });
    await page.click('textarea');
    await page.keyboard.type('I am definitely a human being', { delay: 40 });
    const before = first.result.findings.length;
    await page.click('text=Re-check with my behaviour');
    await page.waitForFunction((n) => (window as unknown as { __botcheck: CheckResponse }).__botcheck.result.findings.some((f) => f.category === 'behavior' && f.id !== 'beh.none') || n < 0, before, { timeout: 10_000 });
    return JSON.parse(await page.evaluate('JSON.stringify(window.__botcheck)'));
  } finally {
    await browser.close();
  }
}

async function puppeteer(stealth: boolean): Promise<CheckResponse> {
  const { chromium } = await import('playwright');
  const executablePath = chromium.executablePath();
  let launcher: typeof import('puppeteer-core').default;
  if (stealth) {
    const { addExtra } = await import('puppeteer-extra');
    const Stealth = (await import('puppeteer-extra-plugin-stealth')).default;
    launcher = addExtra((await import('puppeteer-core')).default as never).use(Stealth()) as unknown as typeof launcher;
  } else {
    launcher = (await import('puppeteer-core')).default;
  }
  const browser = await launcher.launch({ executablePath, headless: true, acceptInsecureCerts: true, args: ['--no-sandbox'] });
  try {
    const page = await browser.newPage();
    await page.goto(`${BASE}/`);
    return await waitForVerdict((fn) => page.evaluate(fn));
  } finally {
    await browser.close();
  }
}

async function selenium(): Promise<CheckResponse> {
  const { Builder } = await import('selenium-webdriver');
  const chrome = await import('selenium-webdriver/chrome.js');
  const options = new chrome.Options();
  options.addArguments('--headless=new', '--no-sandbox');
  options.setAcceptInsecureCerts(true);
  const driver = await new Builder().forBrowser('chrome').setChromeOptions(options).build();
  try {
    await driver.get(`${BASE}/`);
    return await waitForVerdict((fn) => driver.executeScript(`return ${fn}`));
  } finally {
    await driver.quit();
  }
}

scenarios.push(
  { id: 'playwright', name: 'Playwright headless (default shell)', run: () => playwright({ headless: true }) },
  { id: 'playwright-new', name: 'Playwright headless Chromium (new headless)', run: () => playwright({ headless: true, channel: 'chromium' }) },
  { id: 'puppeteer', name: 'Puppeteer headless', run: () => puppeteer(false) },
  { id: 'stealth', name: 'Puppeteer + stealth plugin', run: () => puppeteer(true) },
  { id: 'selenium', name: 'Selenium + ChromeDriver headless', run: selenium },
);
if (HEADFUL) {
  scenarios.push(
    { id: 'playwright-headful', name: 'Playwright, real Chrome window', run: () => playwright({ headless: false, channel: 'chrome' }) },
    { id: 'playwright-human', name: 'Playwright, real Chrome + scripted mouse & typing', run: () => playwright({ headless: false, channel: 'chrome', human: true }) },
  );
}

// ---------------------------------------------------------------- run

interface Row { scenario: Scenario; res?: CheckResponse; error?: string }
const rows: Row[] = [];
for (const s of scenarios.filter((s) => !ONLY || ONLY.includes(s.id))) {
  process.stdout.write(`${s.name.padEnd(52)} `);
  try {
    const res = await s.run();
    rows.push({ scenario: s, res });
    console.log(`${res.result.verdict.padEnd(10)} ${String(res.result.score).padStart(3)}`);
  } catch (e) {
    rows.push({ scenario: s, error: (e as Error).message.split('\n')[0] });
    console.log(`error: ${(e as Error).message.split('\n')[0]}`);
  }
}

const icon = { human: '🟢 human', suspicious: '🟠 suspicious', bot: '🔴 bot' } as const;
const reasons = (r: CheckResponse) =>
  r.result.findings.filter((f) => f.points > 0).slice(0, 4).map((f) => `${f.title} (+${f.points})`).join(' · ');
const md = [
  '| Client | Verdict | Risk | Main reasons |',
  '|---|---|---|---|',
  ...rows.map(({ scenario, res, error }) =>
    res ? `| ${scenario.name} | ${icon[res.result.verdict]} | ${res.result.score} | ${reasons(res)} |` : `| ${scenario.name} | ⚪ skipped | – | ${error} |`,
  ),
].join('\n');
writeFileSync(new URL('../../docs/bot-results.md', import.meta.url), `<!-- generated by npm run bots on ${new Date().toISOString().slice(0, 10)} -->\n${md}\n`);
console.log(`\n${md}\n`);

if (CI) {
  const missed = rows.filter((r) => r.res?.result.verdict === 'human');
  const failed = rows.filter((r) => r.error);
  if (missed.length) console.error(`Scored as human: ${missed.map((r) => r.scenario.name).join(', ')}`);
  if (failed.length) console.error(`Did not run: ${failed.map((r) => r.scenario.name).join(', ')}`);
  if (missed.length || failed.length) process.exitCode = 1;
}
