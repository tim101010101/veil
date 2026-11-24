// Step 4: the pinned Chrome extension logs in to veild and lists the Items.
// Usage: node ext-test.mjs <server-url> <email> <password> <expected item>... [--absent <item>]...
// Runs headed (the popup never renders headless); CI wraps it in xvfb-run.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(path.join(process.env.PLAYWRIGHT_DIR, 'package.json'));
const { chromium } = require('playwright');

const args = process.argv.slice(2);
const [server, email, password] = args;
const expected = [], absent = [];
for (let i = 3; i < args.length; i++) {
  if (args[i] === '--absent') absent.push(args[++i]); else expected.push(args[i]);
}
const ext = process.env.EXTENSION_DIR;
const shots = process.env.SHOTS_DIR || '/tmp/veil-compat-shots';
fs.rmSync(shots, { recursive: true, force: true }); fs.mkdirSync(shots, { recursive: true });

const ctx = await chromium.launchPersistentContext(fs.mkdtempSync('/tmp/veil-compat-profile-'), {
  channel: 'chromium', headless: false,
  args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`, '--ignore-certificate-errors'],
});
let [sw] = ctx.serviceWorkers();
if (!sw) sw = await ctx.waitForEvent('serviceworker');
const id = sw.url().split('/')[2];
const page = await ctx.newPage();
await page.setViewportSize({ width: 420, height: 640 });
let n = 0;
const snap = async (label) => page.screenshot({ path: `${shots}/${String(++n).padStart(2, '0')}-${label}.png` });
const step = async (label, fn) => {
  try { await fn(); await page.waitForTimeout(800); await snap(label); }
  catch (e) {
    await snap(label + '-FAIL').catch(() => {});
    fs.writeFileSync(`${shots}/${label}-FAIL.txt`, await page.locator('body').innerText().catch(() => ''));
    console.log('FAIL', label, e.message.split('\n')[0]);
    await ctx.close(); process.exit(1);
  }
};

await step('open', async () => { await page.goto(`chrome-extension://${id}/popup/index.html#/login`); await page.waitForTimeout(2500); });
await step('reach-login', async () => {
  for (let i = 0; i < 30; i++) {
    if (await page.getByLabel(/email/i).count()) return;
    const skip = page.getByRole('button', { name: /^skip$/i });
    const login = page.getByRole('button', { name: /^log in$/i }).or(page.getByRole('link', { name: /^log in$/i }));
    if (await skip.count()) await skip.first().click().catch(() => {});
    else if (await login.count()) await login.first().click().catch(() => {});
    await page.waitForTimeout(1000);
  }
  throw new Error('never reached the login form');
});
await step('server-menu', async () => {
  await page.getByRole('button', { name: /bitwarden\.com|accessing|logging in on/i }).first().click();
});
await step('self-hosted', async () => { await page.getByText(/self-hosted/i).first().click(); });
await step('server-url', async () => {
  await page.getByLabel(/server url/i).first().fill(server);
  await page.getByRole('button', { name: /^save$/i }).click();
});
await step('email', async () => {
  await page.getByLabel(/email/i).first().fill(email);
  await page.getByRole('button', { name: /continue/i }).click();
});
await step('password', async () => {
  await page.locator('input[type=password]').first().fill(password);
  await page.getByRole('button', { name: /log in with master password|log in/i }).first().click();
  await page.waitForTimeout(6000);
});
await step('vault', async () => {
  for (const name of expected) await page.getByText(name, { exact: false }).first().waitFor({ timeout: 20000 });
  const text = await page.locator('body').innerText();
  for (const name of absent) if (text.includes(name)) throw new Error(`${name} must not be visible`);
});
console.log('RESULT: extension lists', expected.join(', '));
await ctx.close();
