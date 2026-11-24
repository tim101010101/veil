// Extended checks (COMPAT_EXTENDED=1): the extension writes an Item, and autofills it on a page.
// Usage: node ext-extended.mjs <server-url> <email> <password> <page-url>
// Runs headed (the popup never renders headless); CI wraps it in xvfb-run.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(path.join(process.env.PLAYWRIGHT_DIR, 'package.json'));
const { chromium } = require('playwright');

const args = process.argv.slice(2);
const [server, email, password, pageUrl] = args;
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
await step('vault', async () => { await page.getByText(/all items/i).first().waitFor({ timeout: 20000 }); });
await step('new-login', async () => {
  // The popup's Add button opens a separate window; the route is the same page.
  await page.goto(`chrome-extension://${id}/popup/index.html#/add-cipher?type=1`);
  await page.getByLabel(/item name/i).first().waitFor({ timeout: 15000 });
});
await step('fill-login', async () => {
  await page.getByLabel(/item name/i).first().fill('Extension written');
  await page.getByLabel(/^username/i).first().fill('ext-user');
  await page.getByLabel(/^password/i).first().fill('ext-written-pw');
  const uri = page.getByLabel(/website \(uri\)|uri/i).first();
  await uri.fill(pageUrl);
});
await step('save-login', async () => {
  await page.getByRole('button', { name: /^save$/i }).first().click();
  await page.waitForTimeout(3000);
});
// Autofill: the inline menu lives in a closed shadow root, so drive it with the keyboard.
const site = await ctx.newPage();
await site.setViewportSize({ width: 900, height: 700 });
await site.goto(pageUrl);
await site.waitForTimeout(2500);
let filled = '';
for (let attempt = 0; attempt < 5 && !filled; attempt++) {
  await site.locator('#username').click();
  await site.waitForTimeout(1500);
  await site.keyboard.press('ArrowDown');
  await site.waitForTimeout(500);
  await site.keyboard.press('Enter');
  await site.waitForTimeout(1500);
  filled = await site.locator('#password').inputValue();
}
await site.screenshot({ path: `${shots}/autofill.png` });
console.log('AUTOFILL username=' + (await site.locator('#username').inputValue()) + ' filled=' + (filled === 'ext-written-pw'));
await ctx.close();
process.exit(filled === 'ext-written-pw' ? 0 : 2);
