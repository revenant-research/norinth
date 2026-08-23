// Capture product screenshots for the landing page from a running demo server.
// Usage: node scripts/screenshots.mjs http://localhost:8011 oa@local.test 'password'
import { chromium } from "playwright-core";
import { mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { execSync } from "node:child_process";

const [base = "http://localhost:8011", email, password] = process.argv.slice(2);
const exe = execSync(`ls -d ${homedir()}/Library/Caches/ms-playwright/chromium-*/chrome-mac-arm64/Google\\ Chrome\\ for\\ Testing.app/Contents/MacOS/Google\\ Chrome\\ for\\ Testing | tail -1`).toString().trim();
const browser = await chromium.launch({ executablePath: exe, headless: true });
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
const page = await ctx.newPage();
await page.goto(base);
const r = await page.request.post(`${base}/api/auth/login`, { data: { email, password }, headers: { Origin: base } });
if (!r.ok()) throw new Error(`login failed: ${r.status()}`);
mkdirSync("public/assets/screens", { recursive: true });
const shots = [
  ["inventory", "#inventory"],
  ["deployments", "#deployments"],
  ["compliance", "#compliance"],
  ["guide", "#guide"],
  ["agents", "#agents"],
  ["monitoring", "#monitoring"],
];
for (const [name, hash] of shots) {
  await page.goto(`${base}/${hash}`);
  await page.reload();
  await page.waitForSelector("main h1", { timeout: 15000 });
  await page.waitForTimeout(1200);
  await page.screenshot({ path: `public/assets/screens/${name}.png`, clip: { x: 0, y: 0, width: 1440, height: 900 } });
  // Compress to JPEG (macOS sips); PNGs at 2x are ~3x larger.
  execSync(`sips -s format jpeg -s formatOptions 82 --resampleWidth 1800 public/assets/screens/${name}.png --out public/assets/screens/${name}.jpg >/dev/null && rm public/assets/screens/${name}.png`);
  console.log("captured", name);
}
await browser.close();
