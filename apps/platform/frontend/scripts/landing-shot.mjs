import { chromium } from "playwright-core";
import { execSync } from "node:child_process";
import { homedir } from "node:os";
const base = process.argv[2] || "http://localhost:8011";
const exe = execSync(`ls -d ${homedir()}/Library/Caches/ms-playwright/chromium-*/chrome-mac-arm64/Google\\ Chrome\\ for\\ Testing.app/Contents/MacOS/Google\\ Chrome\\ for\\ Testing | tail -1`).toString().trim();
const browser = await chromium.launch({ executablePath: exe, headless: true });
const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
await page.goto(base); await page.waitForTimeout(800);
// Scroll through so lazy images load before the full-page capture.
await page.evaluate(async () => { for (let y = 0; y < document.body.scrollHeight; y += 600) { window.scrollTo(0, y); await new Promise(r => setTimeout(r, 120)); } window.scrollTo(0, 0); });
await page.waitForTimeout(1200);
await page.screenshot({ path: process.argv[3] || "/tmp/landing.png", fullPage: true });
await browser.close();
