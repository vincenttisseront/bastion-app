/**
 * Real Chromium check: modal "Ouvrir" must POST a real HTML form to
 * /open-with-identity (top-level navigation — not fetch/XHR).
 */
import { test, expect } from "@playwright/test";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";

const repoRoot = process.cwd();

function contentType(filePath: string): string {
  if (filePath.endsWith(".js")) return "application/javascript; charset=utf-8";
  if (filePath.endsWith(".css")) return "text/css; charset=utf-8";
  if (filePath.endsWith(".html")) return "text/html; charset=utf-8";
  return "application/octet-stream";
}

async function startStaticServer(): Promise<{ baseURL: string; close: () => Promise<void> }> {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url || "/", "http://127.0.0.1");
    let rel = decodeURIComponent(url.pathname);
    if (rel === "/harness") {
      rel = "/tests/e2e/fixtures/identity-password-modal.html";
    } else if (rel.startsWith("/static/")) {
      rel = "/app" + rel;
    }
    const filePath = path.join(repoRoot, rel.replace(/^\//, ""));
    if (!filePath.startsWith(repoRoot) || !fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
      res.writeHead(404);
      res.end("not found");
      return;
    }
    res.writeHead(200, { "Content-Type": contentType(filePath) });
    fs.createReadStream(filePath).pipe(res);
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const addr = server.address();
  if (!addr || typeof addr === "string") throw new Error("no port");
  return {
    baseURL: `http://127.0.0.1:${addr.port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

test("modal Ouvrir submits HTML form to open-with-identity", async ({ page }) => {
  const staticSrv = await startStaticServer();

  const confirmClicks: string[] = [];
  await page.exposeFunction("__noteConfirmClick", (msg: string) => {
    confirmClicks.push(msg);
  });

  await page.addInitScript(() => {
    document.addEventListener(
      "click",
      (e) => {
        const t = e.target as Element | null;
        if (t && typeof t.closest === "function" && t.closest("#bastion-modal-confirm")) {
          // @ts-expect-error harness bridge
          window.__noteConfirmClick?.("open-modal button clicked");
        }
      },
      true
    );
  });

  try {
    await page.goto(`${staticSrv.baseURL}/harness`);
    await page.click("#tile-grommunio");
    await expect(page.locator("#bastion-modal")).toBeVisible();
    await expect(page.locator("#bastion-modal-confirm")).toHaveText("Ouvrir");
    await page.fill("#bastion-modal-password", "SecretPass-ForE2E");
    await page.click("#bastion-modal-confirm");

    await expect.poll(() => confirmClicks.length).toBeGreaterThan(0);
    expect(confirmClicks[0]).toBe("open-modal button clicked");

    await expect
      .poll(async () =>
        page.evaluate(() => (window as { __lastFormAction?: string }).__lastFormAction)
      )
      .toContain("/api/apps/grommunio/open-with-identity");

    const formMeta = await page.evaluate(() => ({
      method: (window as { __lastFormMethod?: string }).__lastFormMethod,
      target: (window as { __lastFormTarget?: string }).__lastFormTarget,
      body: (window as { __lastFormBody?: string }).__lastFormBody,
    }));
    expect(formMeta.method?.toLowerCase()).toBe("post");
    expect(formMeta.target).toBe("bastion_app_grommunio");
    expect(formMeta.body).toContain("password=SecretPass-ForE2E");
    expect(formMeta.body).not.toContain("/api/internal/impersonate/");
  } finally {
    await staticSrv.close();
  }
});
