import { test, expect } from "@playwright/test";

/**
 * SSO → /apps → click sso_gate tile opens public URL in a new tab.
 *
 * Requires a running portal with nginx injecting SSO headers, or a staging
 * env where E2E_SSO_* vars are set. Skips when E2E_BASE_URL is unset.
 */
const hasPortal = !!process.env.E2E_BASE_URL;
const hasSso = !!process.env.E2E_SSO_READY;

test.describe("user portal apps", () => {
  test.skip(!hasPortal, "Set E2E_BASE_URL to a running portal.");
  test.skip(!hasSso, "Set E2E_SSO_READY=1 when SSO login + grants are provisioned.");

  test("SSO login lands on /apps and sso_gate tile opens new tab", async ({
    page,
    context,
  }) => {
    await page.goto("/auth/login");
    // Staging: follow SSO button when present
    const sso = page.getByRole("link", { name: /Connexion SSO/i });
    if (await sso.count()) {
      await sso.click();
      // External IdP — caller must have storageState / already-authenticated session
    }

    await page.waitForURL(/\/apps/, { timeout: 60_000 });
    await expect(page.locator(".portal-main")).toBeVisible();

    const tile = page.locator(".app-tile:not(.app-tile--disabled)").first();
    await expect(tile).toBeVisible();

    const href = await tile.getAttribute("href");
    expect(href).toBeTruthy();

    const popupPromise = context.waitForEvent("page");
    await tile.click();
    const popup = await popupPromise;
    await popup.waitForLoadState("domcontentloaded");
    expect(popup.url()).toContain(new URL(href!).host);
  });
});
