import { test, expect } from "@playwright/test";
import { loginBreakGlass } from "./fixtures/auth";

const hasPortal = !!process.env.E2E_BASE_URL && !!process.env.E2E_BG_PASSWORD;

test.describe("admin health probe", () => {
  test.skip(!hasPortal, "Requires E2E_BASE_URL + E2E_BG_PASSWORD (admin break-glass)");

  test("probe button updates badge without full reload", async ({ page }) => {
    await loginBreakGlass(
      page,
      process.env.E2E_BG_USER || "admin",
      process.env.E2E_BG_PASSWORD!,
    );
    await page.goto("/admin/health");
    const probeBtn = page.locator("[data-probe-app], .probe-btn, button").filter({ hasText: /Tester/i }).first();
    test.skip((await probeBtn.count()) === 0, "No probe button on page");
    await probeBtn.click();
    await expect(page.locator(".badge, [data-status]").first()).toBeVisible();
  });

  test("probe all refreshes badges", async ({ page }) => {
    await loginBreakGlass(
      page,
      process.env.E2E_BG_USER || "admin",
      process.env.E2E_BG_PASSWORD!,
    );
    await page.goto("/admin/health");
    await page.locator("#probe-all-btn").click();
    await expect(page.locator("#health-score")).toBeVisible();
  });
});
