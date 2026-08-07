import { test, expect } from "@playwright/test";
import { loginBreakGlass } from "./fixtures/auth";

const hasPortal = !!process.env.E2E_BASE_URL && !!process.env.E2E_BG_PASSWORD;

test.describe("apps portal", () => {
  test.skip(!hasPortal, "Requires E2E_BASE_URL + E2E_BG_PASSWORD");

  test("legacy /catalogue redirects; /apps shows apps", async ({ page }) => {
    await loginBreakGlass(
      page,
      process.env.E2E_BG_USER || "admin",
      process.env.E2E_BG_PASSWORD!,
    );
    await page.goto("/catalogue");
    await expect(page).toHaveURL(/\/(apps|admin\/apps)/);
    await page.goto("/apps");
    await expect(
      page.locator(".app-card-link, .app-card, [data-app-slug], .apps-grid").first(),
    ).toBeVisible({ timeout: 10000 });
  });
});
