import { test, expect } from "@playwright/test";
import { loginBreakGlass } from "./fixtures/auth";

const hasPortal = !!process.env.E2E_BASE_URL && !!process.env.E2E_BG_PASSWORD;

test.describe("admin logs", () => {
  test.skip(!hasPortal, "Requires E2E_BASE_URL + E2E_BG_PASSWORD");

  test("filter by action reduces list", async ({ page }) => {
    await loginBreakGlass(
      page,
      process.env.E2E_BG_USER || "admin",
      process.env.E2E_BG_PASSWORD!,
    );
    await page.goto("/admin/logs");
    await expect(page.getByRole("heading", { name: /Journaux/i })).toBeVisible();
    const select = page.locator('select[name="action"]');
    if ((await select.locator("option").count()) > 1) {
      await select.selectOption({ index: 1 });
      await page.getByRole("button", { name: /Filtrer/i }).click();
      await expect(page).toHaveURL(/action=/);
    }
  });

  test("no plaintext secrets visible in detail", async ({ page }) => {
    await loginBreakGlass(
      page,
      process.env.E2E_BG_USER || "admin",
      process.env.E2E_BG_PASSWORD!,
    );
    await page.goto("/admin/logs");
    const body = await page.locator("body").innerText();
    expect(body).not.toMatch(/client_secret\s*[:=]\s*[^(*\s]+/i);
  });
});
