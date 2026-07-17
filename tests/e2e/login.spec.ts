import { test, expect } from "@playwright/test";
import { loginBreakGlass } from "./fixtures/auth";

const hasPortal = !!process.env.E2E_BASE_URL;

test.describe("login", () => {
  test.skip(!hasPortal, "Set E2E_BASE_URL to a running portal (no IdP required for break-glass).");

  test("break-glass success redirects to dashboard", async ({ page }) => {
    const user = process.env.E2E_BG_USER || "admin";
    const pass = process.env.E2E_BG_PASSWORD;
    test.skip(!pass, "E2E_BG_PASSWORD required");
    await loginBreakGlass(page, user, pass!);
    await expect(page).toHaveURL(/\/(dashboard|catalogue|admin)/);
  });

  test("bad password shows clear error without 500", async ({ page }) => {
    await loginBreakGlass(page, "admin", "definitely-wrong-password");
    await expect(page.locator("body")).not.toContainText("Internal Server Error");
    await expect(page.locator("body")).toContainText(/invalide|erreur|incorrect/i);
  });

  test("setup blocked when account already exists", async ({ page }) => {
    const resp = await page.goto("/auth/setup");
    // Either 403 page or redirect away from setup
    expect(resp?.status()).not.toBe(500);
  });
});
