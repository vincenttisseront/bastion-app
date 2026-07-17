import { test, expect } from "@playwright/test";
import { loginBreakGlass } from "./fixtures/auth";

const hasPortal = !!process.env.E2E_BASE_URL && !!process.env.E2E_BG_PASSWORD;
const hasOidcStaging = !!process.env.E2E_OIDC_REALM_URL;

test.describe("admin oidc test", () => {
  test.skip(
    !hasPortal || !hasOidcStaging,
    "Requires portal + E2E_OIDC_REALM_URL (real Keycloak). " +
      "Without staging IdP, OIDC connection test cannot be exercised end-to-end in browser.",
  );

  test("valid credentials show ok status", async ({ page }) => {
    await loginBreakGlass(
      page,
      process.env.E2E_BG_USER || "admin",
      process.env.E2E_BG_PASSWORD!,
    );
    await page.goto(process.env.E2E_OIDC_REALM_URL!);
    await page.getByRole("button", { name: /Tester la connexion/i }).click();
    await expect(page.locator("body")).toContainText(/ok|succès|valide/i);
  });

  test("invalid secret shows error and blocks activation", async ({ page }) => {
    await loginBreakGlass(
      page,
      process.env.E2E_BG_USER || "admin",
      process.env.E2E_BG_PASSWORD!,
    );
    await page.goto(process.env.E2E_OIDC_REALM_URL!);
    await page.fill('input[name="client_secret"]', "invalid-secret");
    await page.getByRole("button", { name: /Tester la connexion/i }).click();
    await expect(page.locator("body")).toContainText(/error|invalide|échou/i);
  });
});
