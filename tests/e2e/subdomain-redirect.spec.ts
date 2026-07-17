import { test, expect } from "@playwright/test";

const staging = process.env.E2E_STAGING_TRANSFER_URL;

test.describe("subdomain redirect", () => {
  test.skip(
    !staging,
    "Requires E2E_STAGING_TRANSFER_URL (e.g. https://transfer.ar-systems.fr) — real CrushFTP/Keycloak. " +
      "Not mockable in pure browser e2e without MSW; deferred to staging.",
  );

  test("unauthenticated transfer host redirects to login", async ({ page }) => {
    await page.goto(staging!);
    await expect(page).toHaveURL(/login|oauth2|auth/i);
  });

  test("after auth CrushFTP UI is visible", async ({ page }) => {
    test.skip(true, "Needs interactive SSO session on staging — run manually.");
  });
});
