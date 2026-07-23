import { test, expect } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";

/**
 * Fast UI unit test — no portal login required.
 * Loads a minimal app form fixture + bastion.js and checks auth-mode toggles.
 */
test.describe("admin apps auth-mode toggles", () => {
  test("subdomain shows auth section; generic_form shows login fields", async ({
    page,
  }) => {
    const bastionJs = fs.readFileSync(
      path.join(__dirname, "../../app/static/js/bastion.js"),
      "utf8",
    );

    await page.setContent(`<!DOCTYPE html>
<html><body>
<form id="app-form">
  <select id="access_mode" name="access_mode" data-access-mode-select>
    <option value="sso_gate" selected>SSO Gate (lanceur)</option>
    <option value="subdomain_proxy">Sous-domaine dédié (reverse proxy)</option>
    <option value="legacy_path_proxy">Chemin /proxy/ (legacy, avancé)</option>
  </select>
  <label id="upstream-url-label">URL</label>
  <p id="upstream-url-help"></p>
  <input id="upstream_url" name="upstream_url" />
  <div id="public-fqdn-group" hidden></div>
  <div id="access-mode-legacy-warning" hidden></div>

  <div id="auth-mode-section" hidden>
    <select id="auth_mode" name="auth_mode" data-auth-mode-select>
      <option value="sso" selected>SSO</option>
      <option value="generic_form">Vault — Formulaire de login</option>
      <option value="generic_basic_auth">Vault — Basic Auth</option>
      <option value="generic_wsse">Vault — X-WSSE (UsernameToken)</option>
    </select>
    <p id="generic-wsse-help" hidden>WSSE help</p>
    <div id="generic-form-fields" hidden>
      <input id="login_form_url" name="login_form_url" />
    </div>
  </div>
</form>
<script>${bastionJs}</script>
</body></html>`);

    const authSection = page.locator("#auth-mode-section");
    const genericFields = page.locator("#generic-form-fields");
    const wsseHelp = page.locator("#generic-wsse-help");

    await expect(authSection).toBeHidden();
    await expect(genericFields).toBeHidden();

    await page.selectOption("#access_mode", "subdomain_proxy");
    await expect(authSection).toBeVisible();
    await expect(genericFields).toBeHidden();
    await expect(wsseHelp).toBeHidden();

    await page.selectOption("#auth_mode", "generic_form");
    await expect(genericFields).toBeVisible();
    await expect(wsseHelp).toBeHidden();

    await page.selectOption("#auth_mode", "generic_wsse");
    await expect(genericFields).toBeHidden();
    await expect(wsseHelp).toBeVisible();

    await page.selectOption("#auth_mode", "generic_basic_auth");
    await expect(genericFields).toBeHidden();
    await expect(wsseHelp).toBeHidden();

    await page.selectOption("#auth_mode", "sso");
    await expect(genericFields).toBeHidden();

    await page.selectOption("#access_mode", "sso_gate");
    await expect(authSection).toBeHidden();
  });

  test("edit initial state: generic_form keeps fields visible", async ({ page }) => {
    const bastionJs = fs.readFileSync(
      path.join(__dirname, "../../app/static/js/bastion.js"),
      "utf8",
    );

    await page.setContent(`<!DOCTYPE html>
<html><body>
<form id="app-form">
  <select id="access_mode" name="access_mode" data-access-mode-select>
    <option value="sso_gate">SSO Gate</option>
    <option value="subdomain_proxy" selected>Sous-domaine dédié</option>
  </select>
  <label id="upstream-url-label">URL</label>
  <p id="upstream-url-help"></p>
  <div id="auth-mode-section" hidden>
    <select id="auth_mode" name="auth_mode" data-auth-mode-select>
      <option value="sso">SSO</option>
      <option value="generic_form" selected>Vault — Formulaire de login</option>
    </select>
    <div id="generic-form-fields" hidden>
      <input id="login_form_url" />
    </div>
  </div>
</form>
<script>${bastionJs}</script>
</body></html>`);

    await expect(page.locator("#auth-mode-section")).toBeVisible();
    await expect(page.locator("#generic-form-fields")).toBeVisible();
  });
});
