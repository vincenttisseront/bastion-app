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
    <div id="sso-bridge-group" hidden>
      <select id="sso_bridge" name="sso_bridge" data-sso-bridge-select>
        <option value="trusted_headers" selected>Injection d’identité</option>
        <option value="app_oidc">OIDC délégué</option>
      </select>
      <p data-sso-bridge-help-trusted>Trusted help</p>
      <p data-sso-bridge-help-oidc hidden>OIDC help</p>
    </div>
    <p id="generic-wsse-help" hidden>WSSE help</p>
    <div id="portal-entry-url-group" hidden>
      <input id="login_form_url" name="login_form_url" />
      <button type="button" id="btn-analyze-login-form" hidden disabled>Analyser</button>
      <span data-portal-entry-label-sso>SSO entry</span>
      <span data-portal-entry-label-generic hidden>Generic entry</span>
      <span data-portal-entry-req-oidc class="req" hidden>*</span>
      <p data-portal-entry-help-sso-trusted>SSO trusted help</p>
      <p data-portal-entry-help-sso-oidc hidden>SSO oidc help</p>
      <p data-portal-entry-help-generic hidden>Generic help</p>
    </div>
    <div id="generic-form-fields" hidden>
      <input id="login_username_field" />
    </div>
  </div>
</form>
<script>${bastionJs}</script>
</body></html>`);

    const authSection = page.locator("#auth-mode-section");
    const portalEntry = page.locator("#portal-entry-url-group");
    const genericFields = page.locator("#generic-form-fields");
    const wsseHelp = page.locator("#generic-wsse-help");
    const bridgeGroup = page.locator("#sso-bridge-group");

    await expect(authSection).toBeHidden();
    await expect(genericFields).toBeHidden();

    await page.selectOption("#access_mode", "subdomain_proxy");
    await expect(authSection).toBeVisible();
    await expect(bridgeGroup).toBeVisible();
    await expect(portalEntry).toBeVisible();
    await expect(genericFields).toBeHidden();
    await expect(wsseHelp).toBeHidden();
    await expect(page.locator("[data-portal-entry-req-oidc]")).toBeHidden();
    await expect(page.locator("[data-portal-entry-help-sso-trusted]")).toBeVisible();

    await page.selectOption("#sso_bridge", "app_oidc");
    await expect(page.locator("[data-sso-bridge-help-oidc]")).toBeVisible();
    await expect(page.locator("[data-portal-entry-req-oidc]")).toBeVisible();
    await expect(page.locator("[data-portal-entry-help-sso-oidc]")).toBeVisible();
    await expect(page.locator("[data-portal-entry-help-sso-trusted]")).toBeHidden();

    await page.selectOption("#auth_mode", "generic_form");
    await expect(bridgeGroup).toBeHidden();
    await expect(portalEntry).toBeVisible();
    await expect(genericFields).toBeVisible();
    await expect(wsseHelp).toBeHidden();
    await expect(page.locator("#btn-analyze-login-form")).toBeVisible();

    await page.selectOption("#auth_mode", "generic_wsse");
    await expect(portalEntry).toBeHidden();
    await expect(genericFields).toBeHidden();
    await expect(wsseHelp).toBeVisible();

    await page.selectOption("#auth_mode", "generic_basic_auth");
    await expect(portalEntry).toBeHidden();
    await expect(genericFields).toBeHidden();
    await expect(wsseHelp).toBeHidden();

    await page.selectOption("#auth_mode", "sso");
    await expect(bridgeGroup).toBeVisible();
    await expect(portalEntry).toBeVisible();
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
    <div id="sso-bridge-group" hidden>
      <select id="sso_bridge" data-sso-bridge-select>
        <option value="trusted_headers" selected>Injection</option>
        <option value="app_oidc">OIDC</option>
      </select>
    </div>
    <div id="portal-entry-url-group" hidden>
      <input id="login_form_url" />
      <button type="button" id="btn-analyze-login-form" hidden disabled>Analyser</button>
      <span data-portal-entry-label-sso hidden>SSO</span>
      <span data-portal-entry-label-generic>Generic</span>
      <p data-portal-entry-help-sso-trusted hidden>SSO trusted</p>
      <p data-portal-entry-help-sso-oidc hidden>SSO oidc</p>
      <p data-portal-entry-help-generic>Generic help</p>
    </div>
    <div id="generic-form-fields" hidden>
      <input id="login_username_field" />
    </div>
  </div>
</form>
<script>${bastionJs}</script>
</body></html>`);

    await expect(page.locator("#auth-mode-section")).toBeVisible();
    await expect(page.locator("#sso-bridge-group")).toBeHidden();
    await expect(page.locator("#portal-entry-url-group")).toBeVisible();
    await expect(page.locator("#generic-form-fields")).toBeVisible();
  });
});
