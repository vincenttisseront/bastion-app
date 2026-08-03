import { Page } from "@playwright/test";

/**
 * Auth helpers for e2e.
 * Break-glass: fill /auth/login form when a local account exists.
 * SSO headers: only available behind nginx in staging — not used in local mock mode.
 */
export async function loginBreakGlass(
  page: Page,
  username: string,
  password: string,
): Promise<void> {
  await page.goto("/auth/login");
  const localTrigger = page.getByRole("button", {
    name: /Connexion locale/i,
  });
  if (await localTrigger.count()) {
    await localTrigger.click();
  }
  await page.locator("#login-panel-local input[name='username']").fill(username);
  await page.locator("#login-panel-local input[name='password']").fill(password);
  await page.locator("#login-panel-local button[type='submit']").click();
}

export function adminHeaders(): Record<string, string> {
  return {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
  };
}
