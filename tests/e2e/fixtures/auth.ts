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
  await page.fill('input[name="username"]', username);
  await page.fill('input[name="password"]', password);
  await page.click('button[type="submit"]');
}

export function adminHeaders(): Record<string, string> {
  return {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
  };
}
