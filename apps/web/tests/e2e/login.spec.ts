import { expect, test } from "@playwright/test";

test("renders a usable login form with hardened response headers", async ({ page }) => {
  const pageErrors: string[] = [];
  const unexpectedResponses: string[] = [];
  page.on("pageerror", error => pageErrors.push(error.message));
  page.on("response", response => {
    if (response.status() < 400) return;
    const target = new URL(response.url());
    if (response.status() === 401 && target.pathname === "/api/cloud/me") return;
    unexpectedResponses.push(`${response.status()} ${target.pathname}`);
  });

  const response = await page.goto("/");
  expect(response?.status()).toBe(200);
  expect(response?.headers()["x-frame-options"]).toBe("DENY");
  expect(response?.headers()["x-content-type-options"]).toBe("nosniff");
  expect(response?.headers()["content-security-policy"]).toContain("frame-ancestors 'none'");

  await expect(page.getByRole("heading", { name: "Forge Agent" })).toBeVisible();
  await expect(page.getByRole("button", { name: "获取验证码" })).toBeVisible();
  await expect(page.locator('input[type="email"]')).toBeEditable();
  const viewportFits = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth);
  expect(viewportFits).toBe(true);
  expect(pageErrors).toEqual([]);
  expect(unexpectedResponses).toEqual([]);
});
