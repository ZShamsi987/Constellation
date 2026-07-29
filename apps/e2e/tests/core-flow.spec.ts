import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
});

test("local planning, streaming, live state, and engineering controls", async ({
  page,
}) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));

  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Your computers, working as one." }),
  ).toBeVisible();
  await expect(page.getByRole("status")).toContainText("Live");
  await expect(
    page.getByRole("heading", { name: "Computers", exact: true }),
  ).toBeVisible();
  await expect(
    page
      .getByRole("region", { name: "Plan a workload" })
      .getByRole("combobox", { name: "Model" }),
  ).toHaveValue("constellation/mock");

  await page.getByRole("button", { name: "Simulate plan" }).click();
  await expect(page.locator(".plan-result")).toContainText("single node");
  await expect(page.locator(".plan-result")).toContainText("Local only");
  await expect(page.locator(".plan-result")).toContainText("Off");

  await page.getByRole("textbox", { name: "Message" }).fill("playwright smoke");
  await page.getByRole("button", { name: "Send" }).click();
  await expect(page.locator(".chat-output")).toContainText(
    "Constellation mock response: playwright smoke",
  );
  await expect(
    page.getByText("workload completed", { exact: true }),
  ).toBeVisible();

  await page.getByRole("button", { name: "Engineering" }).click();
  await expect(
    page.getByRole("heading", { name: "Workflows and administration" }),
  ).toBeVisible();
  await expect(page.getByRole("heading", { name: "Providers" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Identities" })).toBeVisible();
  await expect(page.getByText("No plugins installed.")).toBeVisible();

  await page.getByRole("button", { name: "Visual builder" }).click();
  await expect(page.getByLabel("Workflow dependency graph")).toBeVisible();
  expect(pageErrors).toEqual([]);
});

test("keyboard navigation and reduced-motion mode remain usable", async ({
  page,
}) => {
  await page.goto("/");
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("link", { name: "Skip to main content" }),
  ).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("main")).toBeFocused();
  await expect(page.locator("html")).toHaveCSS("scroll-behavior", "auto");
});
