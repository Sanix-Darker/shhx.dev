const { test, expect, devices } = require("@playwright/test");

test.describe("live share flow", () => {
  test("shares and decrypts a secret without a passphrase", async ({ browser }) => {
    const owner = await browser.newContext();
    const recipient = await browser.newContext();
    const ownerPage = await owner.newPage();
    const recipientPage = await recipient.newPage();

    await ownerPage.goto("/");
    const roomCode = await createSecret(ownerPage, {
      secret: "alpha secret from owner",
      hint: "alpha",
    });

    await recipientPage.goto(`/${roomCode}`);
    await recipientPage.getByRole("button", { name: "Open live secret" }).click();
    await expect(recipientPage.getByRole("button", { name: "Decrypt secret" })).toBeVisible();
    await recipientPage.getByRole("button", { name: "Decrypt secret" }).click();
    await expect(recipientPage.locator("[data-secret-plaintext]")).toContainText("alpha secret from owner");

    await expect(ownerPage.locator("#toast-stack")).toContainText("Someone opened the link.");
    await expect(ownerPage.locator("#toast-stack")).toContainText("Recipient decrypted the secret");

    await recipient.close();
    await owner.close();
  });

  test("exports and imports the local feed with encryption", async ({ browser }) => {
    const owner = await browser.newContext({ acceptDownloads: true });
    const page = await owner.newPage();

    await page.goto("/");
    const roomCode = await createSecret(page, {
      secret: "portable local backup secret",
      hint: "portable",
    });

    page.once("dialog", async (dialog) => {
      await dialog.accept("backup-pass");
    });
    const downloadPromise = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export encrypted feed" }).click();
    const download = await downloadPromise;
    const exportPath = await download.path();
    expect(exportPath).toBeTruthy();

    await page.evaluate(() => {
      localStorage.removeItem("shhx.localSecrets");
    });
    await page.reload();
    await expect(page.locator('#feed details.secret-card[data-room-code="' + roomCode + '"]')).toHaveCount(0);

    page.once("dialog", async (dialog) => {
      await dialog.accept("backup-pass");
    });
    await page.setInputFiles("#feed-import-file", exportPath);
    await expect(page.locator('#feed details.secret-card[data-room-code="' + roomCode + '"]')).toBeVisible();
    await expect(page.locator('#feed details.secret-card[data-room-code="' + roomCode + '"] [data-card-hint]')).toContainText("portable");

    await owner.close();
  });

  test("reports decrypt failure before passphrase success", async ({ browser }) => {
    const owner = await browser.newContext();
    const recipient = await browser.newContext();
    const ownerPage = await owner.newPage();
    const recipientPage = await recipient.newPage();

    await ownerPage.goto("/");
    const roomCode = await createSecret(ownerPage, {
      secret: "beta secret with passphrase",
      passphrase: "correct horse battery staple",
      hint: "beta",
    });

    await recipientPage.goto(`/${roomCode}`);
    await recipientPage.getByRole("button", { name: "Open live secret" }).click();
    await expect(recipientPage.getByPlaceholder("Enter the passphrase")).toBeVisible();
    await recipientPage.getByPlaceholder("Enter the passphrase").fill("wrong passphrase");
    await recipientPage.getByRole("button", { name: "Decrypt secret" }).click();
    await expect(recipientPage.locator("[data-secret-meta]")).toContainText("Could not decrypt. Check the passphrase.");
    await expect(ownerPage.locator("#toast-stack")).toContainText("Recipient failed to decrypt with the passphrase");

    await recipientPage.getByPlaceholder("Enter the passphrase").fill("correct horse battery staple");
    await recipientPage.getByRole("button", { name: "Decrypt secret" }).click();
    await expect(recipientPage.locator("[data-secret-plaintext]")).toContainText("beta secret with passphrase");
    await expect(ownerPage.locator("#toast-stack")).toContainText("Recipient decrypted the secret");

    await recipient.close();
    await owner.close();
  });

  test("shares and decrypts a TTL secret without stalling", async ({ browser }) => {
    const owner = await browser.newContext();
    const recipient = await browser.newContext();
    const ownerPage = await owner.newPage();
    const recipientPage = await recipient.newPage();

    await ownerPage.goto("/");
    const roomCode = await createSecret(ownerPage, {
      secret: "ttl secret from owner",
      hint: "ttl-basic",
      ttl: "300",
    });

    await recipientPage.goto(`/${roomCode}`);
    await recipientPage.getByRole("button", { name: "Open live secret" }).click();
    await expect(recipientPage.getByRole("button", { name: "Decrypt secret" })).toBeVisible();
    await recipientPage.getByRole("button", { name: "Decrypt secret" }).click();
    await expect(recipientPage.locator("[data-secret-plaintext]")).toContainText("ttl secret from owner");

    await recipient.close();
    await owner.close();
  });

  test("keeps a TTL secret deliverable after owner reload", async ({ browser }) => {
    const owner = await browser.newContext();
    const recipient = await browser.newContext();
    const ownerPage = await owner.newPage();
    const recipientPage = await recipient.newPage();

    await ownerPage.goto("/");
    const roomCode = await createSecret(ownerPage, {
      secret: "ttl secret after reload",
      hint: "ttl-reload",
      ttl: "300",
    });

    await ownerPage.reload();
    await expect(ownerPage.locator('#feed details.secret-card[data-room-code="' + roomCode + '"]')).toBeVisible();

    await recipientPage.goto(`/${roomCode}`);
    await recipientPage.getByRole("button", { name: "Open live secret" }).click();
    await expect(recipientPage.getByRole("button", { name: "Decrypt secret" })).toBeVisible();
    await recipientPage.getByRole("button", { name: "Decrypt secret" }).click();
    await expect(recipientPage.locator("[data-secret-plaintext]")).toContainText("ttl secret after reload");

    await recipient.close();
    await owner.close();
  });

  test("shares a TTL secret with passphrase without stalling", async ({ browser }) => {
    const owner = await browser.newContext();
    const recipient = await browser.newContext();
    const ownerPage = await owner.newPage();
    const recipientPage = await recipient.newPage();

    await ownerPage.goto("/");
    const roomCode = await createSecret(ownerPage, {
      secret: "ttl passphrase secret",
      passphrase: "ttl-passphrase",
      hint: "ttl-pass",
      ttl: "300",
    });

    await recipientPage.goto(`/${roomCode}`);
    await recipientPage.getByRole("button", { name: "Open live secret" }).click();
    await expect(recipientPage.getByPlaceholder("Enter the passphrase")).toBeVisible();
    await recipientPage.getByPlaceholder("Enter the passphrase").fill("ttl-passphrase");
    await recipientPage.getByRole("button", { name: "Decrypt secret" }).click();
    await expect(recipientPage.locator("[data-secret-plaintext]")).toContainText("ttl passphrase secret");

    await recipient.close();
    await owner.close();
  });

  test("shares a TTL secret with delete on read", async ({ browser }) => {
    const owner = await browser.newContext();
    const recipient = await browser.newContext();
    const ownerPage = await owner.newPage();
    const recipientPage = await recipient.newPage();

    await ownerPage.goto("/");
    const roomCode = await createSecret(ownerPage, {
      secret: "ttl burn secret",
      hint: "ttl-burn",
      ttl: "300",
    });

    await recipientPage.goto(`/${roomCode}`);
    await recipientPage.getByRole("button", { name: "Open live secret" }).click();
    await expect(recipientPage.getByRole("button", { name: "Decrypt secret" })).toBeVisible();
    await recipientPage.getByRole("button", { name: "Decrypt secret" }).click();
    await expect(recipientPage.locator("[data-secret-plaintext]")).toContainText("ttl burn secret");
    await expect(ownerPage.locator('#feed details.secret-card[data-room-code="' + roomCode + '"] [data-secret-meta]')).toContainText("Deleted on read.");

    await recipient.close();
    await owner.close();
  });

  test("recovers when an earlier opener leaves before the real recipient arrives", async ({ browser }) => {
    const owner = await browser.newContext();
    const preview = await browser.newContext();
    const recipient = await browser.newContext();
    const ownerPage = await owner.newPage();
    const previewPage = await preview.newPage();
    const recipientPage = await recipient.newPage();

    await ownerPage.goto("/");
    const roomCode = await createSecret(ownerPage, {
      secret: "gamma secret after preview exit",
      hint: "gamma",
    });

    await previewPage.goto(`/${roomCode}`);
    await expect(ownerPage.locator("#toast-stack")).not.toContainText("Someone opened the link.");
    await preview.close();

    await recipientPage.goto(`/${roomCode}`);
    await recipientPage.getByRole("button", { name: "Open live secret" }).click();
    await expect(ownerPage.locator("#toast-stack")).toContainText("Someone opened the link.");
    await expect(recipientPage.getByRole("button", { name: "Decrypt secret" })).toBeVisible();
    await recipientPage.getByRole("button", { name: "Decrypt secret" }).click();
    await expect(recipientPage.locator("[data-secret-plaintext]")).toContainText("gamma secret after preview exit");

    await recipient.close();
    await owner.close();
  });

  test("keeps fullscreen usable on mobile", async ({ browser }) => {
    const owner = await browser.newContext({
      ...devices["iPhone 13"],
    });
    const recipient = await browser.newContext({
      ...devices["iPhone 13"],
    });
    const ownerPage = await owner.newPage();
    const recipientPage = await recipient.newPage();

    await ownerPage.goto("/");
    if (!(await ownerPage.locator("#create-secret-input").isVisible())) {
      await ownerPage.locator("#composer > summary").click();
    }
    await ownerPage.getByRole("button", { name: "Open fullscreen editor" }).click();
    await expect(ownerPage.locator("#composer.is-fullscreen-panel")).toBeVisible();
    await expect(ownerPage.locator("#create-secret-input")).toBeVisible();
    await ownerPage.getByPlaceholder("Write one secret. Keep it short and intentional.").fill("mobile fullscreen secret");
    await ownerPage.getByRole("button", { name: "Create secret" }).click();
    await ownerPage.getByRole("button", { name: "Exit fullscreen editor" }).click();

    const card = ownerPage.locator('#feed details.secret-card[data-role="owner"]').first();
    await expect(card).toBeVisible();
    const roomCode = await card.getAttribute("data-room-code");
    expect(roomCode).toBeTruthy();

    await card.locator("[data-focus-card]").click();
    await expect(card).toHaveClass(/is-foreground/);

    await recipientPage.goto(`/${roomCode}`);
    await recipientPage.getByRole("button", { name: "Open live secret" }).click();
    await expect(recipientPage.getByRole("button", { name: "Decrypt secret" })).toBeVisible();

    await recipient.close();
    await owner.close();
  });
});

async function createSecret(page, options) {
  const composerInput = page.locator("#create-secret-input");
  const composerVisible = await composerInput.isVisible().catch(() => false);
  if (!composerVisible) {
    await page.locator("#composer > summary").click();
    await expect(composerInput).toBeVisible();
  }
  await composerInput.fill(options.secret);
  if (options.hint) {
    await page.locator("#create-hint-input").fill(options.hint);
  }
  if (options.passphrase) {
    await page.locator("#create-passphrase-input").fill(options.passphrase);
  }
  if (options.ttl) {
    await page.locator("#create-ttl-select").selectOption(options.ttl);
  }
  if (options.burnAfterRead === false) {
    await page.locator("#create-burn-button").click();
  }
  await page.locator("#create-secret-button").click();

  const card = page.locator('#feed details.secret-card[data-role="owner"]').first();
  await expect(card).toBeVisible();
  await expect(card.locator("[data-secret-meta]")).not.toContainText("Saved locally. Waiting for network");

  const roomCode = await card.getAttribute("data-room-code");
  expect(roomCode).toBeTruthy();
  return roomCode;
}
