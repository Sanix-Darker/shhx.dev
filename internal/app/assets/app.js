const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const stunServers = [{ urls: ["stun:stun.l.google.com:19302"] }];
const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
const scrambleAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ23456789";
const MAX_SECRET_LENGTH = 4096;
const MAX_PASSPHRASE_LENGTH = 128;
const MAX_HINT_LENGTH = 72;
const TOTP_CODE_LENGTH = 6;

const appState = {
  identity: null,
  sessions: new Map(),
  localVaultKey: null,
  expiryTimers: new Map(),
  activeCardFocusRoomCode: null,
  editorFullscreenOpen: false,
  composerCollapsed: false,
  relativeTimeTimerStarted: false,
  composerAnimating: false,
  composerPendingCollapsed: null,
  composerCollapseController: null,
  pendingCreateAttempts: new Map(),
};
const LOCAL_VAULT_KEY_STORAGE = "shhx.localVaultKey";
const LEGACY_LOCAL_VAULT_KEY_STORAGE = "schh.localVaultKey";
const LOCAL_SECRET_LIST_STORAGE = "shhx.localSecrets";
const LEGACY_LOCAL_SECRET_LIST_STORAGE = "schh.localSecrets";
const THEME_STORAGE_KEY = "shhx.theme";
const LEGACY_THEME_STORAGE_KEY = "schh.theme";
const IDENTITY_STORAGE_KEY = "shhx.identity";
const LEGACY_IDENTITY_STORAGE_KEY = "schh.identity";

document.addEventListener("DOMContentLoaded", async () => {
  try {
    initTheme();
    await initIdentity();
    await initLocalVault();
    setupComposer();
    setupBulkActions();
    setupFeedSearch();
    setupFeedScrollMotion();
    setupComposerCollapse();
    setupConnectivityRecovery();
    syncFeedEmptyState();
    await restoreLocalSecrets();
    await autoJoinSharedLink();
  } finally {
    markAppReady();
  }
});

function migrateLocalStorageKey(fromKey, toKey) {
  if (!fromKey || !toKey || fromKey === toKey) {
    return;
  }
  const existing = localStorage.getItem(toKey);
  if (existing !== null) {
    return;
  }
  const legacy = localStorage.getItem(fromKey);
  if (legacy === null) {
    return;
  }
  localStorage.setItem(toKey, legacy);
}

function markAppReady() {
  document.body.classList.add("app-ready");
  window.setTimeout(() => {
    document.querySelector("#boot-splash")?.remove();
  }, 240);
}

function initTheme() {
  const button = document.querySelector("#theme-toggle-button");
  if (!button) {
    return;
  }

  const applyTheme = (theme) => {
    const isLight = theme === "light";
    document.body.classList.toggle("light-theme", isLight);
    button.title = isLight ? "Switch to dark theme" : "Switch to light theme";
    button.setAttribute("aria-label", button.title);
  };

  migrateLocalStorageKey(LEGACY_THEME_STORAGE_KEY, THEME_STORAGE_KEY);
  const stored = localStorage.getItem(THEME_STORAGE_KEY);
  applyTheme(stored === "light" ? "light" : "dark");

  button.addEventListener("click", () => {
    const nextTheme = document.body.classList.contains("light-theme") ? "dark" : "light";
    localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
    applyTheme(nextTheme);
  });
}

async function initIdentity() {
  const statusNode = document.querySelector("#identity-state");
  try {
    migrateLocalStorageKey(LEGACY_IDENTITY_STORAGE_KEY, IDENTITY_STORAGE_KEY);
    const stored = localStorage.getItem(IDENTITY_STORAGE_KEY);
    let record;
    if (stored) {
      record = JSON.parse(stored);
    } else {
      const keyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"],
      );
      const publicKey = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
      const privateKey = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
      const digest = await crypto.subtle.digest("SHA-256", textEncoder.encode(JSON.stringify(publicKey)));
      record = {
        browserId: bytesToHex(new Uint8Array(digest)).slice(0, 16),
        publicKey,
        privateKey,
      };
      localStorage.setItem(IDENTITY_STORAGE_KEY, JSON.stringify(record));
    }
    appState.identity = record;
    statusNode.textContent = `browser id: ${record.browserId}`;
  } catch (error) {
    console.error(error);
    statusNode.textContent = "browser id unavailable.";
  }
}

async function initLocalVault() {
  migrateLocalStorageKey(LEGACY_LOCAL_VAULT_KEY_STORAGE, LOCAL_VAULT_KEY_STORAGE);
  const stored = localStorage.getItem(LOCAL_VAULT_KEY_STORAGE);
  if (stored) {
    appState.localVaultKey = await crypto.subtle.importKey(
      "raw",
      base64ToBytes(stored),
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"],
    );
    return;
  }

  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
  localStorage.setItem(LOCAL_VAULT_KEY_STORAGE, bytesToBase64(raw));
  appState.localVaultKey = key;
}

function setupComposer() {
  const button = document.querySelector("#create-secret-button");
  const composer = document.querySelector("#composer");
  const secretInput = document.querySelector("#create-secret-input");
  const hintInput = document.querySelector("#create-hint-input");
  const passphraseInput = document.querySelector("#create-passphrase-input");
  const totpToggle = document.querySelector("#create-totp-toggle");
  const burnToggle = document.querySelector("#create-burn-toggle");
  const burnButton = document.querySelector("#create-burn-button");
  const totpButton = document.querySelector("#create-totp-button");
  const ttlSelect = document.querySelector("#create-ttl-select");
  const collapseButton = document.querySelector("#composer-collapse-button");
  const fullscreenButton = document.querySelector("#editor-fullscreen-button");
  const gutter = document.querySelector("#secret-editor-gutter");
  const passphraseVisibilityButton = document.querySelector("#create-passphrase-visibility");
  const passphraseCopyButton = document.querySelector("#create-passphrase-copy");
  const params = new URLSearchParams(window.location.search);

  const sync = () => {
    button.disabled = !secretInput.value.trim();
    hintInput.maxLength = MAX_HINT_LENGTH;
    passphraseInput.disabled = totpToggle.checked;
    passphraseVisibilityButton.disabled = totpToggle.checked;
    passphraseCopyButton.disabled = totpToggle.checked;
    passphraseInput.placeholder = totpToggle.checked
      ? "Disabled while authenticator mode is on"
      : "Add a passphrase for extra safety";
    if (totpToggle.checked) {
      passphraseInput.type = "password";
      syncSensitiveButtonLabel(passphraseVisibilityButton, "Show passphrase");
    }
    syncComposerToggleButton(
      burnButton,
      burnToggle.checked,
      "Delete on read is on",
      "Delete on read is off",
    );
    syncComposerToggleButton(
      totpButton,
      totpToggle.checked,
      "Authenticator mode is on",
      "Authenticator mode is off",
    );
    syncEditorGutter(secretInput, gutter);
  };

  button.addEventListener("click", () => createSecret());
  secretInput.addEventListener("input", sync);
  secretInput.addEventListener("scroll", () => {
    gutter.scrollTop = secretInput.scrollTop;
  });
  passphraseInput.addEventListener("input", sync);
  burnButton.addEventListener("click", () => {
    burnToggle.checked = !burnToggle.checked;
    sync();
  });
  totpButton.addEventListener("click", () => {
    totpToggle.checked = !totpToggle.checked;
    sync();
  });
  totpToggle.addEventListener("change", sync);
  ttlSelect.addEventListener("change", sync);
  collapseButton?.addEventListener("click", () => {
    if (appState.composerCollapseController) {
      appState.composerCollapseController(true);
    }
  });
  fullscreenButton.addEventListener("click", () => {
    toggleEditorFullscreen(composer);
  });
  passphraseVisibilityButton.addEventListener("click", () => {
    toggleSensitiveInput(passphraseInput, passphraseVisibilityButton, "passphrase");
  });
  passphraseCopyButton.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(passphraseInput.value);
      updateComposerNote("Passphrase copied.");
    } catch (_error) {
      updateComposerNote("Passphrase copy failed.");
    }
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      closeActiveUI();
    }
  });
  if (params.get("compose") === "1") {
    if (composer) {
      composer.open = true;
    }
    history.replaceState(null, "", "/");
  }
  syncFullscreenButtonState(false);
  sync();
}

async function autoJoinSharedLink() {
  const shareCode = document.body.dataset.shareCode;
  if (!shareCode) {
    return;
  }

  document.body.classList.add("is-guest-view");
  const composer = document.querySelector("#composer");
  if (composer) {
    composer.hidden = true;
  }
  const guestCreateWrap = document.querySelector("#guest-create-wrap");
  const guestCreateButton = document.querySelector("#guest-create-button");
  if (guestCreateWrap && guestCreateButton) {
    guestCreateWrap.hidden = false;
    guestCreateButton.addEventListener("click", () => {
      window.location.href = "/?compose=1";
    });
  }
  updateComposerNote("Opening shared secret.");

  const response = await fetch("/ui/rooms/join", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
    body: new URLSearchParams({
      display_name: "Peer",
      room_code: shareCode,
    }),
  });

  if (!response.ok) {
    showMissingSharedSecret(response.status, shareCode);
    return;
  }

  const html = await response.text();
  const node = insertCardHTML(html);
  bootstrapSession(node);
}

function showMissingSharedSecret(status, shareCode) {
  const empty = document.querySelector("#empty-feed");
  if (empty) {
    empty.hidden = false;
    const eyebrow = empty.querySelector(".eyebrow");
    const note = empty.querySelector(".signal-note");
    if (eyebrow) {
      eyebrow.textContent = "secret";
    }
    if (note) {
      note.textContent = status === 404
        ? `No secret was found for "${shareCode}".`
        : status === 409
          ? `The secret "${shareCode}" is not available right now.`
          : `The secret "${shareCode}" could not be opened.`;
    }
  }
  showToast(
    status === 404
      ? `Secret ${shareCode} was not found.`
      : `Secret ${shareCode} could not be opened.`,
  );
}

async function createSecret() {
  const secretInput = document.querySelector("#create-secret-input");
  const hintInput = document.querySelector("#create-hint-input");
  const passphraseInput = document.querySelector("#create-passphrase-input");
  const totpToggle = document.querySelector("#create-totp-toggle");
  const ttlSelect = document.querySelector("#create-ttl-select");
  const burn = document.querySelector("#create-burn-toggle").checked;
  const plaintext = secretInput.value.trim();
  const hint = hintInput.value.trim();
  const passphrase = passphraseInput.value.trim();
  const useTOTP = totpToggle.checked;
  const ttlSeconds = ttlSelect.selectedIndex === 0 ? null : parseTTLSelection(ttlSelect.value);

  if (!plaintext) {
    return;
  }
  if (plaintext.length > MAX_SECRET_LENGTH || passphrase.length > MAX_PASSPHRASE_LENGTH || hint.length > MAX_HINT_LENGTH) {
    updateComposerNote("Input is too large.");
    return;
  }

  const localSecret = await encryptLocalValue(plaintext);
  const localPassphrase = !useTOTP && passphrase ? await encryptLocalValue(passphrase) : null;
  const localTOTPSecret = useTOTP ? await encryptLocalValue(generateTOTPSecret()) : null;
  const previousPositions = captureFeedPositions();
  const pendingSecret = {
    id: crypto.randomUUID(),
    burnAfterRead: burn,
    hint,
    searchPlaintext: plaintext,
    localSecret,
    localPassphrase,
    localTOTPSecret,
    authMode: useTOTP ? "totp" : (passphrase ? "passphrase" : "none"),
    createdAt: Date.now(),
    expiresAt: ttlSeconds === null ? null : Date.now() + (ttlSeconds * 1000),
    active: true,
    sent: false,
  };
  secretInput.value = "";
  hintInput.value = "";
  passphraseInput.value = "";
  totpToggle.checked = false;
  ttlSelect.value = "";
  ttlSelect.selectedIndex = 0;
  document.querySelector("#create-secret-button").disabled = true;
  showToast("Secret created locally. Waiting for network to publish the live link.", {
    action: null,
  });
  syncEditorGutter(secretInput, document.querySelector("#secret-editor-gutter"));

  try {
    const response = await fetch("/ui/rooms/create", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
      body: new URLSearchParams({ display_name: "Sender" }),
    });
    if (!response.ok) {
      throw new Error(`create room failed: ${response.status}`);
    }

    const html = await response.text();
    const node = insertCardHTML(html, { staged: true });
    const session = bootstrapSession(node);
    session.pendingSecret = pendingSecret;
    hydrateOwnerCard(session);
    persistLocalSecret(session.pendingSecret);
    showToast("Secret created. Share the link while you stay online.", {
      action: {
        label: "Show secret",
        onClick: () => focusSessionCard(session),
      },
    });
    await playSecretCreateAnimation(node, previousPositions);
    return;
  } catch (_error) {
    const provisionalRoomCode = randomLocalRoomCode();
    const provisionalPeerID = randomLocalPeerID();
    const node = insertCardHTML(buildPendingOwnerCardHTML(provisionalRoomCode, provisionalPeerID), { staged: true });
    const session = bootstrapSession(node, { deferStart: true, provisional: true });
    session.pendingSecret = pendingSecret;
    persistLocalSecret(session.pendingSecret);
    hydrateOwnerCard(session);
    updateStatus(session, "offline", "waiting");
    showToast("Network issue. Secret saved locally and will retry publishing.", {
      action: {
        label: "Show secret",
        onClick: () => focusSessionCard(session),
      },
    });
    void provisionOwnerSession(session);
    await playSecretCreateAnimation(node, previousPositions);
  }
}

function randomLocalRoomCode() {
  return `LOCAL-${Math.random().toString(36).slice(2, 8).toUpperCase()}`;
}

function randomLocalPeerID() {
  return `LOCAL${Math.random().toString(36).slice(2, 14).toUpperCase()}`;
}

function buildPendingOwnerCardHTML(roomCode, peerID) {
  return `
<details
  class="room-bubble secret-card"
  data-room-code="${escapeHTML(roomCode)}"
  data-role="owner"
  data-peer-id="${escapeHTML(peerID)}"
