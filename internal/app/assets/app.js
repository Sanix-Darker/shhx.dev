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
  data-display-name="Sender"
  data-provisional="true"
  open
>
  <summary class="room-head" title="Click to open or close">
    <div class="room-title-wrap">
      <p class="eyebrow">secret</p>
      <div class="title-row">
        <h2 data-card-title>s: ${escapeHTML(roomCode)}</h2>
        <span class="ttl-mark" data-ttl-mark hidden title="This secret has a TTL" aria-label="This secret has a TTL">
          <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
            <circle cx="12" cy="12" r="8"></circle>
            <path d="M12 7v5l3 2"></path>
          </svg>
        </span>
      </div>
      <p class="fine-print card-hint" data-card-hint hidden></p>
      <p class="fine-print" data-created-at hidden></p>
    </div>
    <div class="status-stack">
      <div class="card-tools" data-card-tools>
        <button class="icon-button" type="button" data-focus-card aria-label="Show secret in foreground" title="Show secret in foreground">
          <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
            <path d="M9 4H4v5"></path><path d="M15 4h5v5"></path><path d="M20 15v5h-5"></path><path d="M4 15v5h5"></path>
          </svg>
          <span class="sr-only">Show secret in foreground</span>
        </button>
        <button class="icon-button foreground-close-button" type="button" data-unfocus-card aria-label="Exit foreground secret view" title="Exit foreground secret view">
          <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
            <path d="M6 6l12 12"></path><path d="M18 6 6 18"></path>
          </svg>
          <span class="sr-only">Exit foreground secret view</span>
        </button>
        <div class="owner-only card-tools owner-tools">
          <label class="card-select" title="Select secret">
            <input type="checkbox" data-select-card aria-label="Select secret">
            <span class="card-select-bubble" aria-hidden="true"></span>
          </label>
          <button class="icon-button" type="button" data-copy-link aria-label="Copy share link" title="Copy share link">
            <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
              <rect x="9" y="9" width="10" height="10" rx="2"></rect>
              <path d="M7 15H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h7a2 2 0 0 1 2 2v1"></path>
            </svg>
            <span class="sr-only">Copy share link</span>
          </button>
          <button class="icon-button auth-copy-button" type="button" data-copy-totp-secret aria-label="Copy authenticator secret" title="Copy authenticator secret" hidden>
            <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
              <rect x="9" y="9" width="10" height="10" rx="2"></rect>
              <path d="M7 15H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h7a2 2 0 0 1 2 2v1"></path>
            </svg>
            <span class="sr-only">Copy authenticator secret</span>
          </button>
          <button class="icon-button" type="button" data-email-link aria-label="Send share link by email" title="Send share link by email">
            <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
              <rect x="3" y="5" width="18" height="14" rx="2"></rect><path d="m5 8 7 5 7-5"></path>
            </svg>
            <span class="sr-only">Send share link by email</span>
          </button>
          <button class="icon-button" type="button" data-toggle-secret aria-label="Turn off secret" title="Turn off secret">
            <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
              <path d="M12 3v8"></path><path d="M7.5 6.75a7 7 0 1 0 9 0"></path>
            </svg>
            <span class="sr-only">Turn off secret</span>
          </button>
          <button class="icon-button danger-button" type="button" data-delete-secret aria-label="Delete secret" title="Delete secret">
            <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
              <path d="M4 7h16"></path><path d="M9 7V4h6v3"></path><path d="M7 7l1 12h8l1-12"></path><path d="M10 11v5"></path><path d="M14 11v5"></path>
            </svg>
            <span class="sr-only">Delete secret</span>
          </button>
        </div>
      </div>
      <span class="status-pill" data-room-status>offline</span>
    </div>
  </summary>
  <section class="room-panel secret-preview">
    <p class="fine-print" data-secret-meta>Saved locally. Waiting for network to publish the live link.</p>
    <pre class="plaintext" data-secret-plaintext hidden></pre>
    <div class="ciphertext" data-secret-placeholder>Encrypted payload ready.</div>
    <div class="secret-actions" data-secret-actions></div>
  </section>
</details>`;
}

function escapeHTML(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;");
}

function insertCardHTML(html, options = {}) {
  const wrapper = document.createElement("div");
  wrapper.innerHTML = html.trim();
  const node = wrapper.firstElementChild;
  collapseFeedCards();
  node.open = true;
  if (options.staged) {
    node.classList.add("is-staged");
  }
  document.querySelector("#feed").prepend(node);
  syncFeedEmptyState();
  applyFeedFilter();
  if (!options.staged) {
    requestAnimationFrame(() => node.classList.add("is-visible"));
  }
  return node;
}

function collapseFeedCards() {
  document.querySelectorAll("#feed .secret-card").forEach((card) => {
    card.open = false;
  });
}

function captureFeedPositions() {
  const positions = new Map();
  document.querySelectorAll("#feed .secret-card").forEach((card) => {
    positions.set(card.dataset.roomCode, card.getBoundingClientRect());
  });
  return positions;
}

async function playSecretCreateAnimation(node, previousPositions) {
  animateFeedReflow(previousPositions, node.dataset.roomCode);
  if (prefersReducedMotion.matches) {
    node.classList.remove("is-staged");
    node.classList.add("is-visible");
    return;
  }

  await animateComposerHandoff(node);
  node.classList.remove("is-staged");
  requestAnimationFrame(() => node.classList.add("is-visible"));
}

function animateFeedReflow(previousPositions, newRoomCode) {
  document.querySelectorAll("#feed .secret-card").forEach((card) => {
    if (card.dataset.roomCode === newRoomCode) {
      return;
    }
    const previous = previousPositions.get(card.dataset.roomCode);
    if (!previous) {
      return;
    }
    const current = card.getBoundingClientRect();
    const deltaY = previous.top - current.top;
    if (Math.abs(deltaY) < 1) {
      return;
    }
    card.classList.add("feed-shift-animate");
    card.style.transform = `translateY(${deltaY}px)`;
    requestAnimationFrame(() => {
      card.style.transform = "";
    });
    window.setTimeout(() => {
      card.classList.remove("feed-shift-animate");
      card.style.transform = "";
    }, 340);
  });
}

function animateComposerHandoff(node) {
  const composer = document.querySelector("#composer");
  const summary = composer?.querySelector("summary");
  if (!composer || !summary) {
    return Promise.resolve();
  }

  const startRect = composer.getBoundingClientRect();
  const endRect = node.getBoundingClientRect();
  const ghost = document.createElement("div");
  ghost.className = "create-handoff";
  ghost.style.left = `${startRect.left}px`;
  ghost.style.top = `${startRect.top}px`;
  ghost.style.width = `${startRect.width}px`;
  ghost.style.height = `${Math.max(summary.getBoundingClientRect().height + 110, 148)}px`;
  document.body.appendChild(ghost);

  return new Promise((resolve) => {
    requestAnimationFrame(() => {
      ghost.animate([
        {
          transform: "translate3d(0, 0, 0) scale(1)",
          opacity: 0.88,
          filter: "blur(0px)",
        },
        {
          transform: `translate3d(${(endRect.left - startRect.left) * 0.08}px, ${(endRect.top - startRect.top) * 0.52}px, 0) scale(0.97)`,
          opacity: 0.52,
          filter: "blur(1px)",
        },
        {
          transform: `translate3d(${endRect.left - startRect.left}px, ${endRect.top - startRect.top + 24}px, 0) scale(0.92)`,
          opacity: 0,
          filter: "blur(3px)",
        },
      ], {
        duration: 420,
        easing: "cubic-bezier(0.2, 0.78, 0.18, 1)",
        fill: "forwards",
      }).finished.finally(() => {
        ghost.remove();
        resolve();
      });
    });
  });
}

function bootstrapSession(node, options = {}) {
  const roomCode = node.dataset.roomCode;
  if (appState.sessions.has(roomCode)) {
    return appState.sessions.get(roomCode);
  }

  const session = {
    roomCode,
    peerId: node.dataset.peerId,
    role: node.dataset.role,
    node,
    pendingSecret: null,
    receivedSecret: null,
    roomKeyPair: null,
    baseKeyBytes: null,
    rtc: null,
    channel: null,
    eventSource: null,
    remotePeerId: null,
    isConnected: false,
    offerReady: false,
    readySent: false,
    selected: false,
    provisional: options.provisional === true || node.dataset.provisional === "true",
    provisionAttempts: 0,
    provisionTimer: null,
    isDeleted: false,
  };

  appState.sessions.set(roomCode, session);
  syncCardSearchIndex(session);
  wireSessionUI(session);
  if (!options.deferStart && !session.provisional) {
    startSession(session).catch((error) => {
      console.error(error);
      updateSessionNote(session, "Session failed.");
      updateStatus(session, "failed", "waiting");
    });
  }
  return session;
}

async function restoreLocalSecrets() {
  const stored = readStoredSecrets();
  if (stored.length === 0) {
    return;
  }

  for (const record of [...stored].reverse()) {
    if (record.expiresAt && record.expiresAt <= Date.now()) {
      removeLocalSecret(record.id);
      continue;
    }

    const response = await fetch("/ui/rooms/create", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
      body: new URLSearchParams({ display_name: "Sender" }),
    });
    if (!response.ok) {
      continue;
    }

    const html = await response.text();
    const node = insertCardHTML(html);
    const session = bootstrapSession(node);
    const restoredPlaintext = await decryptLocalValue(record.localSecret);
    session.pendingSecret = {
      ...record,
      searchPlaintext: restoredPlaintext,
      createdAt: normalizeCreatedAt(record.createdAt) ?? Date.now(),
      expiresAt: normalizeExpiresAt(record.expiresAt),
      sent: false,
    };
    hydrateOwnerCard(session);
  }

  showToast("Restored local secrets from this browser.");
}

async function provisionOwnerSession(session) {
  if (!session || session.isDeleted || !session.provisional) {
    return;
  }

  session.provisionAttempts += 1;
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
    attachProvisionedOwnerCard(session, html);
    session.provisional = false;
    session.provisionAttempts = 0;
    updateStatus(session, session.pendingSecret?.active === false ? "off" : "waiting", "waiting");
    hydrateOwnerCard(session);
    startSession(session).catch((error) => {
      console.error(error);
      updateStatus(session, "failed", "waiting");
      scheduleProvisionRetry(session);
    });
    showToast("Live link published.");
  } catch (_error) {
    updateStatus(session, "offline", "waiting");
    scheduleProvisionRetry(session);
  }
}

function scheduleProvisionRetry(session) {
  if (!session || session.isDeleted || !session.provisional) {
    return;
  }
  if (session.provisionTimer) {
    window.clearTimeout(session.provisionTimer);
  }
  const delay = Math.min(30000, 1000 * (2 ** Math.min(session.provisionAttempts, 5)));
  session.provisionTimer = window.setTimeout(() => {
    session.provisionTimer = null;
    void provisionOwnerSession(session);
  }, delay);
}

function attachProvisionedOwnerCard(session, html) {
  const wrapper = document.createElement("div");
  wrapper.innerHTML = html.trim();
  const node = wrapper.firstElementChild;
  if (!node) {
    throw new Error("missing provisioned card");
  }

  node.open = session.node.open;
  session.node.replaceWith(node);
  const previousKey = session.roomCode;
  session.roomCode = node.dataset.roomCode;
  session.peerId = node.dataset.peerId;
  session.role = node.dataset.role;
  session.node = node;
  session.eventSource?.close();
  session.eventSource = null;
  session.readySent = false;
  session.offerReady = false;
  appState.sessions.delete(previousKey);
  appState.sessions.set(session.roomCode, session);
  syncCardSearchIndex(session);
  wireSessionUI(session);
  applyFeedFilter();
}

function wireSessionUI(session) {
  const stopSummaryToggle = (event) => {
    event.preventDefault();
    event.stopPropagation();
  };
  session.node.querySelectorAll("[data-card-tools] button").forEach((node) => {
    node.addEventListener("click", stopSummaryToggle);
    node.addEventListener("mousedown", (event) => event.stopPropagation());
  });
  session.node.querySelectorAll("[data-card-tools] input").forEach((node) => {
    node.addEventListener("click", (event) => event.stopPropagation());
    node.addEventListener("mousedown", (event) => event.stopPropagation());
  });
  session.node.querySelector("[data-focus-card]").addEventListener("click", (event) => {
    stopSummaryToggle(event);
    focusSessionCard(session);
  });
  session.node.querySelector("[data-unfocus-card]").addEventListener("click", (event) => {
    stopSummaryToggle(event);
    unfocusSessionCard(session);
  });

  const factorInput = session.node.querySelector("[data-otp-input]");
  const factorVisibility = session.node.querySelector("[data-factor-visibility]");
  if (factorInput && factorVisibility) {
    factorVisibility.addEventListener("click", () => {
      toggleSensitiveInput(factorInput, factorVisibility, "passphrase");
    });
  }

  if (session.role !== "owner") {
    return;
  }

  session.node.querySelector("[data-copy-link]").addEventListener("click", async (event) => {
    stopSummaryToggle(event);
    if (session.provisional) {
      showToast("Link is still offline. Waiting for network.");
      return;
    }
    try {
      await navigator.clipboard.writeText(shareLinkFor(session.roomCode));
      showToast("Share link copied.", {
        action: {
          label: "Show secret",
          onClick: () => focusSessionCard(session),
        },
      });
    } catch (_error) {
      showToast("Copy failed.");
    }
  });
  session.node.querySelector("[data-email-link]").addEventListener("click", (event) => {
    stopSummaryToggle(event);
    if (session.provisional) {
      showToast("Link is still offline. Waiting for network.");
      return;
    }
    window.location.href = mailtoLinkFor([shareLinkFor(session.roomCode)]);
  });
  session.node.querySelector("[data-toggle-secret]").addEventListener("click", (event) => {
    stopSummaryToggle(event);
    toggleSecret(session);
  });
  session.node.querySelector("[data-delete-secret]").addEventListener("click", async (event) => {
    stopSummaryToggle(event);
    await deleteSecret(session);
  });
  session.node.querySelector("[data-select-card]").addEventListener("change", (event) => {
    session.selected = event.target.checked;
    session.node.classList.toggle("is-selected", session.selected);
    syncBulkActions();
  });

  const copyTOTP = session.node.querySelector("[data-copy-totp-secret]");
  if (copyTOTP) {
    copyTOTP.addEventListener("click", async () => {
      try {
        const secret = session.pendingSecret?.localTOTPSecret
          ? await decryptLocalValue(session.pendingSecret.localTOTPSecret)
          : "";
        await navigator.clipboard.writeText(secret);
        showToast("Authenticator secret copied.");
      } catch (_error) {
        showToast("Copy failed.");
      }
    });
  }
}

function hydrateOwnerCard(session) {
  const { pendingSecret, node } = session;
  const hintNode = node.querySelector("[data-card-hint]");
  const normalizedHint = String(pendingSecret.hint || "").trim();
  if (hintNode) {
    hintNode.hidden = !normalizedHint;
    hintNode.textContent = normalizedHint ? `"${normalizedHint}"` : "";
  }
  node.querySelector("[data-secret-meta]").textContent = session.provisional
    ? "Saved locally. Waiting for network to publish the live link."
    : pendingSecret.authMode === "totp"
      ? pendingSecret.burnAfterRead ? "Authenticator code required. Will delete on read." : "Authenticator code required."
      : pendingSecret.authMode === "passphrase"
        ? pendingSecret.burnAfterRead ? "Passphrase required. Will delete on read." : "Passphrase required."
        : pendingSecret.burnAfterRead ? "Will delete on read." : "Stays until you remove it.";
  node.querySelector("[data-secret-plaintext]").hidden = true;
  node.querySelector("[data-secret-placeholder]").hidden = false;
  setAnimatedText(
    node.querySelector("[data-secret-placeholder]"),
    session.provisional
      ? "Secret hidden locally. Waiting for network recovery."
      : "Secret hidden locally. Share the link to deliver it.",
  );
  const totpCopyButton = node.querySelector("[data-copy-totp-secret]");
  if (totpCopyButton) {
    totpCopyButton.hidden = !(pendingSecret.authMode === "totp" && pendingSecret.localTOTPSecret);
  }
  syncCreatedAt(session);
  syncTTLMark(session);
  syncCardSearchIndex(session);
  syncOwnerControls(session);
  syncBulkActions();
  scheduleSecretExpiry(session);
  ensureRelativeTimeTicker();
  applyFeedFilter();
}

function syncOwnerControls(session) {
  const toggle = session.node.querySelector("[data-toggle-secret]");
  if (!toggle) {
    return;
  }
  const isActive = session.pendingSecret?.active !== false;
  toggle.title = isActive ? "Turn off secret" : "Turn on secret";
  toggle.setAttribute("aria-label", toggle.title);
  toggle.setAttribute("aria-pressed", String(!isActive));
}

async function startSession(session) {
  session.roomKeyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );

  updateSessionNote(session, session.role === "owner" ? "Keep this page open while the other person reads it." : "Waiting for sender.");
  const eventsURL = `/api/rooms/${encodeURIComponent(session.roomCode)}/events?peer=${encodeURIComponent(session.peerId)}`;
  session.eventSource = new EventSource(eventsURL);
  session.eventSource.onmessage = async (event) => {
    await handleServerEvent(session, JSON.parse(event.data));
  };
  session.eventSource.onerror = () => {
    updateStatus(session, "offline", "waiting");
    updateSessionNote(session, "Connection interrupted. Retrying.");
  };
}

async function handleServerEvent(session, event) {
  switch (event.type) {
    case "room-state":
      syncRemotePeer(session, event.data);
      await ensurePeerConnection(session);
      await notifyReady(session);
      await maybeCreateOffer(session);
      break;
    case "peer-joined":
      session.remotePeerId = event.data.id;
      updateStatus(session, "linking", "readying");
      updateSessionNote(session, "Peer found. Building direct channel.");
      await ensurePeerConnection(session);
      await maybeCreateOffer(session);
      break;
    case "peer-left":
      session.remotePeerId = null;
      resetPeerLink(session);
      updateStatus(session, "waiting", "waiting");
      updateSessionNote(session, "Peer left.");
      break;
    case "signal":
      await handleSignal(session, event.data);
      break;
    default:
      break;
  }
}

function syncRemotePeer(session, peers) {
  const remote = peers.find((peer) => peer.id !== session.peerId);
  session.remotePeerId = remote ? remote.id : null;
  if (remote) {
    updateStatus(session, "linking", "readying");
    updateSessionNote(session, "Peer found. Building direct channel.");
  } else {
    updateStatus(session, "waiting", "waiting");
    updateSessionNote(session, session.role === "owner" ? "Waiting for someone to open the link." : "Waiting for sender.");
  }
}

async function ensurePeerConnection(session) {
  if (!session.remotePeerId || session.rtc) {
    return;
  }

  session.rtc = new RTCPeerConnection({ iceServers: stunServers });
  session.rtc.onicecandidate = ({ candidate }) => {
    if (!candidate) {
      return;
    }
    postSignal(session, {
      from: session.peerId,
      to: session.remotePeerId,
      type: "candidate",
      payload: candidate,
    });
  };
  session.rtc.onconnectionstatechange = () => {
    const state = session.rtc.connectionState;
    if (state === "connected") {
      session.isConnected = true;
      updateStatus(session, "connected", "connected");
      updateSessionNote(session, "Live encrypted link ready.");
      notifySecretConnected(session);
      flushPendingSecret(session);
    } else if (state === "failed" || state === "disconnected" || state === "closed") {
      session.isConnected = false;
      updateStatus(session, "waiting", "waiting");
    }
  };
  session.rtc.ondatachannel = (event) => bindDataChannel(session, event.channel);
}

async function maybeCreateOffer(session) {
  if (session.role !== "owner" || !session.offerReady || !session.rtc || session.rtc.localDescription) {
    return;
  }
  bindDataChannel(session, session.rtc.createDataChannel("shhx"));
  const offer = await session.rtc.createOffer();
  await session.rtc.setLocalDescription(offer);
  const pubJwk = await crypto.subtle.exportKey("jwk", session.roomKeyPair.publicKey);
  await postSignal(session, {
    from: session.peerId,
    to: session.remotePeerId,
    type: "offer",
    payload: {
      sdp: session.rtc.localDescription,
      sessionPublicKey: pubJwk,
    },
  });
}

async function notifyReady(session) {
  if (session.role !== "guest" || !session.remotePeerId || session.readySent) {
    return;
  }
  session.readySent = true;
  await postSignal(session, {
    from: session.peerId,
    to: session.remotePeerId,
    type: "ready",
    payload: {},
  });
}

function bindDataChannel(session, channel) {
  session.channel = channel;
  channel.onopen = () => {
    session.isConnected = true;
    updateStatus(session, "connected", "connected");
    updateSessionNote(session, "Live encrypted link ready.");
    notifySecretConnected(session);
    if (session.role === "owner" && session.pendingSecret && !session.pendingSecret.active) {
      sendUnavailable(session);
      return;
    }
    flushPendingSecret(session);
  };
  channel.onclose = () => {
    session.isConnected = false;
    updateStatus(session, "waiting", "waiting");
    updateSessionNote(session, "Live link closed.");
  };
  channel.onmessage = async (event) => {
    await handlePeerMessage(session, JSON.parse(event.data));
  };
}

async function handleSignal(session, signal) {
  if (signal.to && signal.to !== session.peerId) {
    return;
  }

  switch (signal.type) {
    case "offer":
      await handleOffer(session, signal);
      break;
    case "answer":
      await handleAnswer(session, signal);
      break;
    case "ready":
      session.remotePeerId = signal.from;
      session.offerReady = true;
      await ensurePeerConnection(session);
      await maybeCreateOffer(session);
      break;
    case "candidate":
      if (session.rtc) {
        await session.rtc.addIceCandidate(signal.payload);
      }
      break;
    default:
      break;
  }
}

async function handleOffer(session, signal) {
  session.remotePeerId = signal.from;
  if (!session.rtc) {
    await ensurePeerConnection(session);
  }
  await session.rtc.setRemoteDescription(signal.payload.sdp);
  await deriveBaseKey(session, signal.payload.sessionPublicKey);
  const answer = await session.rtc.createAnswer();
  await session.rtc.setLocalDescription(answer);
  const pubJwk = await crypto.subtle.exportKey("jwk", session.roomKeyPair.publicKey);
  await postSignal(session, {
    from: session.peerId,
    to: signal.from,
    type: "answer",
    payload: {
      sdp: session.rtc.localDescription,
      sessionPublicKey: pubJwk,
    },
  });
}

async function handleAnswer(session, signal) {
  await session.rtc.setRemoteDescription(signal.payload.sdp);
  await deriveBaseKey(session, signal.payload.sessionPublicKey);
  flushPendingSecret(session);
}

async function deriveBaseKey(session, remotePublicJwk) {
  if (session.baseKeyBytes) {
    return;
  }
  const remotePublicKey = await crypto.subtle.importKey(
    "jwk",
    remotePublicJwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    [],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: remotePublicKey },
    session.roomKeyPair.privateKey,
    256,
  );
  const digest = await crypto.subtle.digest("SHA-256", bits);
  session.baseKeyBytes = new Uint8Array(digest);
}

async function derivePayloadKey(session, otp) {
  const otpBytes = textEncoder.encode(otp || "");
  const combined = new Uint8Array(session.baseKeyBytes.length + otpBytes.length);
  combined.set(session.baseKeyBytes, 0);
  combined.set(otpBytes, session.baseKeyBytes.length);
  const digest = await crypto.subtle.digest("SHA-256", combined);
  return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function postSignal(session, payload) {
  try {
    const response = await fetch(`/api/rooms/${encodeURIComponent(session.roomCode)}/signal`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      throw new Error(`signal failed: ${response.status}`);
    }
    return true;
  } catch (_error) {
    if (session.role === "owner" && !session.provisional) {
      updateStatus(session, "offline", "waiting");
    }
    return false;
  }
}

async function flushPendingSecret(session) {
  if (session.role !== "owner" || !session.pendingSecret || !session.isConnected || !session.baseKeyBytes || !session.channel) {
    return;
  }
  if (!session.pendingSecret.active || session.pendingSecret.sent) {
    return;
  }

  const plaintext = await decryptLocalValue(session.pendingSecret.localSecret);
  const factor = await deriveSecretFactor(session.pendingSecret);
  const payloadKey = await derivePayloadKey(session, factor);
  const secret = await encryptSecret(payloadKey, plaintext);
  const message = {
    kind: "secret",
    id: session.pendingSecret.id,
    burnAfterRead: session.pendingSecret.burnAfterRead,
    authMode: session.pendingSecret.authMode,
    active: session.pendingSecret.active,
    ciphertext: secret.ciphertext,
    iv: secret.iv,
  };
  session.channel.send(JSON.stringify(message));
  session.pendingSecret.sent = true;
  updateStatus(session, "shared", "connected");
  updateSessionNote(session, "Secret delivered to the live link.");
}

async function handlePeerMessage(session, message) {
  switch (message.kind) {
    case "secret":
      session.receivedSecret = message;
      renderReceivedSecret(session, message);
      break;
    case "control":
      handleControl(session, message);
      break;
    default:
      break;
  }
}

function renderReceivedSecret(session, message) {
  const node = session.node;
  const otpWrap = node.querySelector("[data-otp-wrap]");
  const otpInput = node.querySelector("[data-otp-input]");
  const factorVisibility = node.querySelector("[data-factor-visibility]");
  otpWrap.hidden = message.authMode === "none";
  otpInput.value = "";
  if (message.authMode === "totp") {
    otpInput.placeholder = "Enter the current 6-digit code";
    otpInput.maxLength = TOTP_CODE_LENGTH;
    otpInput.inputMode = "numeric";
    otpInput.type = "text";
    factorVisibility.hidden = true;
  } else {
    otpInput.placeholder = "Enter the passphrase";
    otpInput.maxLength = MAX_PASSPHRASE_LENGTH;
    otpInput.inputMode = "text";
    otpInput.type = "password";
    factorVisibility.hidden = false;
    syncSensitiveButtonLabel(factorVisibility, "Show passphrase", "passphrase");
  }
  node.querySelector("[data-secret-meta]").textContent = message.authMode === "totp"
    ? message.burnAfterRead ? "Authenticator code required. Will delete on read." : "Authenticator code required."
    : message.authMode === "passphrase"
      ? message.burnAfterRead ? "Passphrase required. Will delete on read." : "Passphrase required."
      : message.burnAfterRead ? "Will delete on read." : "Ready to read.";
  node.querySelector("[data-secret-placeholder]").hidden = false;
  setAnimatedText(node.querySelector("[data-secret-placeholder]"), "Encrypted secret received.");
  node.querySelector("[data-secret-plaintext]").hidden = true;

  const actions = node.querySelector("[data-secret-actions]");
  actions.innerHTML = "";
  const read = document.createElement("button");
  read.type = "button";
  read.className = "decrypt-secret-button";
  read.title = "Decrypt secret";
  read.setAttribute("aria-label", "Decrypt secret");
  read.innerHTML = `
    <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"></path>
      <circle cx="12" cy="12" r="2.5"></circle>
    </svg>
    <span>DECRYPT</span>
  `;
  read.disabled = !message.active;
  read.addEventListener("click", async () => {
    if (node.classList.contains("is-disabled") || !session.baseKeyBytes) {
      return;
    }
    try {
      const payloadKey = await derivePayloadKey(session, message.authMode === "none" ? "" : otpInput.value.trim());
      const plaintext = await decryptSecret(payloadKey, message);
      setAnimatedText(node.querySelector("[data-secret-plaintext]"), plaintext);
      node.querySelector("[data-secret-plaintext]").hidden = false;
      node.querySelector("[data-secret-placeholder]").hidden = true;
      scrollSecretContentIntoView(node.querySelector("[data-secret-plaintext]"));
      node.querySelector("[data-secret-meta]").textContent = message.burnAfterRead ? "Read once. Deleted after opening." : "Opened.";
      actions.innerHTML = "";
      updateStatus(session, "open", "connected");
      if (message.burnAfterRead) {
        session.channel.send(JSON.stringify({ kind: "control", action: "burn", id: message.id }));
      }
    } catch (_error) {
      node.querySelector("[data-secret-meta]").textContent = message.authMode === "totp"
        ? "Could not decrypt. Check the authenticator code."
        : "Could not decrypt. Check the passphrase.";
    }
  });
  actions.appendChild(read);
  updateStatus(session, message.active ? "sealed" : "off", message.active ? "connected" : "waiting");
}

function toggleSecret(session) {
  if (!session.pendingSecret) {
    return;
  }
  session.pendingSecret.active = !session.pendingSecret.active;
  persistLocalSecret(session.pendingSecret);
  session.node.classList.toggle("is-disabled", !session.pendingSecret.active);
  syncOwnerControls(session);
  updateStatus(session, session.pendingSecret.active ? "ready" : "off", "waiting");
  if (session.pendingSecret.sent && session.channel) {
    session.channel.send(JSON.stringify({
      kind: "control",
      action: "toggle",
      id: session.pendingSecret.id,
      active: session.pendingSecret.active,
    }));
    if (!session.pendingSecret.active) {
      sendUnavailable(session);
    }
  } else if (session.pendingSecret.active) {
    flushPendingSecret(session);
  } else if (session.channel) {
    sendUnavailable(session);
  }
}

async function deleteSecret(session) {
  clearSecretExpiryTimer(session.roomCode);
  removeLocalSecret(session.pendingSecret?.id);
  if (session.pendingSecret?.sent && session.channel) {
    session.channel.send(JSON.stringify({ kind: "control", action: "delete", id: session.pendingSecret.id }));
  }
  await leaveSession(session, true);
}

