const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const stunServers = [{ urls: ["stun:stun.l.google.com:19302"] }];
const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
const scrambleAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ23456789";
const MAX_SECRET_LENGTH = 4096;
const MAX_PASSPHRASE_LENGTH = 128;
const MAX_HINT_LENGTH = 72;
const TOTP_CODE_LENGTH = 6;
const MAX_SHARED_JOIN_RETRIES = 4;

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
  composerSearchRestoreCollapsed: null,
  networkIndicatorBound: false,
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
    setupConnectivityIndicator();
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

function canonicalJSON(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJSON(item)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJSON(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

async function browserIdForPublicKey(publicKey) {
  const digest = await crypto.subtle.digest("SHA-256", textEncoder.encode(canonicalJSON(publicKey)));
  return bytesToHex(new Uint8Array(digest)).slice(0, 16);
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
      record = {
        browserId: await browserIdForPublicKey(publicKey),
        publicKey,
        privateKey,
      };
      localStorage.setItem(IDENTITY_STORAGE_KEY, JSON.stringify(record));
    }
    appState.identity = record;
    statusNode.textContent = record.browserId;
    statusNode.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(record.browserId);
        showToast("Browser id copied.");
      } catch (_error) {
        showToast("Browser id copy failed.");
      }
    });
  } catch (error) {
    console.error(error);
    statusNode.textContent = "unavailable";
    statusNode.disabled = true;
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
  const sessionHTML = await joinSharedLink(shareCode);
  if (!sessionHTML) {
    return;
  }
  const node = insertCardHTML(sessionHTML);
  bootstrapSession(node);
}

async function joinSharedLink(shareCode) {
  for (let attempt = 0; attempt <= MAX_SHARED_JOIN_RETRIES; attempt += 1) {
    const response = await fetch("/ui/rooms/join", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
      body: new URLSearchParams({
        display_name: "Peer",
        room_code: shareCode,
      }),
    });

    if (response.ok) {
      return response.text();
    }

    if (response.status !== 409 || attempt === MAX_SHARED_JOIN_RETRIES) {
      showMissingSharedSecret(response.status, shareCode);
      return "";
    }

    showToast("Another opener was still attached. Retrying live link.");
    await delay(400 * (attempt + 1));
  }
  return "";
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
      note.textContent = status === 409
        ? `The secret "${shareCode}" is not available right now.`
        : `The secret "${shareCode}" is not available.`;
    }
  }
  showToast(
    status === 409
      ? `Secret ${shareCode} is not available right now.`
      : `Secret ${shareCode} is not available.`,
  );
}

function delay(ms) {
  return new Promise((resolve) => {
    window.setTimeout(resolve, ms);
  });
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
    remoteBrowserId: null,
    remoteIdentityPublicKey: null,
    isConnected: false,
    peerValidated: false,
    offerReady: false,
    readySent: false,
    helloSent: false,
    validationChallenge: null,
    selected: false,
    provisional: options.provisional === true || node.dataset.provisional === "true",
    provisionAttempts: 0,
    provisionTimer: null,
    isDeleted: false,
    linkOpenedToastShown: false,
    validationToastShown: false,
    connectedToastShown: false,
    leaveNotified: false,
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
  session.helloSent = false;
  session.peerValidated = false;
  session.validationChallenge = null;
  session.remoteBrowserId = null;
  session.remoteIdentityPublicKey = null;
  session.linkOpenedToastShown = false;
  session.validationToastShown = false;
  session.connectedToastShown = false;
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
      session.linkOpenedToastShown = false;
      session.validationToastShown = false;
      updateStatus(session, "handshake", "readying");
      updateSessionNote(session, session.role === "owner"
        ? "Recipient opened the link. Establishing live channel."
        : "Sender found. Establishing live channel.");
      notifyLinkOpened(session);
      await ensurePeerConnection(session);
      await maybeCreateOffer(session);
      break;
    case "peer-left":
      const hadConnectedPeer = session.isConnected || session.peerValidated;
      session.remotePeerId = null;
      resetPeerLink(session);
      updateStatus(session, "waiting", "waiting");
      updateSessionNote(session, session.role === "owner"
        ? hadConnectedPeer
          ? "Recipient left. Waiting for another open."
          : "Previous opener cleared. Waiting for recipient."
        : "Sender left. Waiting for sender.");
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
  const previousRemotePeerId = session.remotePeerId;
  session.remotePeerId = remote ? remote.id : null;
  if (remote) {
    if (previousRemotePeerId !== session.remotePeerId) {
      session.linkOpenedToastShown = false;
      session.validationToastShown = false;
    }
    updateStatus(session, "handshake", "readying");
    updateSessionNote(session, session.role === "owner"
      ? "Recipient opened the link. Establishing live channel."
      : "Sender found. Establishing live channel.");
    notifyLinkOpened(session);
  } else {
    updateStatus(session, "waiting", "waiting");
    updateSessionNote(session, session.role === "owner" ? "Waiting for recipient to open the link." : "Waiting for sender to come online.");
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
      updateSessionNote(session, session.role === "owner"
        ? "Peer channel ready. Waiting for browser validation."
        : "Live encrypted link ready.");
      if (session.role !== "owner") {
        notifySecretConnected(session);
      }
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
    updateSessionNote(session, session.role === "owner"
      ? "Peer channel ready. Waiting for browser validation."
      : "Live encrypted link ready.");
    if (session.role === "guest") {
      void sendIdentityHello(session);
      notifySecretConnected(session);
    }
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
  if (session.role !== "owner" || !session.pendingSecret || !session.isConnected || !session.baseKeyBytes || !session.channel || !session.peerValidated) {
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
    case "identity":
      await handleIdentityMessage(session, message);
      break;
    case "control":
      handleControl(session, message);
      break;
    default:
      break;
  }
}

async function handleIdentityMessage(session, message) {
  if (message.action === "hello" && session.role === "owner") {
    if (!message.browserId || !message.publicKey) {
      showToast("Recipient validation failed.");
      return;
    }
    const expectedBrowserId = await browserIdForPublicKey(message.publicKey);
    if (expectedBrowserId !== message.browserId) {
      showToast("Recipient validation failed.");
      return;
    }
    session.remoteBrowserId = message.browserId;
    session.remoteIdentityPublicKey = message.publicKey;
    notifyValidationStarted(session);
    await sendValidationChallenge(session);
    return;
  }

  if (message.action === "ping" && session.role === "guest") {
    const signature = await signValidationChallenge(message.challenge);
    if (!signature) {
      showToast("Browser validation unavailable.");
      return;
    }
    session.channel?.send(JSON.stringify({
      kind: "identity",
      action: "pong",
      browserId: appState.identity?.browserId || "",
      challenge: message.challenge,
      signature,
    }));
    return;
  }

  if (message.action === "pong" && session.role === "owner") {
    const challengeMatches = !!message.challenge && session.validationChallenge === message.challenge;
    const browserMatches = !session.remoteBrowserId || session.remoteBrowserId === message.browserId;
    const signatureOK = challengeMatches
      && browserMatches
      && session.remoteIdentityPublicKey
      && await verifyValidationChallenge(session.remoteIdentityPublicKey, message.challenge, message.signature);
    if (!signatureOK) {
      showToast(`Recipient validation failed${formatBrowserIdSuffix(session.remoteBrowserId)}.`);
      await sendValidationChallenge(session);
      return;
    }
    session.peerValidated = true;
    session.validationChallenge = null;
    updateSessionNote(session, "Recipient browser validated. Live encrypted link ready.");
    showToast(`Recipient browser validated${formatBrowserIdSuffix(session.remoteBrowserId)}.`, {
      action: {
        label: "Show secret",
        onClick: () => focusSessionCard(session),
      },
    });
    session.channel?.send(JSON.stringify({ kind: "identity", action: "validated" }));
    notifySecretConnected(session);
    flushPendingSecret(session);
    return;
  }

  if (message.action === "validated" && session.role === "guest") {
    session.peerValidated = true;
    showToast("Sender accepted this browser.");
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
      session.channel?.send(JSON.stringify({ kind: "control", action: "decrypt-success", id: message.id }));
      if (message.burnAfterRead) {
        session.channel.send(JSON.stringify({ kind: "control", action: "burn", id: message.id }));
      }
    } catch (_error) {
      node.querySelector("[data-secret-meta]").textContent = message.authMode === "totp"
        ? "Could not decrypt. Check the authenticator code."
        : "Could not decrypt. Check the passphrase.";
      session.channel?.send(JSON.stringify({
        kind: "control",
        action: "decrypt-failed",
        id: message.id,
        authMode: message.authMode,
      }));
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

function handleControl(session, message) {
  if (message.action === "unavailable") {
    if (session.role === "guest") {
      redirectHome();
      return;
    }
  }
  if (message.action === "toggle") {
    if (session.role === "guest" && !message.active) {
      redirectHome();
      return;
    }
    session.node.classList.toggle("is-disabled", !message.active);
    updateStatus(session, message.active ? "sealed" : "off", message.active ? "connected" : "waiting");
  }
  if (message.action === "delete") {
    if (session.role === "guest") {
      redirectHome();
      return;
    }
    clearSecretExpiryTimer(session.roomCode);
    removeLocalSecret(session.pendingSecret?.id);
    session.node.remove();
    appState.sessions.delete(session.roomCode);
    syncBulkActions();
    syncFeedEmptyState();
  }
  if (message.action === "burn") {
    markBurned(session);
    return;
  }
  if (message.action === "decrypt-success" && session.role === "owner") {
    showToast(`Recipient decrypted the secret${formatBrowserIdSuffix(session.remoteBrowserId)}.`, {
      action: {
        label: "Show secret",
        onClick: () => focusSessionCard(session),
      },
    });
    return;
  }
  if (message.action === "decrypt-failed" && session.role === "owner") {
    const modeLabel = message.authMode === "totp" ? "authenticator code" : "passphrase";
    showToast(`Recipient failed to decrypt with the ${modeLabel}${formatBrowserIdSuffix(session.remoteBrowserId)}.`, {
      action: {
        label: "Show secret",
        onClick: () => focusSessionCard(session),
      },
    });
  }
}

function sendUnavailable(session) {
  if (!session.channel || !session.pendingSecret) {
    return;
  }
  session.channel.send(JSON.stringify({
    kind: "control",
    action: "unavailable",
    id: session.pendingSecret.id,
  }));
}

function markBurned(session) {
  const node = session.node;
  clearSecretExpiryTimer(session.roomCode);
  removeLocalSecret(session.pendingSecret?.id);
  if (session.pendingSecret) {
    session.pendingSecret.active = false;
  }
  node.classList.add("is-burned");
  if (session.role === "guest" && node.querySelector("[data-secret-plaintext]").hidden === false) {
    node.querySelector("[data-secret-meta]").textContent = "Deleted on read.";
    node.querySelector("[data-secret-actions]").innerHTML = "";
    updateStatus(session, "burned", "waiting");
    return;
  }
  node.querySelector("[data-secret-meta]").textContent = "Deleted on read.";
  node.querySelector("[data-secret-placeholder]").hidden = false;
  setAnimatedText(node.querySelector("[data-secret-placeholder]"), "This secret was deleted on read.");
  node.querySelector("[data-secret-plaintext]").hidden = true;
  node.querySelector("[data-secret-actions]").innerHTML = "";
  updateStatus(session, "burned", "waiting");
  syncOwnerControls(session);
  syncBulkActions();
}

async function leaveSession(session, animateRemove = false) {
  try {
    if (appState.activeCardFocusRoomCode === session.roomCode) {
      unfocusSessionCard(session);
    }
    session.isDeleted = true;
    if (session.provisionTimer) {
      window.clearTimeout(session.provisionTimer);
      session.provisionTimer = null;
    }
    clearSecretExpiryTimer(session.roomCode);
    session.eventSource?.close();
    session.channel?.close();
    session.rtc?.close();
    if (!session.provisional) {
      await notifySessionLeave(session);
    }
  } finally {
    appState.sessions.delete(session.roomCode);
    if (animateRemove) {
      await animateCardRemoval(session.node);
    } else {
      session.node.remove();
    }
    syncBulkActions();
    syncFeedEmptyState();
  }
}

async function notifySessionLeave(session) {
  if (!session || session.provisional || session.leaveNotified) {
    return;
  }
  session.leaveNotified = true;
  await fetch(`/api/rooms/${encodeURIComponent(session.roomCode)}/leave?peer=${encodeURIComponent(session.peerId)}`, {
    method: "POST",
    keepalive: true,
  }).catch(() => {});
}

function notifySessionLeaveSoon(session) {
  if (!session || session.provisional || session.leaveNotified) {
    return;
  }
  session.leaveNotified = true;
  const url = `/api/rooms/${encodeURIComponent(session.roomCode)}/leave?peer=${encodeURIComponent(session.peerId)}`;
  if (navigator.sendBeacon) {
    const payload = new Blob([], { type: "text/plain;charset=UTF-8" });
    if (navigator.sendBeacon(url, payload)) {
      return;
    }
  }
  fetch(url, {
    method: "POST",
    keepalive: true,
  }).catch(() => {});
}

function resetPeerLink(session) {
  session.channel?.close();
  session.rtc?.close();
  session.channel = null;
  session.rtc = null;
  session.baseKeyBytes = null;
  session.isConnected = false;
  session.peerValidated = false;
  session.validationChallenge = null;
  session.remoteBrowserId = null;
  session.remoteIdentityPublicKey = null;
  session.helloSent = false;
  session.linkOpenedToastShown = false;
  session.validationToastShown = false;
  session.connectedToastShown = false;
}

function updateSessionNote(session, text) {
  void session;
  void text;
}

function updateStatus(session, label, state) {
  const pill = session.node.querySelector("[data-room-status]");
  pill.textContent = label;
  pill.dataset.state = state;
  syncConnectivityIndicator();
}

function updateComposerNote(text) {
  showToast(text);
}

function setupBulkActions() {
  const enable = document.querySelector("#bulk-enable-button");
  const disable = document.querySelector("#bulk-disable-button");
  const email = document.querySelector("#bulk-email-button");
  const remove = document.querySelector("#bulk-delete-button");
  if (!enable || !disable || !email || !remove) {
    return;
  }

  enable.addEventListener("click", async () => {
    for (const session of selectedOwnerSessions()) {
      if (session.pendingSecret?.active === false) {
        toggleSecret(session);
      }
    }
    syncBulkActions();
  });
  disable.addEventListener("click", async () => {
    for (const session of selectedOwnerSessions()) {
      if (session.pendingSecret?.active !== false) {
        toggleSecret(session);
      }
    }
    syncBulkActions();
  });
  email.addEventListener("click", () => {
    const links = selectedOwnerSessions().map((session) => shareLinkFor(session.roomCode));
    if (links.length === 0) {
      return;
    }
    window.location.href = mailtoLinkFor(links);
  });
  remove.addEventListener("click", async () => {
    const selected = selectedOwnerSessions();
    for (const session of selected) {
      await deleteSecret(session);
    }
    syncBulkActions();
  });
}

function selectedOwnerSessions() {
  return [...appState.sessions.values()].filter((session) => session.role === "owner" && session.selected);
}

function syncBulkActions() {
  const toolbar = document.querySelector("#composer-toolbar");
  const note = document.querySelector("#bulk-selection-note");
  const row = document.querySelector("#bulk-actions-row");
  const enable = document.querySelector("#bulk-enable-button");
  const disable = document.querySelector("#bulk-disable-button");
  const email = document.querySelector("#bulk-email-button");
  const remove = document.querySelector("#bulk-delete-button");
  if (!toolbar || !note || !row || !enable || !disable || !email || !remove) {
    return;
  }

  const selected = selectedOwnerSessions();
  if (selected.length === 0) {
    toolbar.hidden = true;
    note.hidden = true;
    row.hidden = true;
    note.textContent = "0";
    enable.disabled = true;
    disable.disabled = true;
    email.disabled = true;
    remove.disabled = true;
    refreshComposerHeight();
    return;
  }
  toolbar.hidden = false;
  row.hidden = false;
  note.hidden = false;
  note.textContent = String(selected.length);
  enable.disabled = selected.every((session) => session.pendingSecret?.active !== false);
  disable.disabled = selected.every((session) => session.pendingSecret?.active === false);
  email.disabled = selected.length === 0;
  remove.disabled = selected.length === 0;
  refreshComposerHeight();
}

function shareLinkFor(roomCode) {
  return `${window.location.origin}/${encodeURIComponent(roomCode)}`;
}

function mailtoLinkFor(links) {
  const subject = links.length > 1 ? "shhx secret links" : "shhx secret link";
  const body = links.length > 1
    ? `Open these live encrypted secret links while I stay online:\n\n${links.join("\n")}`
    : `Open this live encrypted secret link while I stay online:\n\n${links[0]}`;
  return `mailto:?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}

function redirectHome() {
  window.location.replace("/");
}

function getOverlay() {
  return document.querySelector("#ui-overlay");
}

function openOverlay() {
  const overlay = getOverlay();
  if (!overlay) {
    return;
  }
  overlay.hidden = false;
  document.body.classList.add("ui-overlay-open");
  overlay.onclick = () => closeActiveUI();
}

function closeOverlayIfIdle() {
  if (appState.editorFullscreenOpen || appState.activeCardFocusRoomCode) {
    return;
  }
  const overlay = getOverlay();
  if (!overlay) {
    return;
  }
  overlay.hidden = true;
  overlay.onclick = null;
  document.body.classList.remove("ui-overlay-open");
}

function toggleEditorFullscreen(composer) {
  if (!composer) {
    return;
  }
  if (appState.editorFullscreenOpen) {
    closeEditorFullscreen(composer);
    return;
  }
  appState.editorFullscreenOpen = true;
  document.body.classList.add("editor-fullscreen-open");
  composer.open = true;
  composer.classList.add("is-fullscreen-panel");
  syncFullscreenButtonState(true);
  refreshComposerHeight();
  openOverlay();
}

function closeEditorFullscreen(composer) {
  if (!composer) {
    return;
  }
  if (!appState.editorFullscreenOpen) {
    return;
  }
  appState.editorFullscreenOpen = false;
  document.body.classList.remove("editor-fullscreen-open");
  composer.classList.remove("is-fullscreen-panel");
  syncFullscreenButtonState(false);
  refreshComposerHeight();
  closeOverlayIfIdle();
}

function focusSessionCard(session) {
  if (appState.activeCardFocusRoomCode && appState.activeCardFocusRoomCode !== session.roomCode) {
    const active = appState.sessions.get(appState.activeCardFocusRoomCode);
    if (active) {
      active.node.classList.remove("is-foreground");
    }
  }
  session.node.open = true;
  session.node.classList.add("is-foreground");
  appState.activeCardFocusRoomCode = session.roomCode;
  openOverlay();
  syncConnectivityIndicator();
}

function unfocusSessionCard(session) {
  session.node.classList.remove("is-foreground");
  if (appState.activeCardFocusRoomCode === session.roomCode) {
    appState.activeCardFocusRoomCode = null;
  }
  closeOverlayIfIdle();
  syncConnectivityIndicator();
}

function closeActiveUI() {
  closeEditorFullscreen(document.querySelector("#composer"));
  if (appState.activeCardFocusRoomCode) {
    const active = appState.sessions.get(appState.activeCardFocusRoomCode);
    if (active) {
      unfocusSessionCard(active);
    } else {
      appState.activeCardFocusRoomCode = null;
    }
  }
  closeOverlayIfIdle();
}

function syncFullscreenButtonState(isOpen) {
  const button = document.querySelector("#editor-fullscreen-button");
  if (!button) {
    return;
  }
  const label = isOpen ? "Exit fullscreen editor" : "Open fullscreen editor";
  button.title = label;
  button.setAttribute("aria-label", label);
  button.setAttribute("aria-pressed", String(isOpen));
  const sr = button.querySelector(".sr-only");
  if (sr) {
    sr.textContent = label;
  }
}

function syncFeedEmptyState() {
  const feed = document.querySelector("#feed");
  const empty = document.querySelector("#empty-feed");
  if (!feed || !empty) {
    return;
  }
  const cards = feed.querySelectorAll(".secret-card");
  empty.hidden = cards.length > 0;
}

function persistLocalSecret(secret) {
  if (!secret?.id) {
    return;
  }
  const secrets = readStoredSecrets().filter((item) => item.id !== secret.id);
  secrets.unshift({
    id: secret.id,
    hint: String(secret.hint || "").trim(),
    createdAt: normalizeCreatedAt(secret.createdAt),
    burnAfterRead: secret.burnAfterRead,
    localSecret: secret.localSecret,
    localPassphrase: secret.localPassphrase,
    localTOTPSecret: secret.localTOTPSecret,
    authMode: secret.authMode,
    expiresAt: normalizeExpiresAt(secret.expiresAt),
    active: secret.active,
  });
  localStorage.setItem(LOCAL_SECRET_LIST_STORAGE, JSON.stringify(secrets));
}

function removeLocalSecret(secretID) {
  if (!secretID) {
    return;
  }
  const secrets = readStoredSecrets().filter((item) => item.id !== secretID);
  localStorage.setItem(LOCAL_SECRET_LIST_STORAGE, JSON.stringify(secrets));
}

function readStoredSecrets() {
  migrateLocalStorageKey(LEGACY_LOCAL_SECRET_LIST_STORAGE, LOCAL_SECRET_LIST_STORAGE);
  const raw = localStorage.getItem(LOCAL_SECRET_LIST_STORAGE);
  if (!raw) {
    return [];
  }
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed.map((item) => ({
      ...item,
      hint: typeof item.hint === "string" ? item.hint.trim() : "",
      createdAt: normalizeCreatedAt(item.createdAt),
      expiresAt: normalizeExpiresAt(item.expiresAt),
    })).map((item) => {
      if (item.expiresAt === null) {
        return { ...item, expiresAt: null };
      }
      return item;
    });
  } catch (_error) {
    return [];
  }
}

function syncCardSearchIndex(session) {
  if (!session?.node) {
    return;
  }
  const roomCode = String(session.roomCode || "").trim();
  const hint = String(session.pendingSecret?.hint || "").trim();
  const plaintext = String(session.pendingSecret?.searchPlaintext || "").trim();
  const title = session.node.querySelector("[data-card-title]");
  if (title) {
    title.textContent = roomCode ? `s: ${roomCode}` : "secret";
  }
  session.node.dataset.searchText = `${roomCode} ${hint} ${plaintext}`.trim().toLowerCase();
}

function setupFeedSearch() {
  const input = document.querySelector("#feed-search-input");
  if (!input) {
    return;
  }
  const syncSearchComposerState = () => {
    const query = String(input.value || "").trim();
    if (query) {
      if (appState.composerSearchRestoreCollapsed === null) {
        appState.composerSearchRestoreCollapsed = appState.composerCollapsed;
      }
      appState.composerCollapseController?.(true);
      return;
    }
    if (appState.composerSearchRestoreCollapsed !== null) {
      const restoreCollapsed = appState.composerSearchRestoreCollapsed;
      appState.composerSearchRestoreCollapsed = null;
      appState.composerCollapseController?.(restoreCollapsed);
    }
  };

  input.addEventListener("input", () => {
    syncSearchComposerState();
    applyFeedFilter();
  });
  input.addEventListener("keyup", () => {
    syncSearchComposerState();
    applyFeedFilter();
  });
}

function setupConnectivityRecovery() {
  window.addEventListener("online", () => {
    appState.sessions.forEach((session) => {
      if (session.provisional) {
        void provisionOwnerSession(session);
      }
    });
  });
  window.addEventListener("beforeunload", () => {
    appState.sessions.forEach((session) => {
      notifySessionLeaveSoon(session);
      session.eventSource?.close();
      session.channel?.close();
      session.rtc?.close();
    });
    syncConnectivityIndicator();
  });
  window.addEventListener("pagehide", () => {
    appState.sessions.forEach((session) => {
      notifySessionLeaveSoon(session);
    });
    syncConnectivityIndicator();
  });
}

function setupConnectivityIndicator() {
  if (appState.networkIndicatorBound) {
    return;
  }
  appState.networkIndicatorBound = true;
  const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
  window.addEventListener("online", syncConnectivityIndicator);
  window.addEventListener("offline", syncConnectivityIndicator);
  connection?.addEventListener?.("change", syncConnectivityIndicator);
  syncConnectivityIndicator();
}

function syncConnectivityIndicator() {
  const indicator = document.querySelector("#network-indicator");
  if (!indicator) {
    return;
  }
  const session = currentConnectivitySession();
  const sessionLabel = session?.node?.querySelector("[data-room-status]")?.textContent?.trim() || "no session";
  const sessionTitle = session
    ? `Session ${session.roomCode}: ${sessionLabel}.`
    : "No session yet.";

  const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
  const online = navigator.onLine !== false;
  const effectiveType = String(connection?.effectiveType || "");
  const rtt = Number(connection?.rtt || 0);
  const downlink = Number(connection?.downlink || 0);
  const degradedByNetwork = Boolean(
    connection?.saveData
      || effectiveType === "slow-2g"
      || effectiveType === "2g"
      || effectiveType === "3g"
      || (rtt > 0 && rtt > 450)
      || (downlink > 0 && downlink < 1.2),
  );
  const degradedBySession = online && /^(offline|failed)$/i.test(sessionLabel);

  const state = !online ? "offline" : (degradedByNetwork || degradedBySession ? "degraded" : "online");
  const heading = state === "offline"
    ? "Offline."
    : state === "degraded"
      ? "Unstable connection."
      : "Online.";
  const title = `${heading} ${sessionTitle}`;
  indicator.dataset.state = state;
  indicator.title = title;
  indicator.setAttribute("aria-label", title);
}

function currentConnectivitySession() {
  if (appState.activeCardFocusRoomCode && appState.sessions.has(appState.activeCardFocusRoomCode)) {
    return appState.sessions.get(appState.activeCardFocusRoomCode);
  }
  const shareCode = String(document.body.dataset.shareCode || "").trim().toUpperCase();
  if (shareCode && appState.sessions.has(shareCode)) {
    return appState.sessions.get(shareCode);
  }
  const selected = selectedOwnerSessions();
  if (selected.length > 0) {
    return selected[0];
  }
  const feedCards = document.querySelectorAll("#feed .secret-card[data-room-code]");
  for (const card of feedCards) {
    const roomCode = card.dataset.roomCode;
    if (roomCode && appState.sessions.has(roomCode)) {
      return appState.sessions.get(roomCode);
    }
  }
  return null;
}

function applyFeedFilter() {
  const input = document.querySelector("#feed-search-input");
  const query = String(input?.value || "").trim().toLowerCase();
  appState.sessions.forEach((session) => {
    if (!session?.node) {
      return;
    }
    const haystack = String(session.node.dataset.searchText || session.roomCode || "").toLowerCase();
    const matches = !query || haystack.includes(query);
    session.node.hidden = !matches;
  });
}

function syncEditorGutter(textarea, gutter) {
  if (!textarea || !gutter) {
    return;
  }
  const lines = Math.max(1, textarea.value.split("\n").length);
  gutter.textContent = Array.from({ length: lines }, (_value, index) => index + 1).join("\n");
  gutter.scrollTop = textarea.scrollTop;
}

function toggleSensitiveInput(input, button, labelBase) {
  const isHidden = input.type === "password";
  input.type = isHidden ? "text" : "password";
  syncSensitiveButtonLabel(button, isHidden ? `Hide ${labelBase}` : `Show ${labelBase}`);
}

function syncSensitiveButtonLabel(button, label) {
  button.title = label;
  button.setAttribute("aria-label", label);
  const sr = button.querySelector(".sr-only");
  if (sr) {
    sr.textContent = label;
  }
}

function syncComposerToggleButton(button, enabled, onLabel, offLabel) {
  const label = enabled ? onLabel : offLabel;
  button.title = label;
  button.setAttribute("aria-label", label);
  button.setAttribute("aria-pressed", String(enabled));
  const sr = button.querySelector(".sr-only");
  if (sr) {
    sr.textContent = label;
  }
}

function setAnimatedText(node, finalText) {
  if (!node) {
    return;
  }
  if (prefersReducedMotion.matches) {
    node.textContent = finalText;
    return;
  }

  const runID = String(Date.now() + Math.random());
  node.dataset.scrambleRun = runID;
  const chars = Array.from(finalText);
  const startedAt = performance.now();
  const duration = Math.min(420, Math.max(180, chars.length * 16));

  const frame = (now) => {
    if (node.dataset.scrambleRun !== runID) {
      return;
    }
    const progress = Math.min(1, (now - startedAt) / duration);
    const revealCount = Math.floor(chars.length * progress);
    node.textContent = chars.map((char, index) => {
      if (char === "\n" || char === " ") {
        return char;
      }
      if (index < revealCount || progress === 1) {
        return char;
      }
      return scrambleAlphabet[Math.floor(Math.random() * scrambleAlphabet.length)];
    }).join("");
    if (progress < 1) {
      requestAnimationFrame(frame);
    }
  };

  requestAnimationFrame(frame);
}

function syncTTLMark(session) {
  const mark = session.node.querySelector("[data-ttl-mark]");
  if (!mark) {
    return;
  }
  const expiresAt = normalizeExpiresAt(session.pendingSecret?.expiresAt);
  mark.hidden = expiresAt === null;
  if (expiresAt !== null) {
    mark.title = `TTL secret. Expires ${new Date(expiresAt).toLocaleString()}`;
    mark.setAttribute("aria-label", mark.title);
  } else {
    mark.removeAttribute("title");
    mark.removeAttribute("aria-label");
  }
}

function syncCreatedAt(session) {
  const node = session.node.querySelector("[data-created-at]");
  if (!node) {
    return;
  }
  const createdAt = normalizeCreatedAt(session.pendingSecret?.createdAt);
  if (createdAt === null) {
    node.hidden = true;
    node.textContent = "";
    return;
  }
  node.hidden = false;
  node.textContent = formatRelativeTime(createdAt);
}

function scheduleSecretExpiry(session) {
  clearSecretExpiryTimer(session.roomCode);
  const expiresAt = normalizeExpiresAt(session.pendingSecret?.expiresAt);
  if (expiresAt === null) {
    return;
  }

  const remaining = expiresAt - Date.now();
  if (remaining <= 0) {
    expireSecret(session);
    return;
  }

  const timer = window.setTimeout(() => {
    expireSecret(session);
  }, remaining);
  appState.expiryTimers.set(session.roomCode, timer);
}

function clearSecretExpiryTimer(roomCode) {
  const timer = appState.expiryTimers.get(roomCode);
  if (timer) {
    window.clearTimeout(timer);
    appState.expiryTimers.delete(roomCode);
  }
}

async function expireSecret(session) {
  if (!appState.sessions.has(session.roomCode)) {
    return;
  }
  removeLocalSecret(session.pendingSecret?.id);
  if (session.channel && session.pendingSecret?.sent) {
    session.channel.send(JSON.stringify({ kind: "control", action: "delete", id: session.pendingSecret.id }));
  } else if (session.channel) {
    sendUnavailable(session);
  }
  await leaveSession(session, true);
}

function animateCardRemoval(node) {
  if (!node || prefersReducedMotion.matches) {
    node?.remove();
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    node.classList.add("is-removing");
    window.setTimeout(() => {
      node.remove();
      resolve();
    }, 430);
  });
}

function setupFeedScrollMotion() {
  let lastY = window.scrollY;
  let lastTime = performance.now();
  let clearTimer = 0;
  window.addEventListener("scroll", () => {
    const now = performance.now();
    const deltaY = Math.abs(window.scrollY - lastY);
    const deltaT = Math.max(1, now - lastTime);
    const velocity = deltaY / deltaT;
    lastY = window.scrollY;
    lastTime = now;

    if (velocity < 1.2 || prefersReducedMotion.matches) {
      return;
    }

    document.querySelectorAll("#feed .secret-card").forEach((card) => {
      card.classList.add("is-scroll-quick");
    });
    window.clearTimeout(clearTimer);
    clearTimer = window.setTimeout(() => {
      document.querySelectorAll("#feed .secret-card").forEach((card) => {
        card.classList.remove("is-scroll-quick");
      });
    }, 140);
  }, { passive: true });
}

function setupComposerCollapse() {
  const composer = document.querySelector("#composer");
  const composerBody = composer?.querySelector(".composer-body");
  const composerSummary = composer?.querySelector("summary");
  if (!composer) {
    return;
  }

  const setComposerCollapsed = (collapsed) => {
    if (!composerBody) {
      return;
    }
    if (appState.composerAnimating) {
      appState.composerPendingCollapsed = collapsed;
      return;
    }
    if (appState.composerCollapsed === collapsed) {
      return;
    }

    appState.composerAnimating = true;
    appState.composerPendingCollapsed = null;

    if (!collapsed) {
      composerBody.classList.remove("is-hidden");
      composerBody.style.display = "grid";
    }
    composerBody.style.height = "auto";
    const measuredExpandedHeight = composerBody.scrollHeight;
    const startHeight = composerBody.getBoundingClientRect().height || measuredExpandedHeight;
    composerBody.style.height = `${startHeight}px`;
    void composerBody.offsetHeight;

    requestAnimationFrame(() => {
      composer.classList.toggle("is-collapsed", collapsed);
      const targetHeight = collapsed ? 0 : measuredExpandedHeight;
      composerBody.style.height = `${targetHeight}px`;
      appState.composerCollapsed = collapsed;
    });
  };

  appState.composerCollapseController = setComposerCollapsed;

  composerBody?.addEventListener("transitionend", (event) => {
    if (event.propertyName !== "height") {
      return;
    }
    appState.composerAnimating = false;
    if (!appState.composerCollapsed) {
      composerBody.classList.remove("is-hidden");
      composerBody.style.display = "grid";
      composerBody.style.height = "auto";
    } else {
      composerBody.classList.add("is-hidden");
      composerBody.style.display = "none";
      composerBody.style.height = "0px";
    }
    if (appState.composerPendingCollapsed !== null && appState.composerPendingCollapsed !== appState.composerCollapsed) {
      const pending = appState.composerPendingCollapsed;
      appState.composerPendingCollapsed = null;
      setComposerCollapsed(pending);
    }
  });

  composerSummary?.addEventListener("click", (event) => {
    if (appState.composerCollapsed) {
      event.preventDefault();
      composer.open = true;
      setComposerCollapsed(false);
    }
  });

  window.addEventListener("resize", () => {
    refreshComposerHeight();
  });
  if (document.readyState === "complete") {
    requestAnimationFrame(() => {
      refreshComposerHeight();
    });
  } else {
    window.addEventListener("load", () => {
      requestAnimationFrame(() => {
        refreshComposerHeight();
      });
    }, { once: true });
  }
}

function refreshComposerHeight() {
  const composer = document.querySelector("#composer");
  const composerBody = composer?.querySelector(".composer-body");
  if (!composerBody || appState.composerCollapsed) {
    return;
  }
  composerBody.classList.remove("is-hidden");
  composerBody.style.display = "grid";
  composerBody.style.height = "auto";
  composerBody.style.height = `${composerBody.scrollHeight}px`;
}

function parseTTLSelection(value) {
  const allowed = new Set(["300", "1800", "3600", "21600", "86400"]);
  const normalized = String(value || "").trim();
  if (!allowed.has(normalized)) {
    return null;
  }
  const ttl = Number.parseInt(normalized, 10);
  return Number.isFinite(ttl) && ttl > 0 ? ttl : null;
}

function normalizeExpiresAt(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

function normalizeCreatedAt(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

function formatRelativeTime(timestamp) {
  const seconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
  if (seconds < 60) {
    return "now";
  }
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    return `${minutes} min${minutes === 1 ? "" : "s"} ago`;
  }
  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `${hours} hr${hours === 1 ? "" : "s"} ago`;
  }
  const days = Math.floor(hours / 24);
  return `${days} day${days === 1 ? "" : "s"} ago`;
}

function ensureRelativeTimeTicker() {
  if (appState.relativeTimeTimerStarted) {
    return;
  }
  appState.relativeTimeTimerStarted = true;
  window.setInterval(() => {
    for (const session of appState.sessions.values()) {
      if (session.role === "owner") {
        syncCreatedAt(session);
      }
    }
  }, 60000);
}

function notifySecretConnected(session) {
  if (session.connectedToastShown) {
    return;
  }
  session.connectedToastShown = true;
  showToast(session.role === "owner"
    ? `Recipient browser is verified${formatBrowserIdSuffix(session.remoteBrowserId)}.`
    : "Secret link is live.", {
    action: {
      label: "Show secret",
      onClick: () => focusSessionCard(session),
    },
  });
}

function notifyLinkOpened(session) {
  if (session.role !== "owner" || session.linkOpenedToastShown || !session.remotePeerId) {
    return;
  }
  session.linkOpenedToastShown = true;
  showToast("Someone opened the link.", {
    action: {
      label: "Show secret",
      onClick: () => focusSessionCard(session),
    },
  });
}

function notifyValidationStarted(session) {
  if (session.role !== "owner" || session.validationToastShown) {
    return;
  }
  session.validationToastShown = true;
  showToast(`Recipient browser detected${formatBrowserIdSuffix(session.remoteBrowserId)}. Validating.`, {
    action: {
      label: "Show secret",
      onClick: () => focusSessionCard(session),
    },
  });
}

function shortBrowserId(browserId) {
  const normalized = String(browserId || "").trim();
  return normalized ? normalized.slice(0, 8) : "";
}

function formatBrowserIdSuffix(browserId) {
  const shortID = shortBrowserId(browserId);
  return shortID ? ` (${shortID})` : "";
}

function showToast(message, options = {}) {
  const stack = document.querySelector("#toast-stack");
  if (!stack || !message) {
    return;
  }

  const toast = document.createElement("div");
  toast.className = "toast";
  const copy = document.createElement("div");
  copy.className = "toast-copy";
  copy.textContent = message;
  toast.appendChild(copy);

  if (options.action) {
    const actions = document.createElement("div");
    actions.className = "toast-actions";
    const button = document.createElement("button");
    button.type = "button";
    button.className = "icon-button";
    button.title = options.action.label;
    button.setAttribute("aria-label", options.action.label);
    button.innerHTML = `
      <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
        <path d="M9 4H4v5"></path>
        <path d="M15 4h5v5"></path>
        <path d="M20 15v5h-5"></path>
        <path d="M4 15v5h5"></path>
      </svg>
      <span class="sr-only">${options.action.label}</span>
    `;
    button.addEventListener("click", () => {
      options.action.onClick?.();
      dismissToast(toast);
    });
    actions.appendChild(button);
    toast.appendChild(actions);
  }

  stack.prepend(toast);
  window.setTimeout(() => dismissToast(toast), options.duration ?? 3200);
}

function dismissToast(toast) {
  if (!toast || toast.dataset.leaving === "true") {
    return;
  }
  toast.dataset.leaving = "true";
  toast.classList.add("is-leaving");
  window.setTimeout(() => {
    toast.remove();
  }, 220);
}

function scrollSecretContentIntoView(node) {
  if (!node) {
    return;
  }
  requestAnimationFrame(() => {
    node.scrollIntoView({
      behavior: prefersReducedMotion.matches ? "auto" : "smooth",
      block: "start",
      inline: "nearest",
    });
  });
}

async function encryptSecret(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, textEncoder.encode(plaintext));
  return {
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  };
}

async function decryptSecret(key, payload) {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(payload.iv) },
    key,
    base64ToBytes(payload.ciphertext),
  );
  return textDecoder.decode(plaintext);
}

function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

function base64ToBytes(value) {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

async function encryptLocalValue(value) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    appState.localVaultKey,
    textEncoder.encode(value),
  );
  return {
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  };
}

async function decryptLocalValue(payload) {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(payload.iv) },
    appState.localVaultKey,
    base64ToBytes(payload.ciphertext),
  );
  return textDecoder.decode(plaintext);
}

async function importIdentityPrivateKey() {
  if (!appState.identity?.privateKey) {
    return null;
  }
  return crypto.subtle.importKey(
    "jwk",
    appState.identity.privateKey,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
}

async function importIdentityPublicKey(publicKey) {
  if (!publicKey) {
    return null;
  }
  return crypto.subtle.importKey(
    "jwk",
    publicKey,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
}

function randomValidationChallenge() {
  return bytesToBase64(crypto.getRandomValues(new Uint8Array(24)));
}

async function signValidationChallenge(challenge) {
  const privateKey = await importIdentityPrivateKey();
  if (!privateKey || !challenge) {
    return "";
  }
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    textEncoder.encode(challenge),
  );
  return bytesToBase64(new Uint8Array(signature));
}

async function verifyValidationChallenge(publicKey, challenge, signature) {
  const verifyKey = await importIdentityPublicKey(publicKey);
  if (!verifyKey || !challenge || !signature) {
    return false;
  }
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    verifyKey,
    base64ToBytes(signature),
    textEncoder.encode(challenge),
  );
}

async function sendIdentityHello(session) {
  if (session.role !== "guest" || session.helloSent || !session.channel || !appState.identity?.browserId || !appState.identity?.publicKey) {
    return;
  }
  session.helloSent = true;
  session.channel.send(JSON.stringify({
    kind: "identity",
    action: "hello",
    browserId: appState.identity.browserId,
    publicKey: appState.identity.publicKey,
  }));
}

async function sendValidationChallenge(session) {
  if (session.role !== "owner" || !session.channel || !session.remoteIdentityPublicKey) {
    return;
  }
  session.validationChallenge = randomValidationChallenge();
  session.channel.send(JSON.stringify({
    kind: "identity",
    action: "ping",
    challenge: session.validationChallenge,
  }));
}

async function deriveSecretFactor(pendingSecret) {
  if (pendingSecret.authMode === "passphrase") {
    return pendingSecret.localPassphrase ? decryptLocalValue(pendingSecret.localPassphrase) : "";
  }
  if (pendingSecret.authMode === "totp") {
    const secret = await decryptLocalValue(pendingSecret.localTOTPSecret);
    return generateCurrentTOTP(secret);
  }
  return "";
}

function generateTOTPSecret() {
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  return bytesToBase32(bytes);
}

async function generateCurrentTOTP(secret) {
  const keyBytes = base32ToBytes(secret);
  const counter = Math.floor(Date.now() / 30000);
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setUint32(4, counter, false);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, buffer));
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(code % 1000000).padStart(6, "0");
}

function bytesToBase32(bytes) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }
  return output;
}

function base32ToBytes(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const cleaned = input.replace(/=+$/g, "").toUpperCase();
  let bits = 0;
  let value = 0;
  const out = [];
  for (const char of cleaned) {
    const idx = alphabet.indexOf(char);
    if (idx < 0) {
      continue;
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}
