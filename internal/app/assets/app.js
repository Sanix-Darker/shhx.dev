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
