import {
  fetchVerifiedPluginDetail,
  filterAndSortPlugins,
  loadVerifiedRegistry,
} from "./catalog.js";
import {
  esc,
  populateCategories,
  renderCard,
  renderDrawerContent,
  renderStats,
  swapBrokenIcon,
} from "./render.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const REGISTRY_GITHUB_REPO = "https://github.com/Domush/antigravity-plugin-registry";
const CLIENT_PLUGIN_REPO = "https://github.com/Domush/antigravity-community-marketplace";

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const STORAGE_BOOKMARKS = "agy_web_bookmarks_v1";
const STORAGE_THEME = "agy_web_theme_v1";

const state = {
  index: { plugins: [], generatedAt: null },
  sigStatus: "Checking...",
  sigState: "pending", // "verified" | "unconfigured" | "unsupported" | "invalid"
  sigWarning: "",
  bookmarks: new Set(loadJsonStorage(STORAGE_BOOKMARKS, [])),
  bookmarksOnly: false,
  error: "",

  // URL-synced filters
  q: "",
  cat: "all",
  surface: "all",
  risk: "all",
  sort: "stars",
  noCreds: false,

  // Drawer state
  drawer: {
    open: false,
    pluginId: null,
    tab: "install", // "install" | "audit" | "readme"
    loading: false,
    detail: null,
    error: null,
  },
  detailCache: new Map(),
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function loadJsonStorage(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

let toastTimer = null;
function showToast(message) {
  const el = document.getElementById("toast");
  el.textContent = message;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    el.hidden = true;
  }, 2200);
}

async function copyText(text, label = "Copied to clipboard") {
  try {
    await navigator.clipboard.writeText(text);
    showToast(label);
  } catch {
    window.prompt("Copy command:", text);
  }
}

function applyTheme(theme) {
  if (theme === "light" || theme === "dark") {
    document.documentElement.dataset.theme = theme;
  } else {
    delete document.documentElement.dataset.theme;
  }
}

// ---------------------------------------------------------------------------
// URL State Sync (Shareable Filtered Views & Deep-Linked Plugin Drawers)
// ---------------------------------------------------------------------------
function readUrlState() {
  const params = new URLSearchParams(window.location.search);
  state.q = params.get("q") || "";
  state.cat = params.get("cat") || "all";
  state.surface = params.get("surface") || "all";
  state.risk = params.get("risk") || "all";
  state.sort = params.get("sort") || "stars";
  state.noCreds = params.get("nocreds") === "1";
  state.bookmarksOnly = params.get("saved") === "1";

  document.getElementById("search-input").value = state.q;
  const catSelect = document.getElementById("filter-category");
  if (catSelect.options.length > 1) {
    const hasCat = [...catSelect.options].some((opt) => opt.value === state.cat);
    catSelect.value = hasCat ? state.cat : "all";
    if (!hasCat) state.cat = "all";
  }
  document.getElementById("filter-surface").value = state.surface;
  document.getElementById("filter-risk").value = state.risk;
  document.getElementById("sort-select").value = state.sort;
  document.getElementById("chk-no-creds").checked = state.noCreds;

  return params.get("plugin");
}

function syncUrlState({ push = false } = {}) {
  const params = new URLSearchParams();
  if (state.q.trim()) params.set("q", state.q.trim());
  if (state.cat !== "all") params.set("cat", state.cat);
  if (state.surface !== "all") params.set("surface", state.surface);
  if (state.risk !== "all") params.set("risk", state.risk);
  if (state.sort !== "stars") params.set("sort", state.sort);
  if (state.noCreds) params.set("nocreds", "1");
  if (state.bookmarksOnly) params.set("saved", "1");
  if (state.drawer.open && state.drawer.pluginId) params.set("plugin", state.drawer.pluginId);

  const qs = params.toString();
  const nextUrl = qs ? `${window.location.pathname}?${qs}` : window.location.pathname;
  if (push) window.history.pushState(null, "", nextUrl);
  else window.history.replaceState(null, "", nextUrl);
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------
function render() {
  const alertsEl = document.getElementById("site-alerts");
  const alertParts = [];
  if (state.error) {
    alertParts.push(`<div class="alert alert-danger">${esc(state.error)}</div>`);
  }
  if (state.sigWarning) {
    alertParts.push(`<div class="alert alert-warning">${esc(state.sigWarning)}</div>`);
  }
  alertsEl.innerHTML = alertParts.join("");

  document.getElementById("bookmark-count").textContent = String(state.bookmarks.size);
  document.getElementById("btn-bookmarks").setAttribute("aria-pressed", String(state.bookmarksOnly));

  const hasActiveFilter =
    Boolean(state.q.trim()) ||
    state.cat !== "all" ||
    state.surface !== "all" ||
    state.risk !== "all" ||
    state.noCreds ||
    state.bookmarksOnly;
  document.getElementById("btn-clear-filters").hidden = !hasActiveFilter;

  const filtered = filterAndSortPlugins(state);
  const total = (state.index.plugins || []).length;
  document.getElementById("results-count").textContent =
    `Showing ${filtered.length} of ${total} plugin${total === 1 ? "" : "s"}`;

  const grid = document.getElementById("plugin-grid");
  if (filtered.length === 0) {
    grid.innerHTML = `<div class="empty-state">No plugins match your current search and filters.</div>`;
  } else {
    grid.innerHTML = filtered.map((p) => renderCard(p, state)).join("");
  }
}

function renderDrawer() {
  renderDrawerContent(state, {
    registryGithubRepo: REGISTRY_GITHUB_REPO,
    clientPluginRepo: CLIENT_PLUGIN_REPO,
  });
}

// ---------------------------------------------------------------------------
// Slide-Over Drawer Lifecycle
// ---------------------------------------------------------------------------
async function openDrawer(pluginId, { pushHistory = true, tab = "install" } = {}) {
  const plugin = (state.index.plugins || []).find(
    (p) => p.id.toLowerCase() === pluginId.toLowerCase()
  );
  if (!plugin) return;

  state.drawer = {
    open: true,
    pluginId: plugin.id,
    tab,
    loading: true,
    detail: null,
    error: null,
  };
  syncUrlState({ push: pushHistory });

  document.getElementById("drawer-backdrop").hidden = false;
  const drawerEl = document.getElementById("detail-drawer");
  drawerEl.classList.add("is-open");
  drawerEl.setAttribute("aria-hidden", "false");
  renderDrawer();

  try {
    state.drawer.detail = await fetchVerifiedPluginDetail(plugin, state.detailCache);
  } catch (err) {
    state.drawer.error = err.message;
  } finally {
    state.drawer.loading = false;
    renderDrawer();
  }
}

function closeDrawer() {
  state.drawer.open = false;
  state.drawer.pluginId = null;
  document.getElementById("drawer-backdrop").hidden = true;
  const drawerEl = document.getElementById("detail-drawer");
  drawerEl.classList.remove("is-open");
  drawerEl.setAttribute("aria-hidden", "true");
  syncUrlState({ push: false });
}

// ---------------------------------------------------------------------------
// Events & Boot
// ---------------------------------------------------------------------------
function bindEvents() {
  document.getElementById("link-submit-plugin").href =
    `${REGISTRY_GITHUB_REPO}/issues/new?template=submit-plugin.yml`;
  document.getElementById("link-install-client").href = CLIENT_PLUGIN_REPO;
  document.getElementById("link-registry-repo").href = REGISTRY_GITHUB_REPO;

  const updateFilter = (fn) => {
    fn();
    syncUrlState({ push: false });
    render();
  };

  document.getElementById("search-input").addEventListener("input", (e) =>
    updateFilter(() => { state.q = e.target.value; })
  );
  document.getElementById("filter-category").addEventListener("change", (e) =>
    updateFilter(() => { state.cat = e.target.value; })
  );
  document.getElementById("filter-surface").addEventListener("change", (e) =>
    updateFilter(() => { state.surface = e.target.value; })
  );
  document.getElementById("filter-risk").addEventListener("change", (e) =>
    updateFilter(() => { state.risk = e.target.value; })
  );
  document.getElementById("sort-select").addEventListener("change", (e) =>
    updateFilter(() => { state.sort = e.target.value; })
  );
  document.getElementById("chk-no-creds").addEventListener("change", (e) =>
    updateFilter(() => { state.noCreds = e.target.checked; })
  );
  document.getElementById("btn-bookmarks").addEventListener("click", () =>
    updateFilter(() => { state.bookmarksOnly = !state.bookmarksOnly; })
  );

  const resetAll = () => {
    state.q = "";
    state.cat = "all";
    state.surface = "all";
    state.risk = "all";
    state.sort = "stars";
    state.noCreds = false;
    state.bookmarksOnly = false;
    document.getElementById("search-input").value = "";
    document.getElementById("filter-category").value = "all";
    document.getElementById("filter-surface").value = "all";
    document.getElementById("filter-risk").value = "all";
    document.getElementById("sort-select").value = "stars";
    document.getElementById("chk-no-creds").checked = false;
    syncUrlState({ push: false });
    render();
  };

  document.getElementById("btn-clear-filters").addEventListener("click", resetAll);
  document.getElementById("brand-reset").addEventListener("click", (e) => {
    e.preventDefault();
    closeDrawer();
    resetAll();
  });

  // Theme toggle
  applyTheme(localStorage.getItem(STORAGE_THEME) || "");
  document.getElementById("btn-theme").addEventListener("click", () => {
    const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    const current = document.documentElement.dataset.theme || (prefersDark ? "dark" : "light");
    const next = current === "dark" ? "light" : "dark";
    localStorage.setItem(STORAGE_THEME, next);
    applyTheme(next);
  });

  // Delegated grid & drawer actions + CSP-safe image error fallbacks
  const gridEl = document.getElementById("plugin-grid");
  const drawerEl = document.getElementById("detail-drawer");
  gridEl.addEventListener("error", swapBrokenIcon, true);
  drawerEl.addEventListener("error", swapBrokenIcon, true);

  gridEl.addEventListener("click", (e) => {
    const el = e.target.closest("[data-open-plugin], [data-bookmark], [data-copy]");
    if (!el) return;
    if (el.dataset.openPlugin) {
      const requestedTab = el.dataset.openTab;
      const tab = requestedTab === "audit" || requestedTab === "readme" ? requestedTab : "install";
      openDrawer(el.dataset.openPlugin, { tab });
    } else if (el.dataset.bookmark) {
      const id = el.dataset.bookmark;
      if (state.bookmarks.has(id)) state.bookmarks.delete(id);
      else state.bookmarks.add(id);
      localStorage.setItem(STORAGE_BOOKMARKS, JSON.stringify([...state.bookmarks]));
      render();
    } else if (el.dataset.copy) {
      copyText(el.dataset.copy, "CLI install command copied");
    }
  });

  document.getElementById("drawer-backdrop").addEventListener("click", closeDrawer);
  drawerEl.addEventListener("click", (e) => {
    const btn = e.target.closest("button");
    if (!btn) return;
    if (btn.hasAttribute("data-close-drawer")) {
      closeDrawer();
    } else if (btn.dataset.drawerTab) {
      state.drawer.tab = btn.dataset.drawerTab;
      renderDrawer();
    } else if (btn.dataset.copy) {
      copyText(btn.dataset.copy);
    }
  });

  // Keyboard shortcuts: "/" focuses search, "Escape" closes drawer
  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && state.drawer.open) {
      closeDrawer();
    } else if (e.key === "/" && !e.metaKey && !e.ctrlKey && document.activeElement?.tagName !== "INPUT") {
      e.preventDefault();
      document.getElementById("search-input").focus();
    }
  });

  window.addEventListener("popstate", () => {
    const pluginParam = readUrlState();
    render();
    if (pluginParam) openDrawer(pluginParam, { pushHistory: false });
    else if (state.drawer.open) closeDrawer();
  });
}

async function boot() {
  bindEvents();
  const initialPlugin = readUrlState();
  await loadVerifiedRegistry(state, {
    onReady: () => {
      populateCategories(state);
      renderStats(state);
      render();
    },
    onError: () => {
      renderStats(state);
      render();
    },
  });
  if (initialPlugin) {
    await openDrawer(initialPlugin, { pushHistory: false });
  }
}

boot();
