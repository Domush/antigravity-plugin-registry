import {
  importTrustedEd25519Keys,
  sha256Hex,
  verifyDetachedEd25519,
} from "./verify.js";

const RISK_ORDER = { low: 0, elevated: 1, high: 2, unverified: 3 };

/**
 * Fetch and cryptographically verify index.json against index.json.sig (fail-closed).
 */
export async function loadVerifiedRegistry(state, { onReady, onError }) {
  try {
    let keyMap = null;
    if (!globalThis.crypto?.subtle) {
      state.sigState = "unsupported";
      state.sigStatus = "Needs HTTPS";
      state.sigWarning = "Ed25519 verification requires a secure context (HTTPS or localhost).";
    } else {
      try {
        keyMap = await importTrustedEd25519Keys();
        if (keyMap.size === 0) {
          state.sigState = "unconfigured";
          state.sigStatus = "Key Not Set";
          state.sigWarning = "No trusted Ed25519 public key configured in site/verify.js; catalog is unverified.";
        }
      } catch (err) {
        if (err.name === "NotSupportedError") {
          state.sigState = "unsupported";
          state.sigStatus = "Old Browser";
          state.sigWarning = "This browser does not support Web Crypto Ed25519 yet; update your browser to verify signatures.";
        } else {
          throw err;
        }
      }
    }

    let rawBuf = null;
    let lastVerifyErr = null;

    for (let attempt = 1; attempt <= 2; attempt++) {
      const cacheMode = attempt === 1 ? "no-cache" : "reload";
      const res = await fetch("./index.json", { cache: cacheMode });
      if (!res.ok) throw new Error(`HTTP ${res.status} loading index.json`);
      rawBuf = await res.arrayBuffer();

      if (!keyMap || keyMap.size === 0) {
        lastVerifyErr = null;
        break;
      }

      try {
        const sigRes = await fetch("./index.json.sig", { cache: "reload" });
        if (!sigRes.ok) {
          throw new Error(`Missing detached signature index.json.sig (HTTP ${sigRes.status}).`);
        }
        const sigEnvelope = await sigRes.json();
        const verified = await verifyDetachedEd25519({
          fileName: "index.json",
          rawBuf,
          sigEnvelope,
          keyMap,
        });
        state.sigState = "verified";
        state.sigStatus = `Verified (${verified.keyId.slice(0, 8)})`;
        state.sigWarning = "";
        lastVerifyErr = null;
        break;
      } catch (err) {
        lastVerifyErr = err;
        if (attempt === 1 && /digest mismatch|signature verification failed/i.test(err.message)) {
          await new Promise((r) => setTimeout(r, 1200));
          continue;
        }
        break;
      }
    }

    if (lastVerifyErr) {
      state.sigState = "invalid";
      state.sigStatus = "FAILED";
      state.index = { plugins: [], generatedAt: null };
      state.error = `Security Error: ${lastVerifyErr.message} Catalog display blocked.`;
      onError();
      return;
    }

    state.index = JSON.parse(new TextDecoder().decode(rawBuf));
    onReady();
  } catch (err) {
    state.sigState = "invalid";
    state.sigStatus = "Error";
    state.error = `Could not load registry catalog: ${err.message}`;
    onError();
  }
}

/**
 * Lazy-load a per-plugin detail JSON file with path validation and optional detailSha256 verification.
 */
export async function fetchVerifiedPluginDetail(plugin, detailCache) {
  if (detailCache.has(plugin.id)) {
    return detailCache.get(plugin.id);
  }
  const detailPath = plugin.detailPath || `plugins/${plugin.id}.json`;
  if (!/^plugins\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\.json$/.test(detailPath)) {
    throw new Error(`Invalid detail path: ${detailPath}`);
  }
  const res = await fetch(`./${detailPath}`);
  if (!res.ok) throw new Error(`HTTP ${res.status} loading ${detailPath}`);
  const buf = await res.arrayBuffer();

  if (plugin.detailSha256 && globalThis.crypto?.subtle) {
    const actual = await sha256Hex(buf);
    if (actual !== plugin.detailSha256) {
      throw new Error(`Integrity mismatch for ${detailPath}: hash does not match signed index.json.`);
    }
  }

  const detail = JSON.parse(new TextDecoder().decode(buf));
  detailCache.set(plugin.id, detail);
  return detail;
}

/**
 * Filter and sort catalog entries according to the active UI state.
 */
export function filterAndSortPlugins(state) {
  const q = state.q.trim().toLowerCase();
  const list = (state.index.plugins || []).filter((p) => {
    if (state.bookmarksOnly && !state.bookmarks.has(p.id)) return false;
    if (state.cat !== "all" && !(p.categories || []).includes(state.cat)) return false;
    if (state.noCreds && p.requiresCredentials) return false;

    if (state.surface === "sidebar_ui" && !p.surface?.hasSidebarUi) return false;
    if (state.surface === "prompt_only" && !(p.security?.capabilities || []).includes("prompt_rules_only")) return false;
    if (state.surface === "mcp_stdio" && !(p.surface?.components || []).includes("mcp_stdio")) return false;
    if (state.surface === "mcp_remote" && !(p.surface?.components || []).includes("mcp_remote")) return false;
    if (state.surface === "hooks" && !(p.surface?.components || []).includes("hooks")) return false;

    const riskRank = RISK_ORDER[p.security?.riskTier] ?? 3;
    if (state.risk === "low" && riskRank > 0) return false;
    if (state.risk === "elevated" && riskRank > 1) return false;

    if (q) {
      const hay = [
        p.id,
        p.name,
        p.pluginName,
        p.summary,
        p.author?.login,
        ...(p.categories || []),
        ...(p.tags || []),
      ]
        .join(" ")
        .toLowerCase();
      if (!hay.includes(q)) return false;
    }

    return true;
  });

  list.sort((a, b) => {
    if (state.sort === "stars") return (b.stats?.stars || 0) - (a.stats?.stars || 0);
    if (state.sort === "updated") return Date.parse(b.stats?.pushedAt || 0) - Date.parse(a.stats?.pushedAt || 0);
    if (state.sort === "risk") return (RISK_ORDER[a.security?.riskTier] ?? 3) - (RISK_ORDER[b.security?.riskTier] ?? 3);
    return a.name.localeCompare(b.name);
  });

  return list;
}
