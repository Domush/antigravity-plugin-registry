import fs from "node:fs/promises";
import path from "node:path";

export const REPO_ID_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
export const SHA40_RE = /^[a-f0-9]{40}$/;
export const SHA256_RE = /^[a-f0-9]{64}$/;
export const SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
export const DETAIL_PATH_RE = /^plugins\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\.json$/;

export const VALID_RISK_TIERS = new Set(["low", "elevated", "high", "unverified"]);
export const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low"]);
export const VALID_FINDING_LAYERS = new Set(["code", "prompt", "manifest"]);
export const VALID_UI_SLOTS = new Set(["global", "aux_pane", "file"]);
export const VALID_COMPONENTS = new Set([
  "skills",
  "rules",
  "agents",
  "hooks",
  "mcp_stdio",
  "mcp_remote",
]);
export const VALID_TRANSPORTS = new Set(["stdio", "http"]);

/**
 * Collects schema, parity, and security validation errors and warnings.
 */
export class Validator {
  constructor() {
    this.errors = [];
    this.warnings = [];
  }

  error(file, field, message) {
    this.errors.push({ file, field, message });
  }

  warn(file, field, message) {
    this.warnings.push({ file, field, message });
  }

  isIsoDate(val) {
    return typeof val === "string" && !Number.isNaN(Date.parse(val));
  }

  isNonNegInt(val) {
    return Number.isInteger(val) && val >= 0;
  }

  assertString(file, field, val, { allowEmpty = false } = {}) {
    if (typeof val !== "string" || (!allowEmpty && val.trim().length === 0)) {
      this.error(file, field, `Expected ${allowEmpty ? "string" : "non-empty string"}`);
      return false;
    }
    return true;
  }

  assertStringArray(file, field, val, { allowedSet = null, maxLen = 500 } = {}) {
    if (!Array.isArray(val)) {
      this.error(file, field, "Expected array");
      return false;
    }
    if (val.length > maxLen) {
      this.error(file, field, `Array length ${val.length} exceeds limit (${maxLen})`);
    }
    for (let i = 0; i < val.length; i++) {
      if (typeof val[i] !== "string" || val[i].trim().length === 0) {
        this.error(file, `${field}[${i}]`, "Expected non-empty string");
      } else if (allowedSet && !allowedSet.has(val[i])) {
        this.error(file, `${field}[${i}]`, `Unsupported value "${val[i]}"`);
      }
    }
    return true;
  }

  assertIsoDate(file, field, val) {
    if (!this.isIsoDate(val)) {
      this.error(file, field, `Expected ISO-8601 date string, got "${val}"`);
    }
  }

  assertHttpsUrl(file, field, val, { prefix = "https://" } = {}) {
    if (typeof val !== "string" || !val.startsWith(prefix)) {
      this.error(file, field, `Expected URL starting with "${prefix}", got "${val}"`);
    }
  }
}

export async function readJsonWithStats(absPath) {
  const stat = await fs.stat(absPath);
  const raw = await fs.readFile(absPath, "utf8");
  return { bytes: stat.size, data: JSON.parse(raw) };
}

export async function collectAllFiles(rootDir, currentDir = rootDir, out = []) {
  let entries;
  try {
    entries = await fs.readdir(currentDir, { withFileTypes: true });
  } catch (err) {
    if (err.code === "ENOENT") return out;
    throw err;
  }
  for (const entry of entries) {
    const full = path.join(currentDir, entry.name);
    if (entry.isDirectory()) {
      await collectAllFiles(rootDir, full, out);
    } else if (entry.isFile()) {
      out.push(path.relative(rootDir, full).split(path.sep).join("/"));
    }
  }
  return out;
}

export function sameStringSet(a = [], b = []) {
  const sa = new Set(a);
  const sb = new Set(b);
  if (sa.size !== sb.size) return false;
  for (const item of sa) {
    if (!sb.has(item)) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// 1. Validate denylist.json
// ---------------------------------------------------------------------------
export async function validateDenylist(v, publicDir) {
  const file = "denylist.json";
  const absPath = path.join(publicDir, file);
  const blockedRepos = new Set();
  const blockedShas = new Set();

  let doc;
  try {
    ({ data: doc } = await readJsonWithStats(absPath));
  } catch (err) {
    v.error(file, "$", `Missing or invalid JSON: ${err.message}`);
    return { blockedRepos, blockedShas };
  }

  if (doc.schemaVersion !== 1) v.error(file, "schemaVersion", "Must equal 1");
  v.assertIsoDate(file, "updatedAt", doc.updatedAt);

  if (!Array.isArray(doc.blockedRepos)) {
    v.error(file, "blockedRepos", "Expected array");
  } else {
    doc.blockedRepos.forEach((entry, i) => {
      const p = `blockedRepos[${i}]`;
      if (!entry || typeof entry !== "object") {
        v.error(file, p, "Expected object");
        return;
      }
      if (!REPO_ID_RE.test(entry.id || "")) v.error(file, `${p}.id`, `Invalid owner/repo "${entry.id}"`);
      else blockedRepos.add(entry.id.toLowerCase());
      v.assertString(file, `${p}.reason`, entry.reason);
      if (!VALID_SEVERITIES.has(entry.severity)) {
        v.error(file, `${p}.severity`, `Invalid severity "${entry.severity}"`);
      }
      v.assertIsoDate(file, `${p}.blockedAt`, entry.blockedAt);
    });
  }

  if (!Array.isArray(doc.blockedShas)) {
    v.error(file, "blockedShas", "Expected array");
  } else {
    doc.blockedShas.forEach((entry, i) => {
      const p = `blockedShas[${i}]`;
      if (!entry || typeof entry !== "object") {
        v.error(file, p, "Expected object");
        return;
      }
      if (!REPO_ID_RE.test(entry.id || "")) v.error(file, `${p}.id`, `Invalid owner/repo "${entry.id}"`);
      if (!SHA40_RE.test((entry.sha || "").toLowerCase())) {
        v.error(file, `${p}.sha`, `Expected 40-char hex commit SHA, got "${entry.sha}"`);
      }
      if (REPO_ID_RE.test(entry.id || "") && SHA40_RE.test((entry.sha || "").toLowerCase())) {
        blockedShas.add(`${entry.id.toLowerCase()}@${entry.sha.toLowerCase()}`);
      }
      v.assertString(file, `${p}.reason`, entry.reason);
      if (!VALID_SEVERITIES.has(entry.severity)) {
        v.error(file, `${p}.severity`, `Invalid severity "${entry.severity}"`);
      }
      v.assertIsoDate(file, `${p}.blockedAt`, entry.blockedAt);
    });
  }

  return { blockedRepos, blockedShas };
}
