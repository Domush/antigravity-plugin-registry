#!/usr/bin/env node
import path from "node:path";
import { validatePinnedIconUrl } from "./lib/icon-resolver.mjs";
import {
  collectAllFiles,
  DETAIL_PATH_RE,
  readJsonWithStats,
  REPO_ID_RE,
  sameStringSet,
  SEMVER_RE,
  SHA256_RE,
  SHA40_RE,
  VALID_COMPONENTS,
  VALID_FINDING_LAYERS,
  VALID_RISK_TIERS,
  VALID_SEVERITIES,
  VALID_TRANSPORTS,
  VALID_UI_SLOTS,
  validateDenylist,
  Validator,
} from "./lib/validators.mjs";

const PUBLIC_DIR = path.resolve(process.argv[2] || "./registry-data/public");
const IS_GITHUB_ACTIONS = process.env.GITHUB_ACTIONS === "true";

// Antigravity caps persisted MCP tool outputs at 1 MiB; guard index.json early
const INDEX_WARN_BYTES = 700 * 1024;
const INDEX_HARD_MAX_BYTES = 950 * 1024;
const DETAIL_HARD_MAX_BYTES = 512 * 1024;
const MAX_ARCHIVE_BYTES = 26_214_400; // 25 MB

// ---------------------------------------------------------------------------
// 2. Validate index.json
// ---------------------------------------------------------------------------
async function validateIndex(v, { blockedRepos, blockedShas }) {
  const file = "index.json";
  const absPath = path.join(PUBLIC_DIR, file);
  let bytes = 0;
  let doc;

  try {
    ({ bytes, data: doc } = await readJsonWithStats(absPath));
  } catch (err) {
    v.error(file, "$", `Missing or invalid JSON: ${err.message}`);
    return { indexDoc: null, indexBytes: 0 };
  }

  if (bytes > INDEX_HARD_MAX_BYTES) {
    v.error(
      file,
      "$",
      `Size ${(bytes / 1024).toFixed(1)} KB exceeds hard cap (${INDEX_HARD_MAX_BYTES / 1024} KB for 1 MiB MCP budget)`
    );
  } else if (bytes > INDEX_WARN_BYTES) {
    v.warn(
      file,
      "$",
      `Size ${(bytes / 1024).toFixed(1)} KB is approaching the 1 MiB MCP tool output cap; consider paginating or trimming fields`
    );
  }

  if (doc.schemaVersion !== 1) v.error(file, "schemaVersion", "Must equal 1");
  v.assertIsoDate(file, "generatedAt", doc.generatedAt);
  v.assertString(file, "crawlerVersion", doc.crawlerVersion);
  v.assertString(file, "scannerVersion", doc.scannerVersion);

  if (doc.marketplaceClient !== undefined && doc.marketplaceClient !== null) {
    const mc = doc.marketplaceClient;
    if (typeof mc !== "object") {
      v.error(file, "marketplaceClient", "Expected object");
    } else {
      if (!SEMVER_RE.test(mc.latestVersion || "")) {
        v.error(file, "marketplaceClient.latestVersion", `Invalid semver "${mc.latestVersion}"`);
      }
      if (mc.minSupportedVersion && !SEMVER_RE.test(mc.minSupportedVersion)) {
        v.error(file, "marketplaceClient.minSupportedVersion", `Invalid semver "${mc.minSupportedVersion}"`);
      }
      v.assertHttpsUrl(file, "marketplaceClient.releaseUrl", mc.releaseUrl);
    }
  }

  if (!Array.isArray(doc.plugins)) {
    v.error(file, "plugins", "Expected array");
    return { indexDoc: null, indexBytes: bytes };
  }

  if (doc.totalPlugins !== doc.plugins.length) {
    v.error(file, "totalPlugins", `Mismatch: totalPlugins=${doc.totalPlugins} but plugins.length=${doc.plugins.length}`);
  }

  const seenIds = new Set();
  let prevSortKey = null;

  doc.plugins.forEach((p, i) => {
    const ctx = `plugins[${i}]`;
    if (!p || typeof p !== "object") {
      v.error(file, ctx, "Expected object");
      return;
    }

    if (!REPO_ID_RE.test(p.id || "")) {
      v.error(file, `${ctx}.id`, `Invalid owner/repo "${p.id}"`);
    } else {
      const idLower = p.id.toLowerCase();
      if (seenIds.has(idLower)) {
        v.error(file, `${ctx}.id`, `Duplicate plugin id "${p.id}"`);
      }
      seenIds.add(idLower);

      if (prevSortKey !== null && idLower < prevSortKey) {
        v.error(file, `${ctx}.id`, `Plugins array is not sorted lexicographically ("${p.id}" after "${prevSortKey}")`);
      }
      prevSortKey = idLower;

      if (blockedRepos.has(idLower)) {
        v.error(file, `${ctx}.id`, `Denylisted repository "${p.id}" leaked into index.json`);
      }
      if (p.release?.sha && blockedShas.has(`${idLower}@${String(p.release.sha).toLowerCase()}`)) {
        v.error(file, `${ctx}.release.sha`, `Denylisted SHA "${p.release.sha}" for "${p.id}" leaked into index.json`);
      }
    }

    v.assertString(file, `${ctx}.name`, p.name);
    v.assertString(file, `${ctx}.summary`, p.summary, { allowEmpty: true });
    if (p.iconUrl !== undefined && p.iconUrl !== null) {
      const iconErr = validatePinnedIconUrl(p.iconUrl, p.id, p.release?.sha);
      if (iconErr) v.error(file, `${ctx}.iconUrl`, iconErr);
    }
    v.assertHttpsUrl(file, `${ctx}.repoUrl`, p.repoUrl, { prefix: "https://github.com/" });
    v.assertString(file, `${ctx}.license`, p.license);

    if (!SEMVER_RE.test(p.version || "")) {
      v.error(file, `${ctx}.version`, `Invalid semver "${p.version}"`);
    }
    if (p.minAppVersion !== null && p.minAppVersion !== undefined && !SEMVER_RE.test(p.minAppVersion)) {
      v.error(file, `${ctx}.minAppVersion`, `Expected null or semver, got "${p.minAppVersion}"`);
    }

    if (!p.author || typeof p.author !== "object") {
      v.error(file, `${ctx}.author`, "Expected object");
    } else {
      v.assertString(file, `${ctx}.author.login`, p.author.login);
      v.assertHttpsUrl(file, `${ctx}.author.avatarUrl`, p.author.avatarUrl);
      v.assertHttpsUrl(file, `${ctx}.author.url`, p.author.url, { prefix: "https://github.com/" });
    }

    if (!p.release || typeof p.release !== "object") {
      v.error(file, `${ctx}.release`, "Expected object");
    } else {
      v.assertString(file, `${ctx}.release.ref`, p.release.ref);
      if (!SHA40_RE.test(p.release.sha || "")) {
        v.error(file, `${ctx}.release.sha`, `Expected 40-char lowercase hex commit SHA, got "${p.release.sha}"`);
      }
      const expectedTarball = `https://api.github.com/repos/${p.id}/tarball/${p.release.sha}`;
      if (p.release.tarballUrl !== expectedTarball) {
        v.error(
          file,
          `${ctx}.release.tarballUrl`,
          `Tarball URL must pin exact commit SHA ("${expectedTarball}"), got "${p.release.tarballUrl}"`
        );
      }
      if (!SHA256_RE.test(p.release.contentTreeSha256 || "")) {
        v.error(file, `${ctx}.release.contentTreeSha256`, "Expected 64-char lowercase hex SHA-256");
      }
      if (!Number.isInteger(p.release.archiveBytes) || p.release.archiveBytes <= 0 || p.release.archiveBytes > MAX_ARCHIVE_BYTES) {
        v.error(file, `${ctx}.release.archiveBytes`, `Must be an integer in 1..${MAX_ARCHIVE_BYTES}`);
      }
      v.assertIsoDate(file, `${ctx}.release.publishedAt`, p.release.publishedAt);
    }

    if (!p.surface || typeof p.surface !== "object") {
      v.error(file, `${ctx}.surface`, "Expected object");
    } else {
      if (typeof p.surface.hasSidebarUi !== "boolean") {
        v.error(file, `${ctx}.surface.hasSidebarUi`, "Expected boolean");
      }
      v.assertStringArray(file, `${ctx}.surface.uiSlots`, p.surface.uiSlots, { allowedSet: VALID_UI_SLOTS });
      v.assertStringArray(file, `${ctx}.surface.components`, p.surface.components, { allowedSet: VALID_COMPONENTS });
      if (p.surface.hasSidebarUi && (!Array.isArray(p.surface.uiSlots) || p.surface.uiSlots.length === 0)) {
        v.error(file, `${ctx}.surface.uiSlots`, "hasSidebarUi is true but uiSlots is empty");
      }
    }

    v.assertStringArray(file, `${ctx}.categories`, p.categories, { maxLen: 10 });
    v.assertStringArray(file, `${ctx}.tags`, p.tags, { maxLen: 20 });
    if (typeof p.requiresCredentials !== "boolean") {
      v.error(file, `${ctx}.requiresCredentials`, "Expected boolean");
    }

    if (!p.stats || typeof p.stats !== "object") {
      v.error(file, `${ctx}.stats`, "Expected object");
    } else {
      for (const k of ["stars", "forks", "openIssues"]) {
        if (!v.isNonNegInt(p.stats[k])) v.error(file, `${ctx}.stats.${k}`, "Expected non-negative integer");
      }
      v.assertIsoDate(file, `${ctx}.stats.pushedAt`, p.stats.pushedAt);
    }

    if (!p.security || typeof p.security !== "object") {
      v.error(file, `${ctx}.security`, "Expected object");
    } else {
      if (!VALID_RISK_TIERS.has(p.security.riskTier)) {
        v.error(file, `${ctx}.security.riskTier`, `Invalid riskTier "${p.security.riskTier}"`);
      }
      v.assertString(file, `${ctx}.security.scannerVersion`, p.security.scannerVersion);
      v.assertIsoDate(file, `${ctx}.security.scannedAt`, p.security.scannedAt);
      v.assertStringArray(file, `${ctx}.security.capabilities`, p.security.capabilities);
      if (!p.security.findingCounts || typeof p.security.findingCounts !== "object") {
        v.error(file, `${ctx}.security.findingCounts`, "Expected object");
      } else {
        for (const sev of VALID_SEVERITIES) {
          if (!v.isNonNegInt(p.security.findingCounts[sev])) {
            v.error(file, `${ctx}.security.findingCounts.${sev}`, "Expected non-negative integer");
          }
        }
      }
    }

    const expectedDetailPath = `plugins/${p.id}.json`;
    if (!DETAIL_PATH_RE.test(p.detailPath || "") || p.detailPath !== expectedDetailPath) {
      v.error(file, `${ctx}.detailPath`, `Expected "${expectedDetailPath}", got "${p.detailPath}"`);
    }
  });

  return { indexDoc: doc, indexBytes: bytes };
}

// ---------------------------------------------------------------------------
// 3. Validate Per-Plugin Detail JSON + Cross-File Parity
// ---------------------------------------------------------------------------
async function validatePluginDetail(v, indexEntry) {
  const relPath = indexEntry.detailPath;
  const absPath = path.join(PUBLIC_DIR, ...relPath.split("/"));

  let bytes = 0;
  let doc;
  try {
    ({ bytes, data: doc } = await readJsonWithStats(absPath));
  } catch (err) {
    v.error(relPath, "$", `Referenced by index.json but missing or invalid JSON: ${err.message}`);
    return;
  }

  if (bytes > DETAIL_HARD_MAX_BYTES) {
    v.error(relPath, "$", `Detail JSON size ${(bytes / 1024).toFixed(1)} KB exceeds ${DETAIL_HARD_MAX_BYTES / 1024} KB cap`);
  }

  if (doc.schemaVersion !== 1) v.error(relPath, "schemaVersion", "Must equal 1");
  if (doc.id !== indexEntry.id) v.error(relPath, "id", `Mismatch with index.json ("${indexEntry.id}")`);
  if (doc.sha !== indexEntry.release?.sha) {
    v.error(relPath, "sha", `Mismatch with index.json release.sha ("${indexEntry.release?.sha}")`);
  }
  if (doc.scannerVersion !== indexEntry.security?.scannerVersion) {
    v.error(relPath, "scannerVersion", "Mismatch with index.json security.scannerVersion");
  }
  v.assertIsoDate(relPath, "scannedAt", doc.scannedAt);

  if (!doc.manifest || typeof doc.manifest !== "object") {
    v.error(relPath, "manifest", "Expected object");
  } else {
    v.assertString(relPath, "manifest.manifestPath", doc.manifest.manifestPath);
    v.assertString(relPath, "manifest.name", doc.manifest.name);
    if (doc.manifest.version !== indexEntry.version) {
      v.error(relPath, "manifest.version", `Mismatch with index.json version ("${indexEntry.version}")`);
    }
    if (!Array.isArray(doc.manifest.mcpServers)) {
      v.error(relPath, "manifest.mcpServers", "Expected array");
    } else {
      doc.manifest.mcpServers.forEach((srv, i) => {
        const p = `manifest.mcpServers[${i}]`;
        v.assertString(relPath, `${p}.name`, srv?.name);
        if (!VALID_TRANSPORTS.has(srv?.transport)) {
          v.error(relPath, `${p}.transport`, `Invalid transport "${srv?.transport}"`);
        }
        if (srv && ("env" in srv || "headers" in srv)) {
          v.error(relPath, p, "Secret-leak violation: raw 'env' or 'headers' must be stripped before publishing");
        }
      });
    }
  }

  if (!doc.collisions || typeof doc.collisions !== "object") {
    v.error(relPath, "collisions", "Expected object");
  } else {
    v.assertStringArray(relPath, "collisions.slashCommands", doc.collisions.slashCommands);
    v.assertStringArray(relPath, "collisions.mcpServerNames", doc.collisions.mcpServerNames);
    v.assertStringArray(relPath, "collisions.hookEvents", doc.collisions.hookEvents);
    if (doc.collisions.agentNames !== undefined) {
      v.assertStringArray(relPath, "collisions.agentNames", doc.collisions.agentNames);
    }
  }

  if (!doc.credentials || typeof doc.credentials !== "object") {
    v.error(relPath, "credentials", "Expected object");
  } else {
    if (!Array.isArray(doc.credentials.envVars)) {
      v.error(relPath, "credentials.envVars", "Expected array");
    } else {
      doc.credentials.envVars.forEach((env, i) => {
        v.assertString(relPath, `credentials.envVars[${i}].name`, env?.name);
        if (typeof env?.required !== "boolean") {
          v.error(relPath, `credentials.envVars[${i}].required`, "Expected boolean");
        }
      });
    }
    v.assertStringArray(relPath, "credentials.oauthProviders", doc.credentials.oauthProviders);
  }

  v.assertString(relPath, "readmeMarkdown", doc.readmeMarkdown, { allowEmpty: true });
  v.assertString(relPath, "latestReleaseNotes", doc.latestReleaseNotes, { allowEmpty: true });

  if (!doc.securityReport || typeof doc.securityReport !== "object") {
    v.error(relPath, "securityReport", "Expected object");
  } else {
    if (doc.securityReport.riskTier !== indexEntry.security?.riskTier) {
      v.error(relPath, "securityReport.riskTier", "Mismatch with index.json security.riskTier");
    }
    if (!sameStringSet(doc.securityReport.capabilities, indexEntry.security?.capabilities)) {
      v.error(relPath, "securityReport.capabilities", "Capabilities set does not match index.json");
    }

    if (!Array.isArray(doc.securityReport.findings)) {
      v.error(relPath, "securityReport.findings", "Expected array");
    } else {
      const actualCounts = { critical: 0, high: 0, medium: 0, low: 0 };
      const blobPrefix = `https://github.com/${indexEntry.id}/blob/${indexEntry.release?.sha}/`;

      doc.securityReport.findings.forEach((f, i) => {
        const p = `securityReport.findings[${i}]`;
        v.assertString(relPath, `${p}.id`, f?.id);
        if (!VALID_SEVERITIES.has(f?.severity)) {
          v.error(relPath, `${p}.severity`, `Invalid severity "${f?.severity}"`);
        } else {
          actualCounts[f.severity] += 1;
        }
        if (!VALID_FINDING_LAYERS.has(f?.layer)) {
          v.error(relPath, `${p}.layer`, `Invalid layer "${f?.layer}"`);
        }
        v.assertString(relPath, `${p}.capability`, f?.capability);
        v.assertString(relPath, `${p}.message`, f?.message);
        v.assertString(relPath, `${p}.file`, f?.file);
        if (!Number.isInteger(f?.line) || f.line < 1) {
          v.error(relPath, `${p}.line`, `Expected line integer greater than or equal to 1, got "${f?.line}"`);
        }
        v.assertHttpsUrl(relPath, `${p}.githubBlobUrl`, f?.githubBlobUrl, { prefix: blobPrefix });
      });

      for (const sev of VALID_SEVERITIES) {
        if (actualCounts[sev] !== indexEntry.security?.findingCounts?.[sev]) {
          v.error(
            relPath,
            `securityReport.findings (${sev})`,
            `Count ${actualCounts[sev]} disagrees with index.json findingCounts.${sev} (${indexEntry.security?.findingCounts?.[sev]})`
          );
        }
      }
    }
  }

  if (!Array.isArray(doc.history) || doc.history.length === 0) {
    v.error(relPath, "history", "Expected non-empty history array");
  } else {
    if (doc.history[0]?.sha !== doc.sha) {
      v.error(relPath, "history[0].sha", "Latest history entry must match current detail SHA");
    }
    const seenHistoryShas = new Set();
    doc.history.forEach((h, i) => {
      const p = `history[${i}]`;
      if (!SHA40_RE.test(h?.sha || "")) v.error(relPath, `${p}.sha`, "Invalid 40-char commit SHA");
      else if (seenHistoryShas.has(h.sha)) v.error(relPath, `${p}.sha`, `Duplicate SHA "${h.sha}" in history`);
      else seenHistoryShas.add(h.sha);

      if (!SEMVER_RE.test(h?.version || "")) v.error(relPath, `${p}.version`, `Invalid semver "${h?.version}"`);
      if (!VALID_RISK_TIERS.has(h?.riskTier)) v.error(relPath, `${p}.riskTier`, `Invalid riskTier "${h?.riskTier}"`);
      v.assertIsoDate(relPath, `${p}.scannedAt`, h?.scannedAt);
      v.assertStringArray(relPath, `${p}.capabilities`, h?.capabilities);
    });
  }
}

// ---------------------------------------------------------------------------
// 4. Orphan & Unexpected File Check under plugins/
// ---------------------------------------------------------------------------
async function checkOrphanDetailFiles(v, indexDoc) {
  const expectedFiles = new Set(
    (indexDoc?.plugins || []).map((p) => p.detailPath.toLowerCase())
  );
  const pluginsRoot = path.join(PUBLIC_DIR, "plugins");
  const actualRelPaths = await collectAllFiles(PUBLIC_DIR, pluginsRoot);

  for (const rel of actualRelPaths) {
    if (!rel.endsWith(".json")) {
      v.error(rel, "$", "Unexpected non-JSON file inside plugins/ directory");
    } else if (!expectedFiles.has(rel.toLowerCase())) {
      v.error(rel, "$", "Orphaned plugin detail file not referenced in index.json");
    }
  }
}

// ---------------------------------------------------------------------------
// Main Runner
// ---------------------------------------------------------------------------
async function main() {
  const v = new Validator();
  const deny = await validateDenylist(v, PUBLIC_DIR);
  const { indexDoc, indexBytes } = await validateIndex(v, deny);

  if (indexDoc) {
    for (const entry of indexDoc.plugins) {
      if (DETAIL_PATH_RE.test(entry.detailPath || "")) {
        await validatePluginDetail(v, entry);
      }
    }
    await checkOrphanDetailFiles(v, indexDoc);
  }

  for (const w of v.warnings) {
    if (IS_GITHUB_ACTIONS) {
      console.log(`::warning file=${w.file}::[${w.field}] ${w.message}`);
    } else {
      console.warn(`[warn] ${w.file} (${w.field}): ${w.message}`);
    }
  }

  if (v.errors.length > 0) {
    const maxToPrint = 100;
    for (const e of v.errors.slice(0, maxToPrint)) {
      if (IS_GITHUB_ACTIONS) {
        console.log(`::error file=${e.file}::[${e.field}] ${e.message}`);
      } else {
        console.error(`[error] ${e.file} (${e.field}): ${e.message}`);
      }
    }
    if (v.errors.length > maxToPrint) {
      console.error(`[error] ...and ${v.errors.length - maxToPrint} additional errors.`);
    }
    console.error(`\n[validate] FAILED with ${v.errors.length} error(s) and ${v.warnings.length} warning(s).`);
    process.exitCode = 1;
    return;
  }

  const pluginCount = indexDoc?.totalPlugins ?? 0;
  console.log(
    `[validate] PASSED: ${pluginCount} plugin(s), index.json=${(indexBytes / 1024).toFixed(1)} KB, ` +
      `${deny.blockedRepos.size} blocked repo(s), ${deny.blockedShas.size} blocked SHA(s), ${v.warnings.length} warning(s).`
  );
}

main().catch((err) => {
  console.error("[validate] Fatal error:", err);
  process.exitCode = 1;
});
