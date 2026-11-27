#!/usr/bin/env node
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  computeContentTreeSha256,
  downloadAndExtractTarball,
  resolveInsideSandbox,
  stripTopLevelDir,
} from "./lib/archive.mjs";
import { resolveClientRelease } from "./lib/client-release.mjs";
import { createGitHubClient } from "./lib/github-client.mjs";
import { buildPinnedIconUrl } from "./lib/icon-resolver.mjs";
import { fileExists, validateAndParsePlugin } from "./lib/plugin-parser.mjs";
import { scanPluginSecurity } from "./security-scanner.mjs";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const CONFIG = {
  githubToken: process.env.GITHUB_TOKEN || "",
  registryDir: path.resolve(process.env.REGISTRY_DIR || "./registry-data/public"),
  denylistPath: path.resolve(process.env.DENYLIST_PATH || "./config/denylist.json"),
  clientReleasePath: path.resolve(process.env.CLIENT_RELEASE_PATH || "./config/client-release.json"),
  forceRescan: process.env.FORCE_RESCAN === "true",
  targetRepo: (process.env.TARGET_REPO || "").trim(),
  summaryPath: (process.env.CRAWL_SUMMARY_PATH || "").trim(),
  topics: ["agy-plugin", "antigravity-plugin"],
  crawlerVersion: "1.0.1",
  scannerVersion: "1.2.0",
  schemaVersion: 1,
  maxArchiveBytes: Number(process.env.MAX_ARCHIVE_BYTES || 25 * 1024 * 1024), // 25 MB compressed
  maxUncompressedBytes: 50 * 1024 * 1024, // 50 MB uncompressed
  maxFiles: 5000,
  maxReadmeBytes: 32 * 1024,
  maxHistoryEntries: 10,
  searchStartDate: "2024-01-01",
  userAgent: "agy-plugin-registry-crawler/1.0.1",
};

const gh = createGitHubClient({
  githubToken: CONFIG.githubToken,
  userAgent: CONFIG.userAgent,
  topics: CONFIG.topics,
  searchStartDate: CONFIG.searchStartDate,
});

// ---------------------------------------------------------------------------
// Security Scanner Hook
// ---------------------------------------------------------------------------
async function runSecurityScan({ sandboxDir, files = [], parsed, repoFullName, sha, skipSemgrep = false }) {
  return scanPluginSecurity({
    sandboxDir,
    files,
    parsed,
    repoFullName,
    sha,
    scannerVersion: CONFIG.scannerVersion,
    skipSemgrep,
  });
}

// ---------------------------------------------------------------------------
// State Persistence, Summary Hook & Stale File Pruning
// ---------------------------------------------------------------------------
async function loadJsonSafe(filePath, fallback) {
  try {
    return JSON.parse(await fs.readFile(filePath, "utf8"));
  } catch (err) {
    if (err.code !== "ENOENT") {
      console.warn(`[state] Could not read ${filePath}: ${err.message}`);
    }
    return fallback;
  }
}

async function loadClientReleasePolicy(filePath) {
  let raw;
  try {
    raw = await fs.readFile(filePath, "utf8");
  } catch (err) {
    throw new Error(`Could not read client release policy ${filePath}: ${err.message}`, { cause: err });
  }
  try {
    return JSON.parse(raw);
  } catch (err) {
    throw new Error(`Malformed JSON in client release policy ${filePath}: ${err.message}`, { cause: err });
  }
}

async function pruneStaleDetails(pluginsDir, activeIds) {
  let owners;
  try {
    owners = await fs.readdir(pluginsDir, { withFileTypes: true });
  } catch (err) {
    if (err.code !== "ENOENT") {
      console.warn(`[prune] Could not read ${pluginsDir}: ${err.message}`);
    }
    return;
  }

  for (const ownerDir of owners) {
    if (!ownerDir.isDirectory()) continue;
    const ownerPath = path.join(pluginsDir, ownerDir.name);
    const repoFiles = await fs.readdir(ownerPath, { withFileTypes: true });
    let remaining = 0;

    for (const file of repoFiles) {
      if (!file.isFile() || !file.name.endsWith(".json")) continue;
      const repoName = file.name.slice(0, -".json".length);
      const id = `${ownerDir.name}/${repoName}`.toLowerCase();
      if (!activeIds.has(id)) {
        await fs.rm(path.join(ownerPath, file.name), { force: true });
        console.log(`[prune] Removed stale detail file for ${ownerDir.name}/${repoName}`);
      } else {
        remaining += 1;
      }
    }

    if (remaining === 0) {
      await fs.rm(ownerPath, { recursive: true, force: true });
    }
  }
}

async function writeTargetSummary(payload) {
  if (!CONFIG.summaryPath) return;
  await fs.writeFile(CONFIG.summaryPath, JSON.stringify(payload, null, 2) + "\n", "utf8");
}

// ---------------------------------------------------------------------------
// Main Pipeline
// ---------------------------------------------------------------------------
async function main() {
  const indexPath = path.join(CONFIG.registryDir, "index.json");
  const pluginsDir = path.join(CONFIG.registryDir, "plugins");
  await fs.mkdir(pluginsDir, { recursive: true });

  const denylist = await loadJsonSafe(CONFIG.denylistPath, { blockedRepos: [], blockedShas: [] });
  const blockedRepos = new Set((denylist.blockedRepos || []).map((b) => b.id.toLowerCase()));
  const blockedShas = new Set(
    (denylist.blockedShas || []).map((b) => `${b.id.toLowerCase()}@${b.sha.toLowerCase()}`)
  );

  const prevIndex = await loadJsonSafe(indexPath, { plugins: [] });
  const prevMap = new Map((prevIndex.plugins || []).map((p) => [p.id.toLowerCase(), p]));

  const clientReleasePolicy = await loadClientReleasePolicy(CONFIG.clientReleasePath);
  const marketplaceClient = await resolveClientRelease({
    policy: clientReleasePolicy,
    githubJson: gh.githubJson,
    previousClientRelease: prevIndex.marketplaceClient,
  });

  const discovered = await gh.discoverRepositories(CONFIG.targetRepo);
  console.log(`[discover] Found ${discovered.length} candidate repositories`);

  // In single-repo mode, preserve all unrelated existing plugins
  const nextPluginsMap = CONFIG.targetRepo ? new Map(prevMap) : new Map();

  for (const repo of discovered) {
    const id = repo.full_name;
    const idKey = id.toLowerCase();

    if (blockedRepos.has(idKey)) {
      console.log(`[skip] ${id} is in denylist.blockedRepos`);
      nextPluginsMap.delete(idKey);
      if (CONFIG.targetRepo) {
        await writeTargetSummary({ status: "blocked", id, reason: "Repository or target SHA is listed in denylist.json." });
      }
      continue;
    }

    try {
      const target = await gh.resolveTargetRelease(repo);

      if (blockedShas.has(`${idKey}@${target.sha.toLowerCase()}`)) {
        console.log(`[skip] ${id}@${target.sha.slice(0, 8)} is in denylist.blockedShas`);
        nextPluginsMap.delete(idKey);
        if (CONFIG.targetRepo) {
          await writeTargetSummary({ status: "blocked", id, reason: "Repository or target SHA is listed in denylist.json." });
        }
        continue;
      }

      const detailRelPath = `plugins/${id}.json`;
      const detailAbsPath = path.join(CONFIG.registryDir, ...detailRelPath.split("/"));
      const prev = prevMap.get(idKey);

      // Incremental cache hit: same SHA + same scannerVersion + detail file intact
      const isCacheHit =
        !CONFIG.forceRescan &&
        prev &&
        prev.release?.sha === target.sha &&
        prev.security?.scannerVersion === CONFIG.scannerVersion &&
        (await fileExists(detailAbsPath));

      if (isCacheHit) {
        console.log(`[cache-hit] ${id}@${target.sha.slice(0, 8)} (refreshing stats only)`);
        const cachedEntry = {
          ...prev,
          stats: {
            stars: repo.stargazers_count || 0,
            forks: repo.forks_count || 0,
            openIssues: repo.open_issues_count || 0,
            pushedAt: repo.pushed_at,
          },
        };
        nextPluginsMap.set(idKey, cachedEntry);
        if (CONFIG.targetRepo) {
          await writeTargetSummary({ status: "cached", id, indexEntry: cachedEntry });
        }
        continue;
      }

      // Cache miss: download, extract, hash, validate, and scan inside isolated temp dir
      console.log(`[scan] ${id}@${target.sha.slice(0, 8)} (${target.ref})`);
      const tarballUrl = `${gh.apiBase}/repos/${id}/tarball/${target.sha}`;
      const sandboxDir = await fs.mkdtemp(path.join(os.tmpdir(), "agy-crawl-"));

      try {
        const { archiveBytes } = await downloadAndExtractTarball(tarballUrl, sandboxDir, {
          githubFetchFn: gh.githubFetch,
          maxArchiveBytes: CONFIG.maxArchiveBytes,
          maxUncompressedBytes: CONFIG.maxUncompressedBytes,
          maxFiles: CONFIG.maxFiles,
        });
        const { contentTreeSha256, files } = await computeContentTreeSha256(sandboxDir);
        const parsed = await validateAndParsePlugin(sandboxDir, files, repo, {
          topics: CONFIG.topics,
          maxReadmeBytes: CONFIG.maxReadmeBytes,
        });

        if (!parsed.valid) {
          console.log(`[reject] ${id}: ${parsed.reason}`);
          nextPluginsMap.delete(idKey);
          if (CONFIG.targetRepo) {
            await writeTargetSummary({ status: "rejected", id, reason: parsed.reason });
          }
          continue;
        }

        const security = await runSecurityScan({
          sandboxDir,
          files,
          parsed,
          repoFullName: id,
          sha: target.sha,
        });

        // Preserve rolling version/capability history for update permission-diff UI
        const prevDetail = await loadJsonSafe(detailAbsPath, { history: [] });
        const historyEntry = {
          version: parsed.manifest.version,
          sha: target.sha,
          scannedAt: security.scannedAt,
          riskTier: security.riskTier,
          capabilities: security.capabilities,
        };
        const history = [
          historyEntry,
          ...(prevDetail.history || []).filter((h) => h.sha !== target.sha),
        ].slice(0, CONFIG.maxHistoryEntries);

        const rawSummary =
          typeof parsed.manifest.description === "string" && parsed.manifest.description.trim()
            ? parsed.manifest.description
            : typeof repo.description === "string"
              ? repo.description
              : "";
        const rawMinApp = parsed.manifest.minAppVersion;
        const minAppVersion =
          typeof rawMinApp === "string" && rawMinApp.length > 0
            ? rawMinApp
            : parsed.surface.hasSidebarUi
              ? "2.34.0"
              : null;

        const iconUrl = buildPinnedIconUrl(id, target.sha, parsed.iconPath);

        const indexEntry = {
          id,
          name: parsed.displayName,
          pluginName: parsed.pluginName,
          summary: rawSummary.slice(0, 240),
          ...(iconUrl ? { iconUrl } : {}),
          author: {
            login: repo.owner.login,
            avatarUrl: repo.owner.avatar_url,
            url: repo.owner.html_url,
          },
          repoUrl: repo.html_url,
          license: repo.license?.spdx_id || "UNKNOWN",
          version: parsed.manifest.version,
          minAppVersion,
          release: {
            ref: target.ref,
            sha: target.sha,
            tarballUrl,
            contentTreeSha256,
            archiveBytes,
            publishedAt: target.publishedAt,
          },
          surface: parsed.surface,
          categories: parsed.categories,
          tags: parsed.tags,
          requiresCredentials:
            parsed.credentials.envVars.some((e) => e.required) ||
            parsed.credentials.oauthProviders.length > 0,
          stats: {
            stars: repo.stargazers_count || 0,
            forks: repo.forks_count || 0,
            openIssues: repo.open_issues_count || 0,
            pushedAt: repo.pushed_at,
          },
          security: {
            riskTier: security.riskTier,
            scannerVersion: security.scannerVersion,
            scannedAt: security.scannedAt,
            capabilities: security.capabilities,
            findingCounts: security.findingCounts,
          },
          detailPath: detailRelPath,
        };

        const detailDoc = {
          schemaVersion: CONFIG.schemaVersion,
          id,
          sha: target.sha,
          scannerVersion: security.scannerVersion,
          scannedAt: security.scannedAt,
          manifest: {
            manifestPath: parsed.manifestPath,
            name: parsed.pluginName,
            displayName: parsed.displayName,
            version: parsed.manifest.version,
            minAppVersion: indexEntry.minAppVersion,
            mcpServers: parsed.mcpServers,
            hooks: parsed.hooks.commandHooks,
            skills: parsed.skills,
            agents: parsed.agents,
          },
          collisions: parsed.collisions,
          credentials: parsed.credentials,
          readmeMarkdown: parsed.readmeMarkdown,
          latestReleaseNotes: target.releaseNotes,
          securityReport: {
            riskTier: security.riskTier,
            capabilities: security.capabilities,
            findings: security.findings,
          },
          history,
        };

        await fs.mkdir(path.dirname(detailAbsPath), { recursive: true });
        await fs.writeFile(detailAbsPath, JSON.stringify(detailDoc, null, 2) + "\n", "utf8");
        nextPluginsMap.set(idKey, indexEntry);

        if (CONFIG.targetRepo) {
          await writeTargetSummary({ status: "indexed", id, indexEntry, findings: security.findings });
        }
      } finally {
        await fs.rm(sandboxDir, { recursive: true, force: true });
      }
    } catch (err) {
      console.error(`[error] Skipping ${id}: ${err.message}`);
      if (CONFIG.targetRepo) {
        await writeTargetSummary({ status: "error", id, reason: err.message });
      }
    }
  }

  // Sort deterministically by ID so registry-data commits produce clean diffs
  const plugins = [...nextPluginsMap.values()].sort((a, b) =>
    a.id.toLowerCase() < b.id.toLowerCase() ? -1 : a.id.toLowerCase() > b.id.toLowerCase() ? 1 : 0
  );

  const nextIndex = {
    schemaVersion: CONFIG.schemaVersion,
    generatedAt: new Date().toISOString(),
    crawlerVersion: CONFIG.crawlerVersion,
    scannerVersion: CONFIG.scannerVersion,
    totalPlugins: plugins.length,
    marketplaceClient,
    plugins,
  };

  await fs.writeFile(indexPath, JSON.stringify(nextIndex, null, 2) + "\n", "utf8");

  await pruneStaleDetails(pluginsDir, new Set(nextPluginsMap.keys()));

  console.log(`[done] Published ${plugins.length} valid plugins to ${indexPath}`);
}

export {
  computeContentTreeSha256,
  resolveInsideSandbox,
  runSecurityScan,
  stripTopLevelDir,
  validateAndParsePlugin,
};

const isDirectRun =
  process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isDirectRun) {
  main().catch((err) => {
    console.error("[fatal]", err);
    process.exitCode = 1;
  });
}
