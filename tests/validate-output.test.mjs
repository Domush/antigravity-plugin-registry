import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  computeContentTreeSha256,
  runSecurityScan,
  validateAndParsePlugin,
} from "../scripts/crawl.mjs";

const execFileAsync = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VALIDATE_SCRIPT = path.resolve(__dirname, "../scripts/validate-output.mjs");

async function withTempDir(fn) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "agy-validate-test-"));
  try {
    return await fn(dir);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}

async function writeFixtureFiles(rootDir, fileMap) {
  const files = [];
  for (const [relPath, content] of Object.entries(fileMap)) {
    const abs = path.join(rootDir, ...relPath.split("/"));
    await fs.mkdir(path.dirname(abs), { recursive: true });
    const body = typeof content === "string" ? content : JSON.stringify(content, null, 2) + "\n";
    await fs.writeFile(abs, body, "utf8");
    files.push(relPath);
  }
  return files.sort();
}

function makeMockRepo(id) {
  const [owner] = id.split("/");
  return {
    full_name: id,
    description: `Mock repository for ${id}`,
    html_url: `https://github.com/${id}`,
    default_branch: "main",
    stargazers_count: 42,
    forks_count: 5,
    open_issues_count: 1,
    pushed_at: "2026-11-20T12:00:00Z",
    license: { spdx_id: "MIT" },
    topics: ["agy-plugin", "agy-cat-gamedev", "unity"],
    owner: {
      login: owner,
      avatar_url: `https://avatars.githubusercontent.com/u/1001?v=4`,
      html_url: `https://github.com/${owner}`,
    },
  };
}

async function runValidateOutput(publicDir) {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [VALIDATE_SCRIPT, publicDir], {
      env: { ...process.env, GITHUB_ACTIONS: "false" },
    });
    return { code: 0, stdout, stderr };
  } catch (err) {
    return {
      code: typeof err.code === "number" ? err.code : 1,
      stdout: err.stdout || "",
      stderr: err.stderr || "",
    };
  }
}

// ---------------------------------------------------------------------------
// End-to-End CI Gate Verification (scripts/validate-output.mjs)
// ---------------------------------------------------------------------------
describe("scripts/validate-output.mjs — end-to-end pass and fail gates", () => {
  async function buildValidPublicRegistry(publicDir) {
    const fixtureRepoDir = path.join(publicDir, "..", "mock-plugin-src");
    await fs.mkdir(fixtureRepoDir, { recursive: true });
    const files = await writeFixtureFiles(fixtureRepoDir, {
      "plugin.json": {
        name: "unity-helper",
        displayName: "Unity Helper",
        version: "1.4.0",
        description: "UITK layout assistant.",
      },
      "skills/uitk-check/SKILL.md": "---\nname: uitk-check\n---\nCheck UXML.",
      "README.md": "# Unity Helper\nReady to use.",
    });

    const repo = makeMockRepo("acme-dev/agy-unity-helper");
    const sha = "1234567890abcdef1234567890abcdef12345678";
    const { contentTreeSha256 } = await computeContentTreeSha256(fixtureRepoDir);
    const parsed = await validateAndParsePlugin(fixtureRepoDir, files, repo);
    const security = await runSecurityScan({
      sandboxDir: fixtureRepoDir,
      files,
      parsed,
      repoFullName: repo.full_name,
      sha,
      skipSemgrep: true,
    });

    const detailRelPath = `plugins/${repo.full_name}.json`;
    const now = "2026-11-26T23:00:00Z";

    const denylist = {
      schemaVersion: 1,
      updatedAt: now,
      blockedRepos: [
        {
          id: "bad-actor/malware-plugin",
          reason: "Exfiltrates credentials.",
          severity: "critical",
          blockedAt: now,
        },
      ],
      blockedShas: [],
    };

    const indexDoc = {
      schemaVersion: 1,
      generatedAt: now,
      crawlerVersion: "1.0.0",
      scannerVersion: security.scannerVersion,
      totalPlugins: 1,
      marketplaceClient: {
        latestVersion: "1.1.0",
        minSupportedVersion: "1.0.0",
        releaseUrl: "https://github.com/acme-dev/agy-community-marketplace/releases/latest",
      },
      plugins: [
        {
          id: repo.full_name,
          name: parsed.displayName,
          pluginName: parsed.pluginName,
          summary: parsed.manifest.description,
          author: {
            login: repo.owner.login,
            avatarUrl: repo.owner.avatar_url,
            url: repo.owner.html_url,
          },
          repoUrl: repo.html_url,
          license: "MIT",
          version: parsed.manifest.version,
          minAppVersion: null,
          release: {
            ref: "v1.4.0",
            sha,
            tarballUrl: `https://api.github.com/repos/${repo.full_name}/tarball/${sha}`,
            contentTreeSha256,
            archiveBytes: 2048,
            publishedAt: now,
          },
          surface: parsed.surface,
          categories: parsed.categories,
          tags: parsed.tags,
          requiresCredentials: false,
          stats: {
            stars: repo.stargazers_count,
            forks: repo.forks_count,
            openIssues: repo.open_issues_count,
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
        },
      ],
    };

    const detailDoc = {
      schemaVersion: 1,
      id: repo.full_name,
      sha,
      scannerVersion: security.scannerVersion,
      scannedAt: security.scannedAt,
      manifest: {
        manifestPath: parsed.manifestPath,
        name: parsed.pluginName,
        displayName: parsed.displayName,
        version: parsed.manifest.version,
        minAppVersion: null,
        mcpServers: parsed.mcpServers,
        hooks: parsed.hooks.commandHooks,
        skills: parsed.skills,
        agents: parsed.agents,
      },
      collisions: parsed.collisions,
      credentials: parsed.credentials,
      readmeMarkdown: parsed.readmeMarkdown,
      latestReleaseNotes: "Initial release.",
      securityReport: {
        riskTier: security.riskTier,
        capabilities: security.capabilities,
        findings: security.findings,
      },
      history: [
        {
          version: parsed.manifest.version,
          sha,
          scannedAt: security.scannedAt,
          riskTier: security.riskTier,
          capabilities: security.capabilities,
        },
      ],
    };

    await writeFixtureFiles(publicDir, {
      "denylist.json": denylist,
      "index.json": indexDoc,
      [detailRelPath]: detailDoc,
    });

    return { indexDoc, detailDoc, detailRelPath };
  }

  it("exits 0 on a valid generated registry (including optional HTTPS iconUrl)", async () => {
    await withTempDir(async (tmp) => {
      const publicDir = path.join(tmp, "public");
      const { indexDoc } = await buildValidPublicRegistry(publicDir);

      // Verify optional HTTPS iconUrl passes validation
      indexDoc.plugins[0].iconUrl = `https://raw.githubusercontent.com/${indexDoc.plugins[0].id}/${indexDoc.plugins[0].release.sha}/icon.svg`;
      await fs.writeFile(path.join(publicDir, "index.json"), JSON.stringify(indexDoc, null, 2));

      const res = await runValidateOutput(publicDir);
      assert.equal(res.code, 0, `Expected pass, got stderr:\n${res.stderr}`);
      assert.match(res.stdout, /PASSED: 1 plugin\(s\)/);
    });
  });

  it("rejects insecure, unpinned, off-origin, empty, query/fragment, traversal, and non-image iconUrl values", async () => {
    await withTempDir(async (tmp) => {
      const publicDir = path.join(tmp, "public");
      const { indexDoc } = await buildValidPublicRegistry(publicDir);
      const { id } = indexDoc.plugins[0];
      const { sha } = indexDoc.plugins[0].release;

      const badIconUrls = [
        ["http://raw.githubusercontent.com/" + `${id}/${sha}/icon.svg`, /iconUrl must pin exact repo and commit SHA/],
        ["https://evil.example/pixel.png", /iconUrl must pin exact repo and commit SHA/],
        [`https://raw.githubusercontent.com/${id}/main/icon.svg`, /iconUrl must pin exact repo and commit SHA/],
        [`https://raw.githubusercontent.com/${id}/${sha}/`, /iconUrl contains empty path or disallowed characters/],
        [`https://raw.githubusercontent.com/${id}/${sha}/icon.svg?t=1`, /iconUrl contains empty path or disallowed characters/],
        [`https://raw.githubusercontent.com/${id}/${sha}/icon.svg#frag`, /iconUrl contains empty path or disallowed characters/],
        [`https://raw.githubusercontent.com/${id}/${sha}/../secret.png`, /iconUrl contains invalid path segment/],
        [`https://raw.githubusercontent.com/${id}/${sha}/%2e%2e/secret.png`, /iconUrl contains unsafe decoded path segment/],
        [`https://raw.githubusercontent.com/${id}/${sha}/README.md`, /iconUrl must target a supported image/],
      ];

      for (const [badUrl, expectedErr] of badIconUrls) {
        indexDoc.plugins[0].iconUrl = badUrl;
        await fs.writeFile(path.join(publicDir, "index.json"), JSON.stringify(indexDoc, null, 2));

        const res = await runValidateOutput(publicDir);
        assert.equal(res.code, 1, `Expected failure for iconUrl: ${badUrl}`);
        assert.match(res.stderr, expectedErr, `Unexpected error for iconUrl ${badUrl}:\n${res.stderr}`);
      }
    });
  });

  it("blocks deployment when a denylisted repo, mutable tarball URL, secret leak, parity drift, or orphan file appears", async () => {
    await withTempDir(async (tmp) => {
      const publicDir = path.join(tmp, "public");
      const { indexDoc, detailDoc, detailRelPath } = await buildValidPublicRegistry(publicDir);

      indexDoc.plugins[0].release.tarballUrl =
        "https://api.github.com/repos/acme-dev/agy-unity-helper/tarball/main";

      const denylistPath = path.join(publicDir, "denylist.json");
      const denylist = JSON.parse(await fs.readFile(denylistPath, "utf8"));
      denylist.blockedRepos.push({
        id: "acme-dev/agy-unity-helper",
        reason: "Simulated emergency revocation",
        severity: "critical",
        blockedAt: "2026-11-26T23:05:00Z",
      });
      await fs.writeFile(denylistPath, JSON.stringify(denylist, null, 2));

      detailDoc.securityReport.riskTier = "high";
      detailDoc.manifest.mcpServers.push({
        name: "leaked",
        transport: "stdio",
        env: { SECRET_KEY: "sk-live-oops" },
      });

      await writeFixtureFiles(publicDir, {
        "index.json": indexDoc,
        [detailRelPath]: detailDoc,
        "plugins/ghost/orphan.json": { orphan: true },
      });

      const res = await runValidateOutput(publicDir);
      assert.equal(res.code, 1, "Expected validate-output.mjs to fail with exit code 1");
      assert.match(res.stderr, /Denylisted repository .* leaked into index\.json/);
      assert.match(res.stderr, /Tarball URL must pin exact commit SHA/);
      assert.match(res.stderr, /Secret-leak violation/);
      assert.match(res.stderr, /Mismatch with index\.json security\.riskTier/);
      assert.match(res.stderr, /Orphaned plugin detail file/);
    });
  });
});
