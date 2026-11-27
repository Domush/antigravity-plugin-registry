import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  compareSemver,
  extractReleaseSummary,
  parseSemver,
  resolveClientRelease,
} from "../scripts/lib/client-release.mjs";

const BASE_POLICY = {
  repo: "Domush/antigravity-community-marketplace",
  minSupportedVersion: "1.0.0",
  releaseUrl: "https://github.com/Domush/antigravity-community-marketplace/releases/latest",
};

function encodeBase64Content(text) {
  return {
    type: "file",
    encoding: "base64",
    content: Buffer.from(text, "utf8").toString("base64").replace(/(.{60})/g, "$1\n"),
  };
}

function createMockGithubJson(routes) {
  const calls = [];
  const githubJson = async (endpoint) => {
    calls.push(endpoint);
    if (!(endpoint in routes)) return null;
    const handler = routes[endpoint];
    return typeof handler === "function" ? handler(endpoint) : handler;
  };
  return { githubJson, calls };
}

describe("client-release helpers (parseSemver, compareSemver, extractReleaseSummary)", () => {
  it("parses valid semver tags with or without leading v and rejects invalid versions", () => {
    const parsed = parseSemver("v1.0.2-rc.1+build.7");
    assert.equal(parsed.major, 1);
    assert.equal(parsed.minor, 0);
    assert.equal(parsed.patch, 2);
    assert.deepEqual(parsed.prerelease, ["rc", "1"]);
    assert.equal(parsed.version, "1.0.2-rc.1+build.7");

    assert.equal(parseSemver("1.2.3")?.version, "1.2.3");
    assert.equal(parseSemver("1.2"), null);
    assert.equal(parseSemver("v1"), null);
    assert.equal(parseSemver(""), null);
    assert.equal(parseSemver(null), null);
  });

  it("compares semver versions numerically including multi-digit segments and prereleases", () => {
    assert.equal(compareSemver("v1.0.10", "v1.0.2"), 1);
    assert.equal(compareSemver("v1.0.2", "v1.0.1"), 1);
    assert.equal(compareSemver("1.0.0", "1.0.0-rc.1"), 1);
    assert.equal(compareSemver("1.0.0-beta.11", "1.0.0-beta.2"), 1);
    assert.equal(compareSemver("1.0.0-1", "1.0.0-alpha"), -1);
    assert.equal(compareSemver("v1.2.3+a", "1.2.3+b"), 0);
    assert.throws(() => compareSemver("bad", "1.0.0"), TypeError);
  });

  it("strips markdown noise, extracts changelog sections without prefix collisions, and caps length", () => {
    const body = [
      "<!-- hidden -->",
      "## What's Changed",
      "- Fixed **update** banner with `parseSemver` and [docs](https://example.com)",
      "- Added *offline* tests",
      "**Full Changelog**: https://github.com/Domush/antigravity-community-marketplace/compare/v1.0.1...v1.0.2",
    ].join("\n");
    assert.equal(
      extractReleaseSummary(body),
      "Fixed update banner with parseSemver and docs Added offline tests"
    );

    const longSummary = extractReleaseSummary("word ".repeat(80), { maxLength: 50 });
    assert.ok(longSummary.length <= 50);
    assert.ok(longSummary.endsWith("..."));

    const changelog = [
      "# Changelog",
      "## [1.0.20] - 2026-11-30",
      "- Should not match 1.0.2",
      "## [1.0.2] - 2026-11-26",
      "### Fixed",
      "- Removed false **update** prompt",
      "## [1.0.1] - 2026-11-20",
      "- Initial release",
    ].join("\n");
    assert.equal(
      extractReleaseSummary(changelog, { version: "v1.0.2", fallback: "Fallback" }),
      "Removed false update prompt"
    );
    assert.equal(
      extractReleaseSummary(changelog, { version: "9.9.9", fallback: "Release v9.9.9" }),
      "Release v9.9.9"
    );
  });
});

describe("resolveClientRelease", () => {
  it("resolves live GitHub Release v1.0.2 with summarized markdown body", async () => {
    const { githubJson, calls } = createMockGithubJson({
      "/repos/Domush/antigravity-community-marketplace/releases/latest": {
        tag_name: "v1.0.2",
        draft: false,
        prerelease: false,
        html_url: "https://github.com/Domush/antigravity-community-marketplace/releases/tag/v1.0.2",
        body: "## Highlights\n- Fixed **registry** version check\n- Improved [sidebar](https://example.com) sync",
      },
    });

    const result = await resolveClientRelease({ policy: BASE_POLICY, githubJson });
    assert.deepEqual(result, {
      latestVersion: "1.0.2",
      minSupportedVersion: "1.0.0",
      releaseUrl: "https://github.com/Domush/antigravity-community-marketplace/releases/tag/v1.0.2",
      notes: "Fixed registry version check Improved sidebar sync",
    });
    assert.deepEqual(calls, ["/repos/Domush/antigravity-community-marketplace/releases/latest"]);
  });

  it("falls back to highest numeric semver tag and extracts CHANGELOG.md section when /releases/latest is null", async () => {
    const changelog = [
      "# Changelog",
      "## [v1.0.10] - 2026-11-27",
      "- Sorted tags numerically so `1.0.10` beats `1.0.2`",
      "## [v1.0.2] - 2026-11-25",
      "- Previous patch",
    ].join("\n");

    const { githubJson } = createMockGithubJson({
      "/repos/Domush/antigravity-community-marketplace/releases/latest": null,
      "/repos/Domush/antigravity-community-marketplace/tags?per_page=100": [
        { name: "v1.0.1" },
        { name: "v1.0.2" },
        { name: "v1.0.10" },
        { name: "v2.0.0-rc.1" },
        { name: "nightly" },
      ],
      "/repos/Domush/antigravity-community-marketplace/contents/CHANGELOG.md?ref=v1.0.10":
        encodeBase64Content(changelog),
    });

    const result = await resolveClientRelease({ policy: BASE_POLICY, githubJson });
    assert.deepEqual(result, {
      latestVersion: "1.0.10",
      minSupportedVersion: "1.0.0",
      releaseUrl: "https://github.com/Domush/antigravity-community-marketplace/releases/tag/v1.0.10",
      notes: "Sorted tags numerically so 1.0.10 beats 1.0.2",
    });
  });

  it("succeeds softly with default release notes when CHANGELOG.md is 404 or lacks matching section", async () => {
    const { githubJson: missingChangelog } = createMockGithubJson({
      "/repos/Domush/antigravity-community-marketplace/releases/latest": {
        tag_name: "v1.0.2",
        draft: true,
        prerelease: false,
      },
      "/repos/Domush/antigravity-community-marketplace/tags?per_page=100": [{ name: "v1.0.2" }],
      "/repos/Domush/antigravity-community-marketplace/contents/CHANGELOG.md?ref=v1.0.2": null,
    });

    const resMissing = await resolveClientRelease({ policy: BASE_POLICY, githubJson: missingChangelog });
    assert.equal(resMissing.latestVersion, "1.0.2");
    assert.equal(resMissing.notes, "Release v1.0.2");

    const { githubJson: noSection } = createMockGithubJson({
      "/repos/Domush/antigravity-community-marketplace/releases/latest": null,
      "/repos/Domush/antigravity-community-marketplace/tags?per_page=100": [{ name: "v1.0.2" }],
      "/repos/Domush/antigravity-community-marketplace/contents/CHANGELOG.md?ref=v1.0.2":
        encodeBase64Content("# Changelog\n## [1.0.1]\n- Older"),
    });

    const resNoSection = await resolveClientRelease({ policy: BASE_POLICY, githubJson: noSection });
    assert.equal(resNoSection.latestVersion, "1.0.2");
    assert.equal(resNoSection.notes, "Release v1.0.2");
  });

  it("falls back to plugin.json when no releases or semver tags exist", async () => {
    const { githubJson } = createMockGithubJson({
      "/repos/Domush/antigravity-community-marketplace/releases/latest": null,
      "/repos/Domush/antigravity-community-marketplace/tags?per_page=100": [{ name: "latest" }],
      "/repos/Domush/antigravity-community-marketplace/contents/plugin.json": encodeBase64Content(
        JSON.stringify({
          name: "antigravity-community-marketplace",
          version: "1.0.2",
          description: "Browse and install **verified** community plugins.",
        })
      ),
    });

    const result = await resolveClientRelease({ policy: BASE_POLICY, githubJson });
    assert.deepEqual(result, {
      latestVersion: "1.0.2",
      minSupportedVersion: "1.0.0",
      releaseUrl: "https://github.com/Domush/antigravity-community-marketplace",
      notes: "Browse and install verified community plugins.",
    });
  });

  it("preserves valid previousClientRelease on transient API failure and throws when no fallback exists", async () => {
    const previousClientRelease = {
      latestVersion: "1.0.2",
      minSupportedVersion: "1.0.0",
      releaseUrl: "https://github.com/Domush/antigravity-community-marketplace/releases/tag/v1.0.2",
      notes: "Cached release",
    };

    const { githubJson: failingApi } = createMockGithubJson({
      "/repos/Domush/antigravity-community-marketplace/releases/latest": () => {
        throw new Error("GitHub API 503 on /releases/latest: Service Unavailable");
      },
    });

    const warnings = [];
    const origWarn = console.warn;
    console.warn = (...args) => warnings.push(args.join(" "));
    try {
      const preserved = await resolveClientRelease({
        policy: BASE_POLICY,
        githubJson: failingApi,
        previousClientRelease,
      });
      assert.deepEqual(preserved, previousClientRelease);
      assert.equal(warnings.length, 1);
      assert.match(warnings[0], /503/);
    } finally {
      console.warn = origWarn;
    }

    await assert.rejects(
      () => resolveClientRelease({ policy: BASE_POLICY, githubJson: failingApi }),
      /Failed to resolve client release/
    );

    const { githubJson: emptyRepo } = createMockGithubJson({});
    await assert.rejects(
      () =>
        resolveClientRelease({
          policy: BASE_POLICY,
          githubJson: emptyRepo,
          previousClientRelease,
        }),
      /no valid semver release, tag, or plugin\.json found/
    );
  });

  it("fails fast on invalid policy repo, minSupportedVersion, or releaseUrl without calling GitHub", async () => {
    const { githubJson, calls } = createMockGithubJson({});

    await assert.rejects(
      () => resolveClientRelease({ policy: null, githubJson }),
      /expected a JSON object/
    );
    await assert.rejects(
      () => resolveClientRelease({ policy: { repo: "invalid-repo" }, githubJson }),
      /OWNER\/REPO/
    );
    await assert.rejects(
      () =>
        resolveClientRelease({
          policy: { repo: BASE_POLICY.repo, minSupportedVersion: "1.0" },
          githubJson,
        }),
      /minSupportedVersion/
    );
    await assert.rejects(
      () =>
        resolveClientRelease({
          policy: { repo: BASE_POLICY.repo, releaseUrl: "http://example.com" },
          githubJson,
        }),
      /HTTPS URL/
    );
    assert.equal(calls.length, 0);
  });
});
