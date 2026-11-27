import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { validateAndParsePlugin } from "../scripts/crawl.mjs";
import {
  buildPinnedIconUrl,
  resolveIconRelPath,
  sanitizeRelativeIconPath,
} from "../scripts/lib/icon-resolver.mjs";

const TEST_SHA = "1234567890abcdef1234567890abcdef12345678";

async function withTempDir(fn) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "agy-icon-test-"));
  try {
    return await fn(dir);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}

describe("icon-resolver — safe relative icon path resolution and SHA-pinned URLs", () => {
  it("resolves manifest.icon relative paths across supported image extensions", () => {
    const cases = [
      [{ icon: "./assets/brand/mark.svg" }, ["assets/brand/mark.svg", "icon.png"], "assets/brand/mark.svg"],
      [{ icon: "images/plugin.png" }, ["images/plugin.png"], "images/plugin.png"],
      [{ icon: "media/badge.webp" }, ["media/badge.webp"], "media/badge.webp"],
      [{ icon: "media/photo.jpg" }, ["media/photo.jpg"], "media/photo.jpg"],
      [{ icon: "icon.svg" }, [".antigravity-plugin/icon.svg"], ".antigravity-plugin/icon.svg", ".antigravity-plugin/plugin.json"],
    ];

    for (const [manifest, files, expected, manifestPath = "plugin.json"] of cases) {
      assert.equal(resolveIconRelPath(manifest, files, manifestPath), expected);
    }
  });

  it("falls back to standard icon/logo candidates in deterministic priority order", () => {
    assert.equal(
      resolveIconRelPath({}, [
        "assets/icon.png",
        "logo.svg",
        "icon.svg",
        ".antigravity-plugin/icon.png",
        ".antigravity-plugin/icon.svg",
      ]),
      ".antigravity-plugin/icon.svg"
    );
    assert.equal(
      resolveIconRelPath({}, ["assets/icon.png", "icon.svg", ".antigravity-plugin/icon.png"]),
      ".antigravity-plugin/icon.png"
    );
    assert.equal(
      resolveIconRelPath({}, ["assets/icon.png", "logo.svg", "icon.png", "icon.svg"]),
      "icon.svg"
    );
    assert.equal(resolveIconRelPath({}, ["assets/icon.png", "logo.png", "icon.png"]), "icon.png");
    assert.equal(resolveIconRelPath({}, ["assets/icon.svg", "logo.svg"]), "logo.svg");
    assert.equal(resolveIconRelPath({}, ["assets/icon.png", "logo.png"]), "logo.png");
    assert.equal(resolveIconRelPath({}, ["assets/icon.png", "assets/icon.svg"]), "assets/icon.svg");
    assert.equal(resolveIconRelPath({}, ["assets/icon.png"]), "assets/icon.png");
    assert.equal(resolveIconRelPath({}, ["plugin.json", "skills/a/SKILL.md"]), null);
  });

  it("rejects traversal, absolute, external URL, query/hash, NUL, empty segments, and non-image icon paths", () => {
    const unsafeInputs = [
      null,
      undefined,
      "",
      "   ",
      123,
      "../icon.png",
      "assets/../../secret.png",
      "/etc/icon.png",
      "\\\\server\\share\\icon.png",
      "C:\\icon.png",
      "https://evil.example/icon.png",
      "http://evil.example/icon.png",
      "data:image/svg+xml,<svg/>",
      "icon\0.png",
      "a//b.png",
      "a/./b.png",
      "icon.png?cachebust=1",
      "icon.svg#frag",
      "icon.js",
      "icon.html",
    ];

    for (const bad of unsafeInputs) {
      assert.equal(sanitizeRelativeIconPath(bad), null, `Expected unsafe icon path rejected: ${String(bad)}`);
      if (typeof bad === "string" && bad.trim().length > 0) {
        assert.equal(
          resolveIconRelPath({ icon: bad }, ["icon.png", "assets/icon.svg"]),
          null,
          `Expected resolveIconRelPath to return null for unsafe manifest.icon: ${bad}`
        );
      }
    }
  });

  it("throws TypeError on invalid entry arguments to resolveIconRelPath and buildPinnedIconUrl", () => {
    for (const nonArray of [null, undefined, "icon.png", {}]) {
      assert.throws(
        () => resolveIconRelPath({}, nonArray),
        { name: "TypeError", message: /requires a files array/ }
      );
    }

    assert.equal(buildPinnedIconUrl("acme-dev/agy-tool", TEST_SHA, null), null);
    assert.equal(buildPinnedIconUrl("acme-dev/agy-tool", TEST_SHA, undefined), null);

    assert.throws(
      () => buildPinnedIconUrl("", TEST_SHA, "icon.png"),
      { name: "TypeError", message: /requires non-empty repoFullName and sha/ }
    );
    assert.throws(
      () => buildPinnedIconUrl(null, TEST_SHA, "icon.png"),
      { name: "TypeError", message: /requires non-empty repoFullName and sha/ }
    );
    assert.throws(
      () => buildPinnedIconUrl("acme-dev/agy-tool", "", "icon.png"),
      { name: "TypeError", message: /requires non-empty repoFullName and sha/ }
    );
    assert.throws(
      () => buildPinnedIconUrl("acme-dev/agy-tool", TEST_SHA, 123),
      { name: "TypeError", message: /requires iconPath to be a string/ }
    );
    for (const badIcon of ["", "../evil.png", "https://evil.example/a.png", "icon.js", "icon.png?v=1"]) {
      assert.throws(
        () => buildPinnedIconUrl("acme-dev/agy-tool", TEST_SHA, badIcon),
        { name: "TypeError", message: /Invalid or unsafe plugin iconPath/ }
      );
    }
  });

  it("builds commit-SHA-pinned raw.githubusercontent.com iconUrl", () => {
    assert.equal(
      buildPinnedIconUrl("acme-dev/agy-tool", TEST_SHA, "assets/icon.svg"),
      `https://raw.githubusercontent.com/acme-dev/agy-tool/${TEST_SHA}/assets/icon.svg`
    );
    assert.equal(buildPinnedIconUrl("acme-dev/agy-tool", TEST_SHA, null), null);
  });

  it("integrates with validateAndParsePlugin to surface iconPath when present", async () => {
    await withTempDir(async (dir) => {
      const filesMap = {
        "plugin.json": JSON.stringify({
          name: "icon-plugin",
          version: "1.0.0",
          icon: "branding/logo.webp",
        }),
        "branding/logo.webp": "RIFF....WEBP",
        "skills/demo/SKILL.md": "---\nname: demo\n---\nHello.",
      };
      for (const [rel, body] of Object.entries(filesMap)) {
        const abs = path.join(dir, ...rel.split("/"));
        await fs.mkdir(path.dirname(abs), { recursive: true });
        await fs.writeFile(abs, body, "utf8");
      }

      const parsed = await validateAndParsePlugin(dir, Object.keys(filesMap).sort(), {
        full_name: "acme/icon-plugin",
        topics: ["agy-plugin"],
      });

      assert.equal(parsed.valid, true);
      assert.equal(parsed.iconPath, "branding/logo.webp");
      assert.equal(
        buildPinnedIconUrl("acme/icon-plugin", TEST_SHA, parsed.iconPath),
        `https://raw.githubusercontent.com/acme/icon-plugin/${TEST_SHA}/branding/logo.webp`
      );
    });
  });

  it("discovers .antigravity-plugin/icon.svg automatically when manifest.icon is omitted", async () => {
    await withTempDir(async (dir) => {
      const filesMap = {
        ".antigravity-plugin/plugin.json": JSON.stringify({
          name: "nested-icon-plugin",
          version: "1.0.0",
        }),
        ".antigravity-plugin/icon.svg": "<svg xmlns=\"http://www.w3.org/2000/svg\"/>",
        "icon.svg": "<svg/>",
        "skills/demo/SKILL.md": "---\nname: demo\n---\nHello.",
      };
      for (const [rel, body] of Object.entries(filesMap)) {
        const abs = path.join(dir, ...rel.split("/"));
        await fs.mkdir(path.dirname(abs), { recursive: true });
        await fs.writeFile(abs, body, "utf8");
      }

      const parsed = await validateAndParsePlugin(dir, Object.keys(filesMap).sort(), {
        full_name: "acme/nested-icon-plugin",
        topics: ["agy-plugin"],
      });

      assert.equal(parsed.valid, true);
      assert.equal(parsed.iconPath, ".antigravity-plugin/icon.svg");
      assert.equal(
        buildPinnedIconUrl("acme/nested-icon-plugin", TEST_SHA, parsed.iconPath),
        `https://raw.githubusercontent.com/acme/nested-icon-plugin/${TEST_SHA}/.antigravity-plugin/icon.svg`
      );
    });
  });
});
