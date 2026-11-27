import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  createGitHubClient,
  DEFAULT_DISCOVERY_TOPICS,
} from "../scripts/lib/github-client.mjs";

function makeJsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("scripts/lib/github-client.mjs — multi-topic discovery & release resolution", () => {
  it("searches both agy-plugin and antigravity-plugin topics by default and deduplicates repos", async () => {
    const requestedUrls = [];
    const mockFetch = async (url) => {
      requestedUrls.push(String(url));
      const parsedUrl = new URL(url);
      const q = parsedUrl.searchParams.get("q") || "";
      if (q.includes("topic:agy-plugin")) {
        return makeJsonResponse({
          total_count: 2,
          items: [
            { full_name: "alice/plugin-one", pushed_at: "2026-11-20T00:00:00Z" },
            { full_name: "bob/shared-plugin", pushed_at: "2026-11-21T00:00:00Z" },
          ],
        });
      }
      if (q.includes("topic:antigravity-plugin")) {
        return makeJsonResponse({
          total_count: 2,
          items: [
            { full_name: "Bob/shared-plugin", pushed_at: "2026-11-21T00:00:00Z" },
            { full_name: "carol/plugin-two", pushed_at: "2026-11-22T00:00:00Z" },
          ],
        });
      }
      throw new Error(`Unexpected query: ${url}`);
    };

    assert.deepEqual(DEFAULT_DISCOVERY_TOPICS, ["agy-plugin", "antigravity-plugin"]);

    const client = createGitHubClient({
      userAgent: "agy-plugin-registry-test/1.0.0",
      fetchImpl: mockFetch,
      searchDelayMs: 0,
    });

    const repos = await client.discoverRepositories();
    assert.equal(requestedUrls.length, 2);
    assert.equal(repos.length, 3);
    assert.deepEqual(
      repos.map((r) => r.full_name),
      ["alice/plugin-one", "Bob/shared-plugin", "carol/plugin-two"]
    );
  });

  it("rejects empty or invalid topics configuration fail-fast", () => {
    assert.throws(
      () => createGitHubClient({ userAgent: "test/1.0", topics: [] }),
      /at least one non-empty discovery topic/i
    );
    assert.throws(
      () => createGitHubClient({ userAgent: "test/1.0", topics: "agy-plugin" }),
      /topics to be an array/i
    );
  });

  it("preserves release-first resolution with default-branch fallback when no release exists", async () => {
    const releaseSha = "1".repeat(40);
    const headSha = "2".repeat(40);

    const client = createGitHubClient({
      userAgent: "agy-plugin-registry-test/1.0.0",
      searchDelayMs: 0,
      fetchImpl: async (url) => {
        const pathname = new URL(url).pathname;
        if (pathname === "/repos/dev/with-release/releases/latest") {
          return makeJsonResponse({
            tag_name: "v1.2.0",
            draft: false,
            prerelease: false,
            published_at: "2026-11-10T00:00:00Z",
            body: "Release notes",
          });
        }
        if (pathname === "/repos/dev/with-release/commits/v1.2.0") {
          return makeJsonResponse({ sha: releaseSha, commit: { committer: { date: "2026-11-10T00:00:00Z" } } });
        }
        if (pathname === "/repos/dev/no-release/releases/latest") {
          return makeJsonResponse({ message: "Not Found" }, 404);
        }
        if (pathname === "/repos/dev/no-release/commits/main") {
          return makeJsonResponse({ sha: headSha, commit: { committer: { date: "2026-11-25T00:00:00Z" } } });
        }
        throw new Error(`Unexpected request: ${pathname}`);
      },
    });

    const releasedTarget = await client.resolveTargetRelease({
      full_name: "dev/with-release",
      default_branch: "main",
      pushed_at: "2026-11-26T00:00:00Z",
    });
    assert.equal(releasedTarget.ref, "v1.2.0");
    assert.equal(releasedTarget.sha, releaseSha);
    assert.equal(releasedTarget.releaseNotes, "Release notes");

    const headTarget = await client.resolveTargetRelease({
      full_name: "dev/no-release",
      default_branch: "main",
      pushed_at: "2026-11-26T00:00:00Z",
    });
    assert.equal(headTarget.ref, "main");
    assert.equal(headTarget.sha, headSha);
    assert.equal(headTarget.releaseNotes, "");
  });
});
