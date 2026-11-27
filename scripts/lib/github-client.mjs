const API_BASE = "https://api.github.com";

export const DEFAULT_DISCOVERY_TOPICS = ["agy-plugin", "antigravity-plugin"];

function normalizeTopics(topics) {
  if (!Array.isArray(topics)) {
    throw new TypeError("createGitHubClient requires topics to be an array of non-empty strings.");
  }
  const normalized = [
    ...new Set(
      topics
        .filter((t) => typeof t === "string")
        .map((t) => t.trim().toLowerCase())
        .filter((t) => t.length > 0)
    ),
  ];
  if (normalized.length === 0) {
    throw new Error("createGitHubClient requires at least one non-empty discovery topic.");
  }
  return normalized;
}

/**
 * Create a rate-limit-aware GitHub REST API client.
 */
export function createGitHubClient({
  githubToken = "",
  userAgent,
  topics = DEFAULT_DISCOVERY_TOPICS,
  searchStartDate = "2024-01-01",
  fetchImpl = globalThis.fetch,
  searchDelayMs = 2200,
}) {
  const discoveryTopics = normalizeTopics(topics);
  if (typeof fetchImpl !== "function") {
    throw new TypeError("createGitHubClient requires a valid fetch implementation.");
  }
  if (typeof searchDelayMs !== "number" || !Number.isFinite(searchDelayMs) || searchDelayMs < 0) {
    throw new RangeError("createGitHubClient requires searchDelayMs to be a non-negative finite number.");
  }

  async function githubFetch(url, { accept = "application/vnd.github+json", retries = 3 } = {}) {
    const headers = {
      Accept: accept,
      "User-Agent": userAgent,
      "X-GitHub-Api-Version": "2022-11-28",
    };
    if (githubToken) {
      headers.Authorization = `Bearer ${githubToken}`;
    }

    for (let attempt = 1; attempt <= retries; attempt++) {
      const res = await fetchImpl(url, { headers, redirect: "follow" });

      if (res.status === 403 || res.status === 429) {
        const remaining = Number(res.headers.get("x-ratelimit-remaining") ?? "1");
        const retryAfter = Number(res.headers.get("retry-after") ?? "0");
        const resetEpoch = Number(res.headers.get("x-ratelimit-reset") ?? "0");

        if (attempt < retries && (remaining === 0 || retryAfter > 0 || res.status === 429)) {
          const waitMs =
            retryAfter > 0
              ? retryAfter * 1000
              : Math.max(2000, resetEpoch * 1000 - Date.now() + 1000);
          const cappedWaitMs = Math.min(waitMs, 65_000);
          console.warn(`[rate-limit] Waiting ${Math.ceil(cappedWaitMs / 1000)}s before retrying ${url}`);
          await new Promise((r) => setTimeout(r, cappedWaitMs));
          continue;
        }
      }

      return res;
    }

    throw new Error(`Exceeded retry budget for ${url}`);
  }

  async function githubJson(endpoint) {
    const url = endpoint.startsWith("http") ? endpoint : `${API_BASE}${endpoint}`;
    const res = await githubFetch(url);
    if (res.status === 404) return null;
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`GitHub API ${res.status} on ${endpoint}: ${body.slice(0, 200)}`);
    }
    return res.json();
  }

  function formatDateUTC(ms) {
    return new Date(ms).toISOString().slice(0, 10);
  }

  async function pauseForSearchRateLimit() {
    if (searchDelayMs > 0) {
      await new Promise((r) => setTimeout(r, searchDelayMs));
    }
  }

  async function searchRange(searchTopic, startDate, endDate, collected) {
    const q = encodeURIComponent(
      `topic:${searchTopic} archived:false created:${startDate}..${endDate}`
    );
    const firstPage = await githubJson(`/search/repositories?q=${q}&sort=updated&order=desc&per_page=100&page=1`);
    if (!firstPage) return;

    // Bisect date window if approaching GitHub's 1,000-result search ceiling
    const startMs = Date.parse(`${startDate}T00:00:00Z`);
    const endMs = Date.parse(`${endDate}T00:00:00Z`);
    if (firstPage.total_count > 900 && endMs - startMs > 86_400_000) {
      const midMs = Math.floor((startMs + endMs) / 2);
      const midDate = formatDateUTC(midMs);
      const nextDay = formatDateUTC(midMs + 86_400_000);
      await searchRange(searchTopic, startDate, midDate, collected);
      await searchRange(searchTopic, nextDay, endDate, collected);
      return;
    }

    for (const item of firstPage.items || []) {
      collected.set(item.full_name.toLowerCase(), item);
    }

    const totalPages = Math.min(10, Math.ceil((firstPage.total_count || 0) / 100));
    for (let page = 2; page <= totalPages; page++) {
      // Keep search API comfortably below 30 requests/minute
      await pauseForSearchRateLimit();
      const pageData = await githubJson(
        `/search/repositories?q=${q}&sort=updated&order=desc&per_page=100&page=${page}`
      );
      for (const item of pageData?.items || []) {
        collected.set(item.full_name.toLowerCase(), item);
      }
    }
  }

  async function discoverRepositories(targetRepo = "") {
    if (targetRepo) {
      const repo = await githubJson(`/repos/${targetRepo}`);
      if (!repo) throw new Error(`Target repo not found: ${targetRepo}`);
      return [repo];
    }

    const collected = new Map();
    const tomorrow = formatDateUTC(Date.now() + 86_400_000);
    for (let i = 0; i < discoveryTopics.length; i++) {
      if (i > 0) await pauseForSearchRateLimit();
      await searchRange(discoveryTopics[i], searchStartDate, tomorrow, collected);
    }
    return [...collected.values()];
  }

  async function resolveTargetRelease(repo) {
    const fullName = repo.full_name;
    const latestRelease = await githubJson(`/repos/${fullName}/releases/latest`);

    if (latestRelease && !latestRelease.draft && !latestRelease.prerelease) {
      // /commits/{tag} automatically dereferences annotated tags to the commit SHA
      const commit = await githubJson(
        `/repos/${fullName}/commits/${encodeURIComponent(latestRelease.tag_name)}`
      );
      if (commit?.sha) {
        return {
          ref: latestRelease.tag_name,
          sha: commit.sha,
          publishedAt: latestRelease.published_at || commit.commit?.committer?.date || repo.pushed_at,
          releaseNotes: (latestRelease.body || "").slice(0, 8192),
        };
      }
    }

    const defaultBranch = repo.default_branch || "main";
    const headCommit = await githubJson(
      `/repos/${fullName}/commits/${encodeURIComponent(defaultBranch)}`
    );
    if (!headCommit?.sha) {
      throw new Error(`Could not resolve HEAD commit for ${fullName}`);
    }

    return {
      ref: defaultBranch,
      sha: headCommit.sha,
      publishedAt: headCommit.commit?.committer?.date || repo.pushed_at,
      releaseNotes: "",
    };
  }

  return {
    apiBase: API_BASE,
    githubFetch,
    githubJson,
    discoverRepositories,
    resolveTargetRelease,
  };
}
