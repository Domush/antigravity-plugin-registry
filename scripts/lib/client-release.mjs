import { REPO_ID_RE, SEMVER_RE } from "./validators.mjs";

const SEMVER_TAG_RE = /^[vV]?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/;
const GENERIC_HEADINGS = new Set(["what's changed", "changelog", "release notes", "changes"]);

class ClientReleaseResolutionError extends Error {}

function isValidHttpsUrl(url) {
  if (typeof url !== "string" || !url.startsWith("https://")) return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" && Boolean(parsed.hostname);
  } catch {
    return false;
  }
}

export function parseSemver(raw) {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  const match = trimmed.match(SEMVER_TAG_RE);
  if (!match) return null;
  const [major, minor, patch] = [Number(match[1]), Number(match[2]), Number(match[3])];
  const prerelease = match[4] ? match[4].split(".") : [];
  const build = match[5] || "";
  const version = `${major}.${minor}.${patch}${match[4] ? `-${match[4]}` : ""}${build ? `+${build}` : ""}`;
  return { major, minor, patch, prerelease, build, version, raw: trimmed };
}

function toParsedSemver(value) {
  if (value && typeof value === "object" && Number.isInteger(value.major) && Array.isArray(value.prerelease)) {
    return value;
  }
  const parsed = parseSemver(value);
  if (!parsed) throw new TypeError(`Invalid semver value: ${String(value)}`);
  return parsed;
}

export function compareSemver(a, b) {
  const va = toParsedSemver(a);
  const vb = toParsedSemver(b);
  if (va.major !== vb.major) return va.major < vb.major ? -1 : 1;
  if (va.minor !== vb.minor) return va.minor < vb.minor ? -1 : 1;
  if (va.patch !== vb.patch) return va.patch < vb.patch ? -1 : 1;

  const [pa, pb] = [va.prerelease, vb.prerelease];
  if (pa.length === 0 && pb.length === 0) return 0;
  if (pa.length === 0) return 1;
  if (pb.length === 0) return -1;

  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    if (i >= pa.length) return -1;
    if (i >= pb.length) return 1;
    if (pa[i] === pb[i]) continue;
    const [numA, numB] = [/^\d+$/.test(pa[i]), /^\d+$/.test(pb[i])];
    if (numA && numB) return Number(pa[i]) < Number(pb[i]) ? -1 : 1;
    if (numA !== numB) return numA ? -1 : 1;
    return pa[i] < pb[i] ? -1 : 1;
  }
  return 0;
}

function cleanInlineMarkdown(line) {
  let out = line.replace(/!\[([^\]]*)\]\([^)]+\)/g, "$1").replace(/\[([^\]]+)\]\([^)]+\)/g, "$1").replace(/`([^`]+)`/g, "$1");
  for (let i = 0; i < 2; i++) out = out.replace(/(\*\*|__|~~|\*|_)(.+?)\1/g, "$2");
  return out.replace(/\s+/g, " ").trim();
}

function extractChangelogSection(markdown, targetVersion) {
  const parsed = parseSemver(targetVersion);
  const cleanVer = (parsed ? parsed.version : String(targetVersion || "").replace(/^[vV]/, "")).trim();
  if (!cleanVer) return "";
  const escaped = cleanVer.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const versionMatchRe = new RegExp(`(?:^|[^0-9A-Za-z.])v?${escaped}(?=$|[^0-9A-Za-z.-])`, "i");

  let sectionLevel = 0;
  const collected = [];
  for (const line of markdown.split(/\r?\n/)) {
    const heading = line.match(/^(#{1,6})\s+(.+)$/);
    if (heading) {
      const level = heading[1].length;
      if (sectionLevel > 0) {
        if (level <= sectionLevel) break;
        collected.push(line);
      } else if (versionMatchRe.test(heading[2])) {
        sectionLevel = level;
      }
      continue;
    }
    if (sectionLevel > 0) collected.push(line);
  }
  return collected.join("\n").trim();
}

export function extractReleaseSummary(rawText, { version = "", maxLength = 240, fallback = "" } = {}) {
  if (typeof rawText !== "string" || !rawText.trim()) return fallback;
  const limit = Number.isInteger(maxLength) && maxLength > 0 ? maxLength : 240;
  const source = version ? extractChangelogSection(rawText, version) : rawText;
  if (!source) return fallback;

  const stripped = source.replace(/<!--[\s\S]*?-->/g, " ").replace(/```[\s\S]*?```/g, " ");
  const bodyLines = [];
  const headingLines = [];

  for (const rawLine of stripped.split(/\r?\n/)) {
    const trimmed = rawLine.trim();
    if (!trimmed || /^[-*_]{3,}$/.test(trimmed) || /^(?:\*\*|__)?Full Changelog(?:\*\*|__)?:/i.test(trimmed)) continue;
    const headingMatch = trimmed.match(/^#{1,6}\s+(.+)$/);
    if (headingMatch) {
      const cleanedHeading = cleanInlineMarkdown(headingMatch[1]);
      if (cleanedHeading && !GENERIC_HEADINGS.has(cleanedHeading.toLowerCase())) headingLines.push(cleanedHeading);
      continue;
    }
    const cleaned = cleanInlineMarkdown(trimmed.replace(/^>\s?/, "").replace(/^(?:[-*+]|\d+\.)\s+/, ""));
    if (cleaned) bodyLines.push(cleaned);
  }

  let text = bodyLines.join(" ").trim();
  if (!text && !version && headingLines.length > 0) text = headingLines.join(" ").trim();
  if (!text) return fallback;
  if (text.length <= limit) return text;
  if (limit <= 3) return text.slice(0, limit);

  let truncated = text.slice(0, limit - 3).trimEnd();
  const wordBoundary = truncated.replace(/\s+\S*$/, "");
  if (wordBoundary.length >= Math.floor(limit * 0.5)) truncated = wordBoundary;
  return `${truncated}...`;
}

function validatePolicy(policy) {
  if (!policy || typeof policy !== "object" || Array.isArray(policy)) {
    throw new Error("Invalid client-release policy: expected a JSON object");
  }
  if (typeof policy.repo !== "string" || !REPO_ID_RE.test(policy.repo.trim())) {
    throw new Error(`Invalid client-release policy: repo must be in OWNER/REPO format, got "${policy.repo}"`);
  }
  let minSupportedVersion = null;
  if (policy.minSupportedVersion !== undefined && policy.minSupportedVersion !== null) {
    const parsedMin = parseSemver(policy.minSupportedVersion);
    if (!parsedMin) {
      throw new Error(`Invalid client-release policy: minSupportedVersion must be valid semver, got "${policy.minSupportedVersion}"`);
    }
    minSupportedVersion = parsedMin.version;
  }
  let releaseUrl = null;
  if (policy.releaseUrl !== undefined && policy.releaseUrl !== null) {
    if (!isValidHttpsUrl(policy.releaseUrl)) {
      throw new Error(`Invalid client-release policy: releaseUrl must be an HTTPS URL, got "${policy.releaseUrl}"`);
    }
    releaseUrl = policy.releaseUrl;
  }
  return { repo: policy.repo.trim(), minSupportedVersion, releaseUrl };
}

function isValidClientRelease(candidate) {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return false;
  if (typeof candidate.latestVersion !== "string" || !SEMVER_RE.test(candidate.latestVersion)) return false;
  if (!isValidHttpsUrl(candidate.releaseUrl)) return false;
  if (candidate.minSupportedVersion !== undefined && candidate.minSupportedVersion !== null) {
    return typeof candidate.minSupportedVersion === "string" && SEMVER_RE.test(candidate.minSupportedVersion);
  }
  return true;
}

function decodeGitHubContent(fileDoc, label) {
  if (!fileDoc || typeof fileDoc !== "object" || typeof fileDoc.content !== "string") return null;
  if (fileDoc.encoding && fileDoc.encoding !== "base64") {
    throw new ClientReleaseResolutionError(`Unsupported content encoding "${fileDoc.encoding}" for ${label}`);
  }
  return Buffer.from(fileDoc.content, "base64").toString("utf8");
}

function formatClientRelease(latestVersion, minSupportedVersion, releaseUrl, notes) {
  return { latestVersion, ...(minSupportedVersion ? { minSupportedVersion } : {}), releaseUrl, notes };
}

export async function resolveClientRelease({ policy, githubJson, previousClientRelease = null }) {
  const { repo, minSupportedVersion, releaseUrl: policyReleaseUrl } = validatePolicy(policy);
  if (typeof githubJson !== "function") {
    throw new Error("Invalid arguments: githubJson function is required");
  }

  try {
    const latestRelease = await githubJson(`/repos/${repo}/releases/latest`);
    if (latestRelease && !latestRelease.draft && !latestRelease.prerelease) {
      const parsedTag = parseSemver(latestRelease.tag_name);
      if (parsedTag) {
        const releaseUrl = isValidHttpsUrl(latestRelease.html_url)
          ? latestRelease.html_url
          : policyReleaseUrl || `https://github.com/${repo}/releases/tag/${encodeURIComponent(latestRelease.tag_name)}`;
        const notes = extractReleaseSummary(latestRelease.body || "", { fallback: `Release ${latestRelease.tag_name}` });
        return formatClientRelease(parsedTag.version, minSupportedVersion, releaseUrl, notes);
      }
    }

    const tags = await githubJson(`/repos/${repo}/tags?per_page=100`);
    if (Array.isArray(tags) && tags.length > 0) {
      const parsedTags = tags
        .map((tag) => ({ tagName: tag?.name, semver: parseSemver(tag?.name) }))
        .filter((entry) => typeof entry.tagName === "string" && entry.semver !== null);
      const stableTags = parsedTags.filter((entry) => entry.semver.prerelease.length === 0);
      const candidateTags = stableTags.length > 0 ? stableTags : parsedTags;

      if (candidateTags.length > 0) {
        candidateTags.sort((a, b) => compareSemver(b.semver, a.semver));
        const best = candidateTags[0];
        let notes = `Release ${best.tagName}`;
        const changelogDoc = await githubJson(`/repos/${repo}/contents/CHANGELOG.md?ref=${encodeURIComponent(best.tagName)}`);
        const changelogRaw = decodeGitHubContent(changelogDoc, "CHANGELOG.md");
        if (changelogRaw) {
          notes = extractReleaseSummary(changelogRaw, { version: best.tagName, fallback: notes });
        }
        return formatClientRelease(
          best.semver.version,
          minSupportedVersion,
          `https://github.com/${repo}/releases/tag/${encodeURIComponent(best.tagName)}`,
          notes
        );
      }
    }

    const pluginRaw = decodeGitHubContent(await githubJson(`/repos/${repo}/contents/plugin.json`), "plugin.json");
    if (pluginRaw !== null) {
      let manifest;
      try {
        manifest = JSON.parse(pluginRaw);
      } catch (err) {
        throw new ClientReleaseResolutionError(`Invalid JSON in ${repo}/plugin.json: ${err.message}`);
      }
      const parsedPluginVer = parseSemver(manifest?.version);
      if (parsedPluginVer) {
        const notes = extractReleaseSummary(typeof manifest.description === "string" ? manifest.description : "", {
          fallback: `Release ${parsedPluginVer.version}`,
        });
        return formatClientRelease(parsedPluginVer.version, minSupportedVersion, `https://github.com/${repo}`, notes);
      }
    }

    throw new ClientReleaseResolutionError(`Unable to resolve client release for ${repo}: no valid semver release, tag, or plugin.json found`);
  } catch (err) {
    if (!(err instanceof ClientReleaseResolutionError) && isValidClientRelease(previousClientRelease)) {
      console.warn(`[client-release] GitHub API error resolving ${repo} (${err.message}); preserving previous version ${previousClientRelease.latestVersion}`);
      return previousClientRelease;
    }
    if (err instanceof ClientReleaseResolutionError) throw err;
    throw new Error(`Failed to resolve client release for ${repo}: ${err.message}`, { cause: err });
  }
}
