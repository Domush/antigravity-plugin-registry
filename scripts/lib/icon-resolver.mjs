const ICON_EXTENSIONS_RE = /\.(?:svg|png|webp|jpe?g)$/i;

const DEFAULT_ICON_CANDIDATES = [
  ".antigravity-plugin/icon.svg",
  ".antigravity-plugin/icon.png",
  "icon.svg",
  "icon.png",
  "logo.svg",
  "logo.png",
  "assets/icon.svg",
  "assets/icon.png",
];

/**
 * Validate and normalize a relative icon path from manifest.icon.
 * Rejects external URLs, absolute paths, query/fragment strings, and path traversal.
 */
export function sanitizeRelativeIconPath(rawPath) {
  if (typeof rawPath !== "string") return null;
  const trimmed = rawPath.trim();
  if (!trimmed) return null;

  if (/[\0?#]/.test(trimmed)) return null;
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed)) return null;
  if (trimmed.startsWith("/") || trimmed.startsWith("\\")) return null;

  const normalized = trimmed.replace(/\\/g, "/").replace(/^(?:\.\/)+/, "");
  if (!normalized) return null;

  const segments = normalized.split("/");
  if (segments.some((seg) => seg === "" || seg === "." || seg === "..")) {
    return null;
  }

  if (!ICON_EXTENSIONS_RE.test(normalized)) return null;
  return normalized;
}

/**
 * Resolve an optional plugin icon file path present inside the extracted archive.
 * Prefers a safe relative `manifest.icon` path, then standard icon/logo candidates.
 */
export function resolveIconRelPath(manifest, files, manifestPath = "") {
  if (!Array.isArray(files)) {
    throw new TypeError("resolveIconRelPath requires a files array.");
  }

  const exactFiles = new Set();
  const lowerToExact = new Map();
  for (const file of files) {
    if (typeof file !== "string" || !file) continue;
    exactFiles.add(file);
    const lower = file.toLowerCase();
    if (!lowerToExact.has(lower)) {
      lowerToExact.set(lower, file);
    }
  }

  const findInFiles = (relPath) => {
    if (exactFiles.has(relPath)) return relPath;
    return lowerToExact.get(relPath.toLowerCase()) || null;
  };

  if (manifest && typeof manifest.icon === "string" && manifest.icon.trim().length > 0) {
    const safeRel = sanitizeRelativeIconPath(manifest.icon);
    if (!safeRel) return null;

    const directHit = findInFiles(safeRel);
    if (directHit) return directHit;

    if (typeof manifestPath === "string" && manifestPath.startsWith(".antigravity-plugin/")) {
      const nestedHit = findInFiles(`.antigravity-plugin/${safeRel}`);
      if (nestedHit) return nestedHit;
    }
  }

  for (const candidate of DEFAULT_ICON_CANDIDATES) {
    const hit = findInFiles(candidate);
    if (hit) return hit;
  }

  return null;
}

/**
 * Validate a commit-SHA-pinned raw GitHub icon URL emitted into index.json.
 * Returns null if valid, or a descriptive error message if invalid.
 */
export function validatePinnedIconUrl(iconUrl, repoFullName, sha) {
  if (typeof iconUrl !== "string") {
    return `Expected HTTPS raw.githubusercontent.com URL string, got "${iconUrl}"`;
  }
  if (!repoFullName || !sha) {
    return "Cannot verify iconUrl pinning without valid plugin id and release.sha";
  }
  const expectedPrefix = `https://raw.githubusercontent.com/${repoFullName}/${sha}/`;
  if (!iconUrl.startsWith(expectedPrefix)) {
    return `iconUrl must pin exact repo and commit SHA ("${expectedPrefix}..."), got "${iconUrl}"`;
  }
  const rawRel = iconUrl.slice(expectedPrefix.length);
  if (!rawRel || /[\0?#\\]/.test(rawRel)) {
    return `iconUrl contains empty path or disallowed characters (?, #, \\, NUL): "${iconUrl}"`;
  }
  const rawSegments = rawRel.split("/");
  const decodedSegments = [];
  for (const seg of rawSegments) {
    if (!seg || seg === "." || seg === "..") {
      return `iconUrl contains invalid path segment in "${iconUrl}"`;
    }
    let decoded;
    try {
      decoded = decodeURIComponent(seg);
    } catch {
      return `iconUrl contains malformed percent-encoding in "${iconUrl}"`;
    }
    if (!decoded || decoded === "." || decoded === ".." || /[/\\\0]/.test(decoded)) {
      return `iconUrl contains unsafe decoded path segment in "${iconUrl}"`;
    }
    decodedSegments.push(decoded);
  }
  if (!ICON_EXTENSIONS_RE.test(decodedSegments.join("/"))) {
    return `iconUrl must target a supported image (.svg, .png, .webp, .jpg, .jpeg), got "${iconUrl}"`;
  }
  return null;
}

/**
 * Build a commit-SHA-pinned raw GitHub URL for a resolved plugin icon path.
 */
export function buildPinnedIconUrl(repoFullName, sha, iconPath) {
  if (iconPath === null || iconPath === undefined) return null;
  if (typeof iconPath !== "string") {
    throw new TypeError("buildPinnedIconUrl requires iconPath to be a string, null, or undefined.");
  }
  if (typeof repoFullName !== "string" || !repoFullName || typeof sha !== "string" || !sha) {
    throw new TypeError("buildPinnedIconUrl requires non-empty repoFullName and sha.");
  }
  const safePath = sanitizeRelativeIconPath(iconPath);
  if (!safePath) {
    throw new TypeError(`Invalid or unsafe plugin iconPath: "${iconPath}"`);
  }
  const encodedPath = safePath.split("/").map(encodeURIComponent).join("/");
  return `https://raw.githubusercontent.com/${repoFullName}/${sha}/${encodedPath}`;
}
