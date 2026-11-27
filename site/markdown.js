/**
 * Zero-dependency, XSS-safe Markdown renderer for the Antigravity Portal.
 * Escapes all raw HTML before inline formatting and validates every URL scheme.
 */

const BLOCK_START_RE =
  /^ {0,3}(?:#{1,6}\s+\S|(?:```|~~~)|(?:-\s*){3,}$|(?:\*\s*){3,}$|(?:_\s*){3,}$|>\s?|[-*+]\s+\S|\d+[.)]\s+\S)/;
const HR_RE = /^ {0,3}(?:(?:-\s*){3,}|(?:\*\s*){3,}|(?:_\s*){3,})$/;
const FENCE_OPEN_RE = /^ {0,3}(`{3,}|~{3,})(.*)$/;
const HEADING_RE = /^ {0,3}(#{1,6})\s+(\S.*?)\s*#*$/;
const UL_ITEM_RE = /^ {0,3}[-*+]\s+(.*)$/;
const OL_ITEM_RE = /^ {0,3}\d+[.)]\s+(.*)$/;
const BQ_LINE_RE = /^ {0,3}>\s?(.*)$/;
const DEST_PART = String.raw`((?:[^()\n]|\([^()\n]*\))+)`;
const LINKED_BADGE_RE = new RegExp(`\\[!\\[([^\\]]*)\\]\\(${DEST_PART}\\)\\]\\(${DEST_PART}\\)`, "g");
const IMAGE_RE = new RegExp(`!\\[([^\\]]*)\\]\\(${DEST_PART}\\)`, "g");
const LINK_RE = new RegExp(`\\[([^\\]]+)\\]\\(${DEST_PART}\\)`, "g");
const AUTO_URL_RE = /(https?:\/\/(?:[^\s&]|&amp;)+)/g;

/** Escape HTML metacharacters to prevent injection. */
export function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/**
 * Validate a Markdown URL, allowing only http:/https: or relative repo paths
 * pinned to `${repoUrl}/blob/${sha}/` on https://github.com.
 */
export function resolveSafeUrl(rawUrl, { repoUrl = "", sha = "" } = {}) {
  if (typeof rawUrl !== "string") return null;
  const trimmed = rawUrl.trim();
  if (!trimmed || /[\u0000-\u001f\u007f]/.test(trimmed)) return null;
  if (trimmed.startsWith("//") || trimmed.startsWith("\\")) return null;

  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed)) {
    try {
      const parsed = new URL(trimmed);
      return parsed.protocol === "https:" || parsed.protocol === "http:" ? parsed.href : null;
    } catch {
      return null;
    }
  }

  if (trimmed.startsWith("/") || trimmed.startsWith("#")) return null;
  if (typeof repoUrl !== "string" || !repoUrl.startsWith("https://github.com/") || !sha) {
    return null;
  }

  try {
    const base = `${repoUrl.replace(/\/+$/, "")}/blob/${encodeURIComponent(sha)}/`;
    const resolved = new URL(trimmed, base);
    if (resolved.origin !== "https://github.com") return null;
    return resolved.pathname.startsWith(new URL(base).pathname) ? resolved.href : null;
  } catch {
    return null;
  }
}

function decodeEscapedHref(escapedDest) {
  const trimmed = escapedDest.trim();
  const withTitle = trimmed.match(/^(\S+)\s+(?:&quot;[\s\S]*&quot;|&#39;[\s\S]*&#39;)$/);
  const raw = withTitle ? withTitle[1] : trimmed;
  return /&(?:lt|gt|quot|#39);/.test(raw) ? null : raw.replaceAll("&amp;", "&");
}

function renderSafeLink(safeUrl, labelHtml, linkMode) {
  const hrefEsc = escapeHtml(safeUrl);
  return linkMode === "button"
    ? `<button type="button" class="md-link" data-external-url="${hrefEsc}">${labelHtml}</button>`
    : `<a href="${hrefEsc}" target="_blank" rel="noopener noreferrer">${labelHtml}</a>`;
}

function applyEmphasis(text) {
  return text
    .replace(/\*\*([^\n*]+?)\*\*/g, "<strong>$1</strong>")
    .replace(/__([^\n_]+?)__/g, "<strong>$1</strong>")
    .replace(/~~([^\n~]+?)~~/g, "<del>$1</del>")
    .replace(/(?<!\*)\*([^*\n]+?)\*(?!\*)/g, "<em>$1</em>")
    .replace(/(?<![A-Za-z0-9_])_([^_\n]+?)_(?![A-Za-z0-9_])/g, "<em>$1</em>");
}

function stripTrailingPunctuation(raw) {
  let url = raw;
  let suffix = "";
  while (url.length > 0 && /[.,;:!?)]/.test(url[url.length - 1])) {
    const ch = url[url.length - 1];
    if (ch === ")" && (url.match(/\)/g) || []).length <= (url.match(/\(/g) || []).length) break;
    suffix = ch + suffix;
    url = url.slice(0, -1);
  }
  return { url, suffix };
}

function renderInline(rawLine, opts) {
  const codeTokens = [];
  const linkTokens = [];

  // 1. Protect inline code spans before escaping or formatting
  let text = rawLine.replace(/(`+)([\s\S]+?)\1/g, (_, _t, inner) => {
    codeTokens.push(`<code>${escapeHtml(inner)}</code>`);
    return `\0C${codeTokens.length - 1}\0`;
  });

  // 2. Escape all remaining raw HTML before links, auto-links, and emphasis
  text = escapeHtml(text);

  const stashLink = (safeUrl, labelHtml, fallbackHtml) => {
    if (!safeUrl) return fallbackHtml;
    linkTokens.push(renderSafeLink(safeUrl, labelHtml, opts.linkMode));
    return `\0T${linkTokens.length - 1}\0`;
  };

  // 3. Linked badges, standalone images, standard links, and bare http(s) auto-links
  text = text.replace(LINKED_BADGE_RE, (_, alt, _img, hrefDest) => {
    const safeUrl = resolveSafeUrl(decodeEscapedHref(hrefDest), opts);
    return stashLink(safeUrl, alt || "Badge", alt || "");
  });
  text = text.replace(IMAGE_RE, (_, alt, srcDest) => {
    const safeUrl = resolveSafeUrl(decodeEscapedHref(srcDest), opts);
    return stashLink(safeUrl, alt || "Image", alt || "");
  });
  text = text.replace(LINK_RE, (_, label, hrefDest) => {
    const safeUrl = resolveSafeUrl(decodeEscapedHref(hrefDest), opts);
    const formatted = applyEmphasis(label);
    return stashLink(safeUrl, formatted, formatted);
  });
  text = text.replace(AUTO_URL_RE, (match) => {
    const { url, suffix } = stripTrailingPunctuation(match);
    const safeUrl = resolveSafeUrl(decodeEscapedHref(url), opts);
    return stashLink(safeUrl, url, url) + suffix;
  });

  // 4. Emphasis & strikethrough, then restore tokens (links first, then inline code)
  text = applyEmphasis(text);
  text = text.replace(/\0T(\d+)\0/g, (_, idx) => linkTokens[Number(idx)] ?? "");
  return text.replace(/\0C(\d+)\0/g, (_, idx) => codeTokens[Number(idx)] ?? "");
}

/** Render untrusted Markdown to sanitized HTML. */
export function renderMarkdown(markdown, { linkMode = "anchor", repoUrl = "", sha = "" } = {}) {
  if (linkMode !== "anchor" && linkMode !== "button") {
    throw new TypeError(`Invalid linkMode "${linkMode}"; expected "anchor" or "button".`);
  }
  if (markdown === null || markdown === undefined || markdown === "") return "";
  if (typeof markdown !== "string") {
    throw new TypeError("renderMarkdown requires markdown to be a string, null, or undefined.");
  }

  const opts = { linkMode, repoUrl, sha };
  const lines = markdown.replaceAll("\0", "").replace(/\r\n?/g, "\n").split("\n");
  const out = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) {
      i += 1;
      continue;
    }

    const fenceMatch = line.match(FENCE_OPEN_RE);
    if (fenceMatch) {
      const fenceChar = fenceMatch[1][0];
      const closeRe = new RegExp(`^ {0,3}${fenceChar}{${fenceMatch[1].length},}\\s*$`);
      const lang = fenceMatch[2].trim().split(/\s+/)[0] || "";
      const codeLines = [];
      i += 1;
      while (i < lines.length && !closeRe.test(lines[i])) {
        codeLines.push(lines[i++]);
      }
      if (i < lines.length) i += 1;
      const langAttr = /^[A-Za-z0-9_-]+$/.test(lang) ? ` class="language-${escapeHtml(lang)}"` : "";
      out.push(`<pre><code${langAttr}>${escapeHtml(codeLines.join("\n"))}</code></pre>`);
      continue;
    }

    if (HR_RE.test(line)) {
      out.push("<hr />");
      i += 1;
      continue;
    }

    const headingMatch = line.match(HEADING_RE);
    if (headingMatch) {
      const level = headingMatch[1].length;
      out.push(`<h${level}>${renderInline(headingMatch[2], opts)}</h${level}>`);
      i += 1;
      continue;
    }

    const collectBlock = (re) => {
      const items = [];
      while (i < lines.length && re.test(lines[i])) items.push(lines[i++].replace(re, "$1"));
      return items;
    };

    if (BQ_LINE_RE.test(line)) {
      out.push(`<blockquote>${renderMarkdown(collectBlock(BQ_LINE_RE).join("\n"), opts)}</blockquote>`);
      continue;
    }
    if (UL_ITEM_RE.test(line)) {
      out.push(`<ul>${collectBlock(UL_ITEM_RE).map((x) => `<li>${renderInline(x, opts)}</li>`).join("")}</ul>`);
      continue;
    }
    if (OL_ITEM_RE.test(line)) {
      out.push(`<ol>${collectBlock(OL_ITEM_RE).map((x) => `<li>${renderInline(x, opts)}</li>`).join("")}</ol>`);
      continue;
    }

    const paraLines = [];
    while (i < lines.length && lines[i].trim() && (paraLines.length === 0 || !BLOCK_START_RE.test(lines[i]))) {
      paraLines.push(lines[i++].trim());
    }
    out.push(`<p>${renderInline(paraLines.join(" "), opts)}</p>`);
  }

  return out.join("\n");
}
