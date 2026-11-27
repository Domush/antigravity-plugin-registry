/**
 * Zero-dependency, XSS-safe Markdown renderer for the Antigravity Portal.
 * Escapes all raw HTML before inline formatting and validates every URL scheme.
 */

const BLOCK_START_RE =
  /^ {0,3}(?:#{1,6}\s+\S|(?:```|~~~)|(?:-\s*){3,}$|(?:\*\s*){3,}$|(?:_\s*){3,}$|>\s?|[-*+]\s+\S|\d+[.)]\s+\S)/;
const HR_RE = /^ {0,3}(?:(?:-\s*){3,}|(?:\*\s*){3,}|(?:_\s*){3,})$/;
const FENCE_OPEN_RE = /^ {0,3}(`{3,}|~{3,})(.*)$/;
const HEADING_RE = /^ {0,3}(#{1,6})\s+(\S.*)$/;
const UL_ITEM_RE = /^ {0,3}[-*+]\s+(.*)$/;
const OL_ITEM_RE = /^ {0,3}\d+[.)]\s+(.*)$/;
const BQ_LINE_RE = /^ {0,3}>\s?(.*)$/;
const BQ_LEADING_RE = /^(?: {0,3}>\s?)+/;
const MAX_BLOCKQUOTE_DEPTH = 32;
const AUTO_URL_RE = /(https?:\/\/(?:[^\s&\0]|&amp;)+)/g;

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
  let openParens = 0;
  let closeParens = 0;
  for (let i = 0; i < raw.length; i += 1) {
    if (raw[i] === "(") openParens += 1;
    else if (raw[i] === ")") closeParens += 1;
  }

  let end = raw.length;
  while (end > 0) {
    const ch = raw[end - 1];
    if (!/[.,;:!?)]/.test(ch)) break;
    if (ch === ")") {
      if (closeParens <= openParens) break;
      closeParens -= 1;
    }
    end -= 1;
  }

  return { url: raw.slice(0, end), suffix: raw.slice(end) };
}

/** Map each '(' index to its matching ')' index in O(N) time; unmatched '(' stay -1. */
function buildParenMap(text) {
  const map = new Int32Array(text.length).fill(-1);
  const stack = [];
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (ch === "(") {
      stack.push(i);
    } else if (ch === ")" && stack.length > 0) {
      map[stack.pop()] = i;
    }
  }
  return map;
}

function replaceLinkedBadges(text, onMatch) {
  if (!text.includes("[![") || !text.includes("(")) return text;
  const parenMap = buildParenMap(text);
  const parts = [];
  let cursor = 0;
  let i = 0;

  while (i < text.length) {
    const start = text.indexOf("[![", i);
    if (start === -1) break;
    const altEnd = text.indexOf("]", start + 3);
    if (altEnd === -1) break;

    if (text[altEnd + 1] === "(") {
      const imgClose = parenMap[altEnd + 1];
      if (imgClose !== -1 && text[imgClose + 1] === "]" && text[imgClose + 2] === "(") {
        const hrefClose = parenMap[imgClose + 2];
        if (hrefClose !== -1) {
          const alt = text.slice(start + 3, altEnd);
          const hrefDest = text.slice(imgClose + 3, hrefClose);
          parts.push(text.slice(cursor, start), onMatch(alt, hrefDest));
          cursor = hrefClose + 1;
          i = cursor;
          continue;
        }
      }
    }
    i = altEnd + 1;
  }

  if (cursor === 0) return text;
  parts.push(text.slice(cursor));
  return parts.join("");
}

function scanBracketLinks(text, prefix, minLabelLen, onMatch) {
  if (!text.includes(prefix) || !text.includes("(")) return text;
  const parenMap = buildParenMap(text);
  const parts = [];
  let cursor = 0;
  let i = 0;

  while (i < text.length) {
    const start = text.indexOf(prefix, i);
    if (start === -1) break;
    const labelStart = start + prefix.length;
    const closeBracket = text.indexOf("]", labelStart);
    if (closeBracket === -1) break;

    if (closeBracket - labelStart >= minLabelLen && text[closeBracket + 1] === "(") {
      const destClose = parenMap[closeBracket + 1];
      if (destClose !== -1) {
        const label = text.slice(labelStart, closeBracket);
        const dest = text.slice(closeBracket + 2, destClose);
        parts.push(text.slice(cursor, start), onMatch(label, dest));
        cursor = destClose + 1;
        i = cursor;
        continue;
      }
    }
    i = closeBracket + 1;
  }

  if (cursor === 0) return text;
  parts.push(text.slice(cursor));
  return parts.join("");
}

/** Replace inline backtick code spans in strictly O(N) time without regex backtracking. */
function replaceInlineCode(rawLine, onMatch) {
  if (!rawLine.includes("`")) return rawLine;

  const runs = [];
  const runsByLen = new Map();
  let i = 0;
  while (i < rawLine.length) {
    const start = rawLine.indexOf("`", i);
    if (start === -1) break;
    let end = start + 1;
    while (end < rawLine.length && rawLine[end] === "`") end += 1;
    const len = end - start;
    const runIdx = runs.length;
    runs.push({ start, end, len });
    let list = runsByLen.get(len);
    if (!list) {
      list = [];
      runsByLen.set(len, list);
    }
    list.push(runIdx);
    i = end;
  }

  if (runs.length < 2) return rawLine;

  const cursorByLen = new Map();
  const parts = [];
  let charCursor = 0;
  let rIdx = 0;

  while (rIdx < runs.length) {
    const openRun = runs[rIdx];
    const indices = runsByLen.get(openRun.len);
    let listPos = cursorByLen.get(openRun.len) ?? 0;
    while (listPos < indices.length && indices[listPos] <= rIdx) {
      listPos += 1;
    }
    cursorByLen.set(openRun.len, listPos);

    if (listPos < indices.length) {
      const closeIdx = indices[listPos];
      const closeRun = runs[closeIdx];
      parts.push(rawLine.slice(charCursor, openRun.start), onMatch(rawLine.slice(openRun.end, closeRun.start)));
      charCursor = closeRun.end;
      cursorByLen.set(openRun.len, listPos + 1);
      rIdx = closeIdx + 1;
      continue;
    }
    rIdx += 1;
  }

  if (charCursor === 0) return rawLine;
  parts.push(rawLine.slice(charCursor));
  return parts.join("");
}

function renderInline(rawLine, opts) {
  const codeTokens = [];
  const linkTokens = [];
  const linkPlainTexts = [];

  // 1. Protect inline code spans before escaping or formatting
  let text = replaceInlineCode(rawLine, (inner) => {
    codeTokens.push(`<code>${escapeHtml(inner)}</code>`);
    return `\0C${codeTokens.length - 1}\0`;
  });

  // 2. Escape all remaining raw HTML before links, auto-links, and emphasis
  text = escapeHtml(text);

  const stashLink = (safeUrl, labelHtml, fallbackHtml, plainText = fallbackHtml) => {
    if (!safeUrl) return fallbackHtml;
    linkTokens.push(renderSafeLink(safeUrl, labelHtml, opts.linkMode));
    linkPlainTexts.push(plainText);
    return `\0T${linkTokens.length - 1}\0`;
  };
  const unwrapLinkTokens = (label) =>
    label.replace(/\0T(\d+)\0/g, (_, idx) => linkPlainTexts[Number(idx)] ?? "");

  // 3. Linked badges, standalone images, standard links, and bare http(s) auto-links
  text = replaceLinkedBadges(text, (alt, hrefDest) => {
    const safeUrl = resolveSafeUrl(decodeEscapedHref(hrefDest), opts);
    return stashLink(safeUrl, alt || "Badge", alt || "", alt || "Badge");
  });
  text = scanBracketLinks(text, "![", 0, (alt, srcDest) => {
    const unwrappedAlt = unwrapLinkTokens(alt);
    const safeUrl = resolveSafeUrl(decodeEscapedHref(srcDest), opts);
    return stashLink(safeUrl, unwrappedAlt || "Image", unwrappedAlt || "", unwrappedAlt);
  });
  text = scanBracketLinks(text, "[", 1, (label, hrefDest) => {
    const safeUrl = resolveSafeUrl(decodeEscapedHref(hrefDest), opts);
    const unwrappedLabel = unwrapLinkTokens(label);
    const formatted = applyEmphasis(unwrappedLabel);
    return stashLink(safeUrl, formatted, formatted, unwrappedLabel);
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

function renderMarkdownBlocks(markdown, opts, depth) {
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
      const rawHeading = headingMatch[2];
      let end = rawHeading.length;
      while (end > 1 && rawHeading[end - 1] === "#") end -= 1;
      while (end > 1 && /\s/.test(rawHeading[end - 1])) end -= 1;
      out.push(`<h${level}>${renderInline(rawHeading.slice(0, end), opts)}</h${level}>`);
      i += 1;
      continue;
    }

    const collectBlock = (re) => {
      const items = [];
      while (i < lines.length && re.test(lines[i])) items.push(lines[i++].replace(re, "$1"));
      return items;
    };

    if (depth <= MAX_BLOCKQUOTE_DEPTH && BQ_LINE_RE.test(line)) {
      const innerLines = collectBlock(BQ_LINE_RE);
      const nextLines =
        depth >= MAX_BLOCKQUOTE_DEPTH
          ? innerLines.map((item) => item.replace(BQ_LEADING_RE, ""))
          : innerLines;
      out.push(`<blockquote>${renderMarkdownBlocks(nextLines.join("\n"), opts, depth + 1)}</blockquote>`);
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

/** Render untrusted Markdown to sanitized HTML. */
export function renderMarkdown(markdown, { linkMode = "anchor", repoUrl = "", sha = "" } = {}) {
  if (linkMode !== "anchor" && linkMode !== "button") {
    throw new TypeError(`Invalid linkMode "${linkMode}"; expected "anchor" or "button".`);
  }
  if (markdown === null || markdown === undefined || markdown === "") return "";
  if (typeof markdown !== "string") {
    throw new TypeError("renderMarkdown requires markdown to be a string, null, or undefined.");
  }

  return renderMarkdownBlocks(markdown, { linkMode, repoUrl, sha }, 0);
}
