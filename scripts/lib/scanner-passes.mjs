import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const DEFAULT_SEMGREP_RULES = path.resolve(__dirname, "../../scanner/semgrep-rules.yml");

export function makeBlobUrl(repoFullName, sha, file, line = 1) {
  const safeLine = Number.isInteger(line) && line >= 1 ? line : 1;
  return `https://github.com/${repoFullName}/blob/${sha}/${file}#L${safeLine}`;
}

export function lineNumberAtIndex(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

export function findNeedleLine(text, needle) {
  if (!text || !needle) return 1;
  const idx = text.indexOf(needle);
  return idx === -1 ? 1 : lineNumberAtIndex(text, idx);
}

export function cleanSnippet(raw, maxLen = 180) {
  return String(raw || "")
    .replace(/\r?\n/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maxLen);
}

export const PIPE_TO_SHELL_RE =
  /(?:\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash)\b|\b(?:iex|Invoke-Expression)\b[^\n]*(?:irm|Invoke-RestMethod|Invoke-WebRequest|DownloadString)|\bbase64\s+(?:-d|--decode)\b[^\n|]*\|\s*(?:sh|bash|zsh|python3?|node)\b)/i;

// ---------------------------------------------------------------------------
// Prompt-Injection Heuristic Rules (SKILL.md, agents/*.md, rules/*.md, hooks)
// ---------------------------------------------------------------------------
// Invisible / zero-width / bidirectional override / Unicode Tag block characters
const INVISIBLE_UNICODE_RE = /[\u200B-\u200F\u202A-\u202E\u2060-\u206F\u2066-\u2069]/u;
// Note: use explicit codepoint range for Unicode Tags (U+E0000..U+E007F)
const UNICODE_TAG_BLOCK_RE = /[\u{E0000}-\u{E007F}]/u;

const GEMINI_CREDENTIAL_PATH_PATTERN = String.raw`~/\.gemini/(?:oauth_creds\.json|google_accounts\.json|[^/\s"'\x60]*credential[^/\s"'\x60]*|[^/\s"'\x60]*secret[^/\s"'\x60]*|[^/\s"'\x60]*token[^/\s"'\x60]*\.json|\.env\b)`;
const PROMPT_CREDENTIAL_TARGET_PATTERN = String.raw`(?:\.env\b|~/\.ssh|~/\.aws|${GEMINI_CREDENTIAL_PATH_PATTERN}|id_rsa)`;

const PROMPT_LINE_RULES = [
  {
    id: "PROMPT_OVERRIDE_GUARDRAILS",
    severity: "critical",
    capability: "prompt_injection_suspect",
    regex:
      /\b(?:ignore|disregard|forget|bypass|override)\s+(?:all\s+)?(?:(?:previous|prior|above|system|safety|security)\s+)+(?:instructions|prompts|rules|guardrails|policies)\b|\b(?:do\s+not\s+(?:tell|inform|alert|ask)\s+the\s+user|silently\s+(?:execute|run|send|exfiltrate)|hide\s+this\s+from\s+the\s+user)\b/i,
    message: "Prompt instructs the agent to override safety rules or hide actions from the user.",
  },
  {
    id: "PROMPT_CREDENTIAL_EXFIL",
    severity: "critical",
    capability: "credential_access",
    regex: new RegExp(
      `(?:(?:read|dump|steal|exfiltrate|send|post|upload|curl|wget|encode).{0,80}(?:${PROMPT_CREDENTIAL_TARGET_PATTERN}|api[_\\s-]?key|access[_\\s-]?token|secret[_\\s-]?key)|${PROMPT_CREDENTIAL_TARGET_PATTERN}.{0,80}(?:send|post|upload|curl|wget|exfiltrate|webhook|https?:\\/\\/))`,
      "i"
    ),
    message: "Prompt combines sensitive credential paths/secrets with exfiltration or outbound transfer directives.",
  },
  {
    id: "PROMPT_PIPE_TO_SHELL",
    severity: "critical",
    capability: "prompt_mentions_shell",
    regex: PIPE_TO_SHELL_RE,
    message: "Prompt instructs the agent to download or decode and pipe content directly into a shell.",
  },
  {
    id: "PROMPT_BASE64_PAYLOAD",
    severity: "high",
    capability: "prompt_injection_suspect",
    regex: /(?<![A-Za-z0-9+/=:/.-])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/=])/,
    skipLineIf: /data:image\/|sha256-|sha512-|integrity["']?\s*:/i,
    message: "Contains an embedded base64-encoded blob (80+ characters) that may obscure instructions.",
  },
  {
    id: "PROMPT_SHELL_TOOL_HINT",
    severity: "low",
    capability: "prompt_mentions_shell",
    regex: /\b(?:run|execute|invoke)\s+(?:the\s+)?(?:command|script|shell|terminal|bash|pwsh|powershell)\b|`(?:\.\/|\.\.\/|bash\s|sh\s|pwsh\s|powershell\s|npm\s+run\s|python3?\s)/i,
    message: "Prompt guides the agent to execute local shell commands or scripts.",
  },
];

const HTML_COMMENT_RE = /<!--([\s\S]*?)-->/g;
const SUSPICIOUS_COMMENT_DIRECTIVE_RE =
  /\b(?:ignore|override|system\s+prompt|always\s+run|never\s+tell|silently|secret|token|credential|curl|wget|bash|powershell|exfiltrate|execute)\b/i;

export function scanPromptText({ text, file, repoFullName, sha, capabilities, findings }) {
  if (
    typeof text !== "string" ||
    typeof file !== "string" ||
    !file ||
    typeof repoFullName !== "string" ||
    !repoFullName ||
    typeof sha !== "string" ||
    !sha ||
    !(capabilities instanceof Set) ||
    !Array.isArray(findings)
  ) {
    throw new TypeError(
      "scanPromptText requires string text, non-empty file/repoFullName/sha, Set capabilities, and Array findings."
    );
  }

  // 1. Check invisible Unicode / bidi spoofing / Unicode Tag steganography per line
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const lineNum = i + 1;
    const rawLine = lines[i];
    // Strip legitimate UTF-8 BOM on line 1 only before checking mid-file invisible characters
    const checkLine = lineNum === 1 ? rawLine.replace(/^\uFEFF/, "") : rawLine;

    if (
      INVISIBLE_UNICODE_RE.test(checkLine) ||
      UNICODE_TAG_BLOCK_RE.test(checkLine) ||
      (lineNum > 1 && checkLine.includes("\uFEFF"))
    ) {
      capabilities.add("prompt_injection_suspect");
      findings.push({
        id: "PROMPT_HIDDEN_UNICODE",
        severity: "critical",
        layer: "prompt",
        capability: "prompt_injection_suspect",
        message: "Contains invisible zero-width, bidi-override, or Unicode Tag characters often used to smuggle hidden prompts.",
        file,
        line: lineNum,
        snippet: cleanSnippet(checkLine.replace(/[^\x20-\x7E]/gu, (ch) => `\\u{${ch.codePointAt(0).toString(16)}}`)),
        githubBlobUrl: makeBlobUrl(repoFullName, sha, file, lineNum),
      });
    }

    // 2. Line-by-line heuristic rules
    for (const rule of PROMPT_LINE_RULES) {
      if (rule.skipLineIf && rule.skipLineIf.test(rawLine)) continue;
      if (rule.regex.test(rawLine)) {
        capabilities.add(rule.capability);
        findings.push({
          id: rule.id,
          severity: rule.severity,
          layer: "prompt",
          capability: rule.capability,
          message: rule.message,
          file,
          line: lineNum,
          snippet: cleanSnippet(rawLine),
          githubBlobUrl: makeBlobUrl(repoFullName, sha, file, lineNum),
        });
      }
    }
  }

  // 3. Multi-line HTML comment directives hidden from rendered Markdown
  for (const match of text.matchAll(HTML_COMMENT_RE)) {
    const inner = match[1] || "";
    if (SUSPICIOUS_COMMENT_DIRECTIVE_RE.test(inner)) {
      const lineNum = lineNumberAtIndex(text, match.index ?? 0);
      capabilities.add("prompt_injection_suspect");
      findings.push({
        id: "PROMPT_HTML_COMMENT_DIRECTIVE",
        severity: "high",
        layer: "prompt",
        capability: "prompt_injection_suspect",
        message: "Hidden HTML comment contains imperative or security-sensitive instructions invisible in rendered Markdown.",
        file,
        line: lineNum,
        snippet: cleanSnippet(match[0]),
        githubBlobUrl: makeBlobUrl(repoFullName, sha, file, lineNum),
      });
    }
  }
}

// ---------------------------------------------------------------------------
// Minified & Obfuscated Source File Detector
// ---------------------------------------------------------------------------
const CODE_FILE_RE = /\.(?:js|mjs|cjs|ts|mts|cts|jsx|tsx|py|sh|ps1)$/i;
const OBFUSCATED_ESCAPES_RE = /(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}){12,}/;

export async function scanObfuscationAndMinification({ sandboxDir, files, repoFullName, sha, capabilities, findings }) {
  for (const file of files) {
    if (!CODE_FILE_RE.test(file) || file.startsWith("node_modules/")) continue;

    const absPath = path.join(sandboxDir, ...file.split("/"));
    let stat;
    try {
      stat = await fs.stat(absPath);
    } catch (err) {
      if (err.code === "ENOENT") continue;
      throw err;
    }
    if (!stat.isFile() || stat.size > 2 * 1024 * 1024) continue;

    const text = await fs.readFile(absPath, "utf8");
    if (!text) continue;

    const lines = text.split(/\r?\n/);
    const longLineIdx = lines.findIndex((l) => l.length > 2000);
    const avgLineLen = text.length / Math.max(1, lines.length);

    if (longLineIdx !== -1 || (text.length > 10_000 && avgLineLen > 500)) {
      const lineNum = longLineIdx !== -1 ? longLineIdx + 1 : 1;
      capabilities.add("contains_minified");
      findings.push({
        id: "CODE_MINIFIED_BLOB",
        severity: "medium",
        layer: "code",
        capability: "contains_minified",
        message: "Source file appears minified or bundled, which reduces static-analysis visibility.",
        file,
        line: lineNum,
        snippet: cleanSnippet(lines[lineNum - 1], 140),
        githubBlobUrl: makeBlobUrl(repoFullName, sha, file, lineNum),
      });
    }

    const escMatch = text.match(OBFUSCATED_ESCAPES_RE);
    if (escMatch) {
      const lineNum = lineNumberAtIndex(text, escMatch.index ?? 0);
      capabilities.add("contains_minified");
      findings.push({
        id: "CODE_OBFUSCATED_ESCAPES",
        severity: "high",
        layer: "code",
        capability: "contains_minified",
        message: "Contains dense hex/Unicode escape sequences typical of obfuscated payloads.",
        file,
        line: lineNum,
        snippet: cleanSnippet(escMatch[0], 140),
        githubBlobUrl: makeBlobUrl(repoFullName, sha, file, lineNum),
      });
    }
  }
}

// ---------------------------------------------------------------------------
// Semgrep AST Runner
// ---------------------------------------------------------------------------
const REQUIRES_LOGIN_SNIPPET_RE = /^\s*requires login\s*$/i;

async function readCachedFileLines(sandboxDir, relPosix, fileLinesCache) {
  if (fileLinesCache.has(relPosix)) {
    return fileLinesCache.get(relPosix);
  }
  const absRoot = path.resolve(sandboxDir);
  const absPath = path.resolve(absRoot, ...relPosix.split("/"));
  const relCheck = path.relative(absRoot, absPath);
  if (
    !relCheck ||
    relCheck === ".." ||
    relCheck.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relCheck)
  ) {
    fileLinesCache.set(relPosix, null);
    return null;
  }

  let lines = null;
  try {
    const text = await fs.readFile(absPath, "utf8");
    lines = text.split(/\r?\n/);
  } catch (err) {
    if (err.code === "ENOENT" || err.code === "EISDIR") {
      lines = null;
    } else {
      throw new Error(`Failed reading ${relPosix} for Semgrep snippet resolution: ${err.message}`, {
        cause: err,
      });
    }
  }
  fileLinesCache.set(relPosix, lines);
  return lines;
}

export async function resolveSemgrepSnippet({
  sandboxDir,
  relPosix,
  startLine,
  endLine = startLine,
  rawLines = "",
  fileLinesCache = new Map(),
}) {
  const safeStart = Math.max(1, Number(startLine) || 1);
  const safeEnd = Math.max(safeStart, Number(endLine) || safeStart);
  const raw = typeof rawLines === "string" ? rawLines : "";

  if (raw && !REQUIRES_LOGIN_SNIPPET_RE.test(raw)) {
    const cleaned = cleanSnippet(raw);
    if (cleaned) return cleaned;
  }

  const lines = await readCachedFileLines(sandboxDir, relPosix, fileLinesCache);
  if (lines && lines.length > 0) {
    const slice = lines.slice(safeStart - 1, safeEnd).join(" ");
    const cleaned = cleanSnippet(slice);
    if (cleaned && !REQUIRES_LOGIN_SNIPPET_RE.test(cleaned)) {
      return cleaned;
    }
  }

  return `(line ${safeStart})`;
}

export async function parseSemgrepReport({ report, sandboxDir, repoFullName, sha }) {
  if (!report || typeof report !== "object") {
    throw new TypeError("parseSemgrepReport requires a parsed Semgrep report object.");
  }
  if (!sandboxDir || !repoFullName || !sha) {
    throw new TypeError("parseSemgrepReport requires sandboxDir, repoFullName, and sha.");
  }

  const findings = [];
  const capabilities = new Set();
  const fileLinesCache = new Map();

  for (const r of report.results || []) {
    const rawId = String(r.check_id || "SEMGREP_RULE").split(".").pop();
    const meta = r.extra?.metadata || {};
    const semgrepSev = String(r.extra?.severity || "WARNING").toUpperCase();
    const severity =
      meta.agySeverity ||
      (semgrepSev === "ERROR" ? "high" : semgrepSev === "WARNING" ? "medium" : "low");
    const capability = meta.capability || "mcp_local_exec";

    const absOrRel = r.path || "";
    const relPosix = (
      path.isAbsolute(absOrRel) ? path.relative(sandboxDir, absOrRel) : absOrRel
    )
      .split(path.sep)
      .join("/");
    if (
      !relPosix ||
      relPosix === ".." ||
      relPosix.startsWith("../") ||
      relPosix.split("/").includes("..") ||
      path.isAbsolute(relPosix)
    ) {
      continue;
    }

    const line = Math.max(1, Number(r.start?.line) || 1);
    const endLine = Math.max(line, Number(r.end?.line) || line);
    const snippet = await resolveSemgrepSnippet({
      sandboxDir,
      relPosix,
      startLine: line,
      endLine,
      rawLines: r.extra?.lines,
      fileLinesCache,
    });

    capabilities.add(capability);
    findings.push({
      id: rawId,
      severity,
      layer: "code",
      capability,
      message: r.extra?.message || `Matched static analysis rule ${rawId}.`,
      file: relPosix,
      line,
      snippet,
      githubBlobUrl: makeBlobUrl(repoFullName, sha, relPosix, line),
    });
  }

  return { findings, capabilities };
}

export async function runSemgrepScan({
  sandboxDir,
  repoFullName,
  sha,
  semgrepRulesPath = DEFAULT_SEMGREP_RULES,
  allowMissingSemgrep = process.env.CI !== "true",
  execSemgrepFn = null,
}) {
  let stdout = "";
  try {
    if (execSemgrepFn) {
      stdout = await execSemgrepFn({ sandboxDir, semgrepRulesPath });
    } else {
      ({ stdout } = await execFileAsync(
        "semgrep",
        [
          "--config",
          semgrepRulesPath,
          "--json",
          "--quiet",
          "--no-git-ignore",
          "--metrics=off",
          "--timeout=15",
          "--max-target-bytes=1048576",
          "--exclude=node_modules",
          sandboxDir,
        ],
        { maxBuffer: 16 * 1024 * 1024, timeout: 90_000 }
      ));
    }
  } catch (err) {
    if (err.code === "ENOENT" && allowMissingSemgrep) {
      console.warn("[scanner] semgrep binary not installed locally; skipping AST pass.");
      return { findings: [], capabilities: new Set() };
    }
    throw new Error(`Semgrep execution failed: ${err.stderr || err.message}`);
  }

  let report;
  try {
    report = JSON.parse(stdout || "{}");
  } catch (err) {
    throw new Error(`Failed parsing Semgrep JSON output: ${err.message}`);
  }

  return parseSemgrepReport({ report, sandboxDir, repoFullName, sha });
}
