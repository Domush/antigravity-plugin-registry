import fs from "node:fs/promises";
import path from "node:path";
import {
  cleanSnippet,
  DEFAULT_SEMGREP_RULES,
  findNeedleLine,
  makeBlobUrl,
  PIPE_TO_SHELL_RE,
  runSemgrepScan,
  scanObfuscationAndMinification,
  scanPromptText,
} from "./lib/scanner-passes.mjs";

const MAX_FINDINGS_PER_PLUGIN = 100;
const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

async function readOptionalUtf8(filePath) {
  try {
    return await fs.readFile(filePath, "utf8");
  } catch (err) {
    if (err.code === "ENOENT") return "";
    throw err;
  }
}

// ---------------------------------------------------------------------------
// 1. Unpinned Remote Runtime Detection (npx / uvx / pnpx / bunx / pipx / deno)
// ---------------------------------------------------------------------------
const EXACT_NPM_SPEC_RE = /^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+@\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const EXACT_PY_SPEC_RE = /^[A-Za-z0-9._-]+==\d+(?:\.\d+)*(?:[a-zA-Z0-9._-]+)?$/;

const RUNNER_FLAG_WITH_VALUE = new Set([
  "-p", "--package", "--from", "--with", "--python", "--index-url", "-c", "--call",
]);

/**
 * Inspect an MCP command + args pair (or split shell command) for unpinned remote package execution.
 * Returns { packageSpec, runner } if unpinned, or null if pinned / not a remote runner.
 */
export function detectUnpinnedRuntime(command, args = []) {
  const base = path.basename(String(command || "").trim()).toLowerCase().replace(/\.(exe|cmd|bat)$/, "");
  const argList = Array.isArray(args) ? args.map(String) : [];

  let runner = base;
  let scanArgs = argList;

  if (base === "npm" && argList[0] === "exec") {
    runner = "npm exec";
    scanArgs = argList.slice(1);
  } else if (base === "uv" && argList[0] === "tool" && argList[1] === "run") {
    runner = "uv tool run";
    scanArgs = argList.slice(2);
  } else if (base === "pipx" && argList[0] === "run") {
    runner = "pipx run";
    scanArgs = argList.slice(1);
  } else if (base === "deno" && argList[0] === "run") {
    const remoteUrl = argList.find((a) => /^https?:\/\//i.test(a));
    if (remoteUrl) {
      return { runner: "deno run", packageSpec: remoteUrl };
    }
    return null;
  } else if (!["npx", "pnpx", "bunx", "uvx"].includes(base)) {
    return null;
  }

  const isPythonRunner = runner === "uvx" || runner === "uv tool run" || runner === "pipx run";
  const exactPinRe = isPythonRunner ? EXACT_PY_SPEC_RE : EXACT_NPM_SPEC_RE;

  const candidateSpecs = [];
  for (let i = 0; i < scanArgs.length; i++) {
    const tok = scanArgs[i];
    if (tok === "--") break;

    if (tok.startsWith("--package=") || tok.startsWith("--from=")) {
      candidateSpecs.push(tok.slice(tok.indexOf("=") + 1));
      continue;
    }
    if (RUNNER_FLAG_WITH_VALUE.has(tok) && i + 1 < scanArgs.length) {
      const val = scanArgs[++i];
      if (tok === "-p" || tok === "--package" || tok === "--from") {
        candidateSpecs.push(val);
      }
      continue;
    }
    if (tok.startsWith("-")) continue;

    // First positional token is the package specifier unless -p/--package/--from already declared it
    if (candidateSpecs.length === 0) {
      candidateSpecs.push(tok);
    }
    break;
  }

  for (const spec of candidateSpecs) {
    // Local file/directory paths are covered by contentTreeSha256, not remote registries
    if (spec.startsWith(".") || spec.startsWith("/") || spec.includes("${PLUGIN_ROOT}")) {
      continue;
    }
    if (!exactPinRe.test(spec)) {
      return { runner, packageSpec: spec };
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Main Entrypoint: Plugs Directly Into scripts/crawl.mjs
// ---------------------------------------------------------------------------
/**
 * Execute all 4 static security analysis passes against an extracted plugin directory.
 */
export async function scanPluginSecurity({
  sandboxDir,
  files = [],
  parsed,
  repoFullName,
  sha,
  scannerVersion = "1.2.0",
  semgrepRulesPath = DEFAULT_SEMGREP_RULES,
  skipSemgrep = false,
}) {
  if (!sandboxDir || !parsed || !repoFullName || !sha) {
    throw new Error("scanPluginSecurity requires sandboxDir, parsed, repoFullName, and sha.");
  }

  const capabilities = new Set();
  const findings = [];

  // Read mcp_config.json and hooks.json raw text once for accurate line-number pinning
  const mcpRaw = await readOptionalUtf8(path.join(sandboxDir, "mcp_config.json"));
  const hooksRaw = await readOptionalUtf8(path.join(sandboxDir, "hooks.json"));

  // --- Pass 1: Manifest, MCP Runtimes & Lifecycle Hooks ---
  if (parsed.surface.components.includes("mcp_stdio")) {
    capabilities.add("mcp_local_exec");
  }
  if (parsed.surface.components.includes("mcp_remote")) {
    capabilities.add("network_external_mcp");
  }

  for (const srv of parsed.mcpServers || []) {
    if (srv.transport !== "stdio") continue;
    const unpinned = detectUnpinnedRuntime(srv.command, srv.args);
    if (unpinned) {
      const line = findNeedleLine(mcpRaw, unpinned.packageSpec) || findNeedleLine(mcpRaw, srv.name);
      capabilities.add("unpinned_remote_runtime");
      findings.push({
        id: "MANIFEST_UNPINNED_RUNTIME",
        severity: "high",
        layer: "manifest",
        capability: "unpinned_remote_runtime",
        message: `MCP server "${srv.name}" executes unpinned remote package "${unpinned.packageSpec}" via ${unpinned.runner} (bypasses commit SHA pinning).`,
        file: "mcp_config.json",
        line,
        snippet: cleanSnippet(`${srv.command} ${(srv.args || []).join(" ")}`),
        githubBlobUrl: makeBlobUrl(repoFullName, sha, "mcp_config.json", line),
      });
    }
  }

  for (const h of parsed.hooks?.commandHooks || []) {
    const cmd = h.command || "";
    const line = findNeedleLine(hooksRaw, cmd) || findNeedleLine(hooksRaw, h.group);
    capabilities.add("runs_shell_hooks");

    findings.push({
      id: "HOOK_SHELL_COMMAND",
      severity: "high",
      layer: "manifest",
      capability: "runs_shell_hooks",
      message: `Lifecycle hook "${h.group}" executes a shell command on ${h.event} (matcher: ${h.matcher}).`,
      file: "hooks.json",
      line,
      snippet: cleanSnippet(cmd),
      githubBlobUrl: makeBlobUrl(repoFullName, sha, "hooks.json", line),
    });

    if (PIPE_TO_SHELL_RE.test(cmd)) {
      findings.push({
        id: "HOOK_PIPE_TO_SHELL",
        severity: "critical",
        layer: "manifest",
        capability: "runs_shell_hooks",
        message: `Lifecycle hook "${h.group}" downloads or decodes content and pipes it directly into a shell.`,
        file: "hooks.json",
        line,
        snippet: cleanSnippet(cmd),
        githubBlobUrl: makeBlobUrl(repoFullName, sha, "hooks.json", line),
      });
    }

    const tokens = cmd.trim().split(/\s+/);
    const unpinnedHook = detectUnpinnedRuntime(tokens[0], tokens.slice(1));
    if (unpinnedHook) {
      capabilities.add("unpinned_remote_runtime");
      findings.push({
        id: "HOOK_UNPINNED_RUNTIME",
        severity: "high",
        layer: "manifest",
        capability: "unpinned_remote_runtime",
        message: `Lifecycle hook "${h.group}" executes unpinned package "${unpinnedHook.packageSpec}" via ${unpinnedHook.runner}.`,
        file: "hooks.json",
        line,
        snippet: cleanSnippet(cmd),
        githubBlobUrl: makeBlobUrl(repoFullName, sha, "hooks.json", line),
      });
    }
  }

  for (const h of parsed.hooks?.promptHooks || []) {
    const line = findNeedleLine(hooksRaw, h.prompt || h.group);
    capabilities.add("runs_prompt_hooks");
    findings.push({
      id: "HOOK_PROMPT_EVAL",
      severity: "low",
      layer: "manifest",
      capability: "runs_prompt_hooks",
      message: `Lifecycle hook "${h.group}" runs a prompt check on ${h.event} (matcher: ${h.matcher}).`,
      file: "hooks.json",
      line,
      snippet: cleanSnippet(h.prompt || ""),
      githubBlobUrl: makeBlobUrl(repoFullName, sha, "hooks.json", line),
    });
    if (h.prompt) {
      scanPromptText({
        text: h.prompt,
        file: "hooks.json",
        repoFullName,
        sha,
        capabilities,
        findings,
      });
    }
  }

  // --- Pass 2: Prompt-Injection Scan across SKILL.md, agents/*.md, and rules/*.md ---
  const promptFiles = [
    ...(parsed.skills || []).map((s) => s.file),
    ...(parsed.agents || []).map((a) => a.file),
    ...(parsed.ruleFiles || []),
  ];
  for (const relFile of new Set(promptFiles)) {
    const text = await fs.readFile(path.join(sandboxDir, ...relFile.split("/")), "utf8");
    if (!text) continue;
    scanPromptText({ text, file: relFile, repoFullName, sha, capabilities, findings });
  }

  // --- Pass 3: Minified / Obfuscated Code Scan ---
  await scanObfuscationAndMinification({
    sandboxDir,
    files,
    repoFullName,
    sha,
    capabilities,
    findings,
  });

  // --- Pass 4: Semgrep AST Scan ---
  if (!skipSemgrep) {
    const sg = await runSemgrepScan({ sandboxDir, repoFullName, sha, semgrepRulesPath });
    for (const c of sg.capabilities) capabilities.add(c);
    findings.push(...sg.findings);
  }

  if (capabilities.size === 0) {
    capabilities.add("prompt_rules_only");
  }

  // Deduplicate by (id, file, line) and sort deterministically (most severe first)
  const seen = new Set();
  const deduped = [];
  for (const f of findings) {
    const key = `${f.id}|${f.file}|${f.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(f);
  }

  deduped.sort((a, b) => {
    const sevDiff = (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9);
    if (sevDiff !== 0) return sevDiff;
    if (a.file !== b.file) return a.file < b.file ? -1 : 1;
    return a.line - b.line;
  });

  const cappedFindings = deduped.slice(0, MAX_FINDINGS_PER_PLUGIN);

  // Compute findingCounts strictly from cappedFindings so index.json & detail JSON stay in 100% parity
  const findingCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of cappedFindings) {
    if (f.severity in findingCounts) findingCounts[f.severity] += 1;
  }

  let riskTier = "low";
  if (
    findingCounts.critical > 0 ||
    capabilities.has("runs_shell_hooks") ||
    capabilities.has("prompt_injection_suspect") ||
    capabilities.has("credential_access") ||
    capabilities.has("unpinned_remote_runtime")
  ) {
    riskTier = "high";
  } else if (
    findingCounts.high > 0 ||
    findingCounts.medium >= 2 ||
    capabilities.has("mcp_local_exec") ||
    capabilities.has("network_external_mcp") ||
    capabilities.has("contains_minified") ||
    capabilities.has("process_spawn") ||
    capabilities.has("dynamic_code_exec")
  ) {
    riskTier = "elevated";
  }

  return {
    riskTier,
    scannerVersion,
    scannedAt: new Date().toISOString(),
    capabilities: [...capabilities].sort(),
    findingCounts,
    findings: cappedFindings,
  };
}
