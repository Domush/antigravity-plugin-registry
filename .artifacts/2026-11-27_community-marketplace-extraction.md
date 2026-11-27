# Plan: Antigravity Plugin Registry Extraction & Implementation

**Date:** 2026-11-27  
**Repository:** `C:\GitHub\antigravity-plugin-registry`  
**Pipeline Scope:** Code + Adversarial Audit (`@team-coder` -> `@team-auditor`)

## Goal
Extract and implement the complete `agy-plugin-registry` backend, static security scanner, Ed25519 signing pipeline, GitHub Actions workflows, Issue-Ops submission template, static GitHub Pages web portal, and offline fixture test suites specified in `community marketplace v1.pdf` (with all incremental updates applied).

## Implementation Phases

### Phase 1: Package, Config, Scanner Rules & Workflows
- `package.json`: Node.js 22 ESM configuration (`tar-stream`, `crawl` and `test` scripts).
- `config/denylist.json`: Valid `schemaVersion: 1` kill-switch template (`blockedRepos`, `blockedShas`).
- `config/client-release.json`: Self-update banner metadata (`latestVersion`, `minSupportedVersion`, `releaseUrl`, `notes`).
- `scanner/semgrep-rules.yml`: AST security rules (`CODE_CREDENTIAL_PATH`, `CODE_JS_PROCESS_SPAWN`, `CODE_PY_PROCESS_SPAWN`, `CODE_JS_DYNAMIC_EXEC`, `CODE_PY_DYNAMIC_EXEC`, `CODE_JS_NETWORK`, `CODE_PY_NETWORK`, `CODE_JS_FS_WRITE`, `CODE_PY_FS_WRITE`).
- `.github/ISSUE_TEMPLATE/submit-plugin.yml`: Issue-Ops form for on-demand plugin indexing.
- `.github/workflows/crawl-registry.yml`, `.github/workflows/issue-ops-submit.yml`, `.github/workflows/deploy-site.yml`: Full CI pipelines with offline tests, `validate-output.mjs`, Ed25519 signing, and combined `pages-dist` Pages deployment.

### Phase 2: Crawler, Security Scanner, Validator & Signer
- `scripts/security-scanner.mjs`: 4-pass security scanner (`detectUnpinnedRuntime` with positional-after-flag fix, prompt-injection & invisible Unicode/tag scanner with `INVISIBLE_UNICODE_RE` cleanup, minification/obfuscation detector, Semgrep AST runner).
- `scripts/crawl.mjs` (decomposed modularly under `scripts/lib/` to stay strictly <= 500 lines per file while preserving all named exports: `computeContentTreeSha256`, `resolveInsideSandbox`, `runSecurityScan`, `stripTopLevelDir`, `validateAndParsePlugin`):
  - Date-sharded topic discovery, deterministic SHA resolution, zip-slip & bomb-hardened tarball extraction, deterministic `contentTreeSha256`, Antigravity component parsing (`.antigravity-plugin/plugin.json`, `mcp_config.json`, `hooks.json`, `skills/*/SKILL.md`, `agents/*.md`, `rules/*.md`), `CRAWL_SUMMARY_PATH` structured summary hook, `marketplaceClient` inclusion, `pluginName` field, and delegation to `scanPluginSecurity` (`scannerVersion: "1.1.0"`).
- `scripts/validate-output.mjs`: Zero-dependency CI gate validating `denylist.json`, `index.json` (including `marketplaceClient` and 1 MiB budget), `plugins/{owner}/{repo}.json` parity, secret-leak guard, and orphan file detection (split helper if needed to stay <= 500 lines).
- `scripts/sign-registry.mjs`: Ed25519 `--keygen` and detached `.sig` signing for `index.json` and `denylist.json`.

### Phase 3: Static GitHub Pages Web Portal
- `site/index.html`, `site/styles.css`, `site/app.js` (modularized under `site/` if > 500 lines, e.g., `site/verify.js`, `site/render.js`):
  - Search/filter/sort UI, URL query state sync, bookmarks, theme toggle, Web Crypto Ed25519 `index.json.sig` verification (fail-closed + CDN retry), `detailSha256` transitive check, and slide-over audit/install drawer.

### Phase 4: Offline Fixture Tests (Extracted from PDF)
- `tests/registry-fixtures.test.mjs` (updated to stay consistent with `scannerVersion: "1.1.0"` findings such as `HOOK_PIPE_TO_SHELL` sorting ahead of `HOOK_SHELL_COMMAND` and exact line-number blob URLs).
- `tests/security-scanner.test.mjs`.

## Edge Cases & Guardrails
- Enforce <= 500-line ceiling on every source and test file (`audit-gate.js`).
- Zero stubs, zero `TODO`/`FIXME` markers, zero `.skip`/`.only` in tests.
- Ensure `tests/registry-fixtures.test.mjs` assertions match `scanPluginSecurity()` behavior in `crawl.mjs` v1.1.0.

## Verification Strategy
- Run `node "C:\Users\domus\.gemini\config\plugins\agent-team\scripts\audit-gate.js"` on all created files.
- Perform full line-1-to-EOF adversarial audit via `@team-auditor`.
