# Implementation Summary: Add `antigravity-plugin` Discovery Topic & Release v1.0.1

**Date:** 2026-11-27  
**Repository:** `c:\GitHub\antigravity-plugin-registry`

## Created / Modified Files
- `scripts/lib/github-client.mjs` (modified): Exported `DEFAULT_DISCOVERY_TOPICS = ["agy-plugin", "antigravity-plugin"]`, replaced single `topic` with validated `topics`, updated `discoverRepositories` and `searchRange` to query each topic and deduplicate by `full_name`. Preserved `resolveTargetRelease` unchanged.
- `scripts/crawl.mjs` (modified): Updated `CONFIG.topics` to `["agy-plugin", "antigravity-plugin"]` and bumped `crawlerVersion` and `userAgent` to `1.0.1`.
- `scripts/lib/plugin-parser.mjs` (modified): Excluded all configured `topics` (case-insensitively) plus `agy-cat-*` when populating `tags`.
- `.github/workflows/issue-ops-submit.yml` (modified): Updated topic gate to accept `agy-plugin` or `antigravity-plugin`.
- `.github/ISSUE_TEMPLATE/submit-plugin.yml` (modified): Updated template copy and checklist to mention `agy-plugin` or `antigravity-plugin`.
- `site/index.html` (modified): Updated hero copy to list both discovery tags.
- `README.md` (modified): Updated discovery topic documentation.
- `CHANGELOG.md` (created): Documented `1.0.1` and `1.0.0` releases.
- `package.json`, `package-lock.json` (modified): Bumped version to `1.0.1`.
- `.gitignore` (modified): Hardened ignores for `Logs/`, `registry-data/`, `pages-dist/`, `.env*` (preserving `!.env.example`), `*.pem`/`*.key`, `.codegraph/`, editor files, and OS artifacts.
- `tests/github-client.test.mjs` (created): Added tests for multi-topic search/deduplication, fail-fast topic validation, and preserved release-vs-HEAD resolution.
- `tests/registry-fixtures.test.mjs` (modified): Added assertion that both `agy-plugin` and `antigravity-plugin` are excluded from `parsed.tags`.
- `.artifacts/2026-11-27_antigravity-plugin-topic.md`, `.artifacts/2026-11-27_antigravity-plugin-topic-summary.md` (created): Plan and summary artifacts.

## Verification
- `npm test`: `73` passed, `0` failed, `0` skipped (`Logs/test-results-v1.0.1.log`).
- `audit-gate.js`: `GATE VERDICT: PASS (0 violations detected)`.
