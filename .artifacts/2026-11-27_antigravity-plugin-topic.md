# Plan: Add `antigravity-plugin` Discovery Topic

**Date:** 2026-11-27  
**Repository:** `c:\GitHub\antigravity-plugin-registry`

## Goal
Add `antigravity-plugin` alongside `agy-plugin` as a supported GitHub repository discovery topic/tag in the plugin registry crawler, parser, Issue-Ops workflow, web portal, and documentation, while keeping `resolveTargetRelease` (release vs. default-branch HEAD resolution) unchanged.

## Implementation Steps
1. Update `scripts/lib/github-client.mjs` to replace single `topic` with `DEFAULT_DISCOVERY_TOPICS = ["agy-plugin", "antigravity-plugin"]`, validate `topics`, search each topic, and deduplicate results by `full_name`. Keep `resolveTargetRelease` unchanged.
2. Update `scripts/crawl.mjs` (`CONFIG.topics`) and `scripts/lib/plugin-parser.mjs` (`topics` filtering in `tags`).
3. Update `.github/workflows/issue-ops-submit.yml`, `.github/ISSUE_TEMPLATE/submit-plugin.yml`, `site/index.html`, and `README.md`.
4. Add unit tests in `tests/github-client.test.mjs` and `tests/registry-fixtures.test.mjs`.

## Edge Cases
- Deduplicate repositories carrying both `agy-plugin` and `antigravity-plugin`.
- Fail fast if `topics` is invalid or empty.
- Preserve rate-limit pacing between topic searches with configurable `searchDelayMs` for tests.

## Verification Strategy
- Run `npm test` (logging to `Logs/test-results-antigravity-plugin-topic.log`).
- Run `audit-gate.js` on all modified and newly created JS/MJS files.
