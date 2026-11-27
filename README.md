# Antigravity Community Plugin Registry

Automated discovery, static security auditing, and cryptographic publishing pipeline for community-made Google Antigravity App plugins.

- **Live Web Portal:** <https://domush.github.io/antigravity-plugin-registry/>
- **Submit or Refresh a Plugin:** [Open Issue-Ops Submission Form](https://github.com/Domush/antigravity-plugin-registry/issues/new?template=submit-plugin.yml)
- **Companion Sidebar Client:** [Antigravity Community Marketplace Releases](https://github.com/Domush/antigravity-community-marketplace/releases/latest)

Every 6 hours (and on every Issue-Ops submission), the registry crawls public GitHub repositories tagged `agy-plugin` or `antigravity-plugin`, pins each release to an immutable commit SHA, computes a deterministic tree hash, runs multi-layer static and AST security checks, signs the catalog with Ed25519, and publishes the catalog and web portal to GitHub Pages.

---

## Indexing Requirements for Plugin Authors

### 1. Repository Setup

- **Public & Active:** Your GitHub repository must be public and not archived.
- **Discovery Topic:** Add the `agy-plugin` or `antigravity-plugin` topic under **About → Topics** on GitHub.
- **Optional Category Topics:** Add `agy-cat-<name>` topics (for example `agy-cat-unity` or `agy-cat-devops`) to categorize your plugin alongside manifest `category`/`categories` fields (up to 5 categories; up to 10 tags from `keywords` and remaining GitHub topics).
- **Archive Bounds:** Tarballs must stay within 25 MB compressed, 50 MB uncompressed, and 5,000 files, with no symlinks or hardlinks.
- **Opt Out:** Place a `.agy-registry-ignore` file at the repository root to exclude a repository from indexing.

### 2. Plugin Manifest

Include `.antigravity-plugin/plugin.json` (takes precedence) or a root `plugin.json` with valid JSON and these fields:

| Field | Required | Format / Notes |
| --- | --- | --- |
| `name` | Yes | Lowercase identifier matching `^[a-z0-9][a-z0-9._-]{0,63}$` |
| `version` | Yes | Valid SemVer string (for example `1.2.0`) |
| `displayName` | No | Human-friendly catalog title (defaults to `name`) |
| `description` | No | Short summary shown in catalog cards |
| `icon` | No | Relative image path (`.svg`, `.png`, `.webp`, `.jpg`, or `.jpeg`); otherwise `.antigravity-plugin/icon.svg`, `.antigravity-plugin/icon.png`, `icon.svg`, `icon.png`, `logo.svg`, `logo.png`, `assets/icon.svg`, or `assets/icon.png` is used if present |
| `minAppVersion` | No | Valid SemVer string (defaults to `2.34.0` when sidebar UI is detected) |
| `category` / `categories` | No | String or array of category slugs |
| `keywords` | No | Array of search tags |

Include `.antigravity-plugin/README.md` (takes precedence) or root `README.md` (up to 32 KB rendered) for pre-install documentation.

### 3. Supported Antigravity Components

A repository must ship **at least one** of the following components alongside its manifest:

- **Skills:** `skills/<folder>/SKILL.md` (one directory level deep; supports YAML frontmatter `name`, `description`, `disable-model-invocation`)
- **Rules:** `rules/*.md`, `AGENTS.md`, or `GEMINI.md`
- **Agents:** `agents/*.md` or `agents/<folder>/agent.md`
- **Hooks:** `hooks.json` supporting `SessionStart`, `PreToolUse`, `PostToolUse`, `PreInvocation`, `PostInvocation`, and `Stop`
- **MCP Servers:** `mcp_config.json` defining local `stdio` (`command`, `args`) or remote `http` (`url` / `serverUrl`) servers, plus optional `variables` metadata and `${VAR}` placeholders (raw `env` and `headers` values are always stripped before publishing)

---

## Security & Supply-Chain Standards

Every candidate commit passes through four static analysis passes (`scripts/security-scanner.mjs`, `scripts/lib/scanner-passes.mjs`, and `scanner/semgrep-rules.yml`) plus integrity validation:

- **Pin Remote Package Versions:** In `mcp_config.json` and `hooks.json`, pin exact versions when invoking remote package runners:
  - Node runners (`npx`, `pnpx`, `bunx`, `npm exec`): use `pkg@1.2.3` or `@scope/pkg@1.2.3`.
  - Python runners (`uvx`, `uv tool run`, `pipx run`): use `pkg==1.2.3`.
  - Avoid remote `http://` or `https://` script URLs in `deno run`.
  - Local paths (`.`, `/`, `${PLUGIN_ROOT}`) are verified automatically by the pinned repository tree hash.
- **Avoid Pipe-to-Shell Hooks:** Lifecycle hooks in `hooks.json` and prompt instructions should never download or decode payloads directly into a shell (`curl ... | sh`, `wget ... | bash`, `iex ... irm`, `base64 -d | sh`).
- **Keep Code Unminified & Auditable:** Avoid minified/bundled code files (`> 2,000` characters per line or dense single-line bundles) and dense `\x` / `\u` escape sequences so static and Semgrep AST rules can inspect every file cleanly.
- **Keep Prompts Clean:** Markdown skills, rules, agents, and prompt hooks are scanned for invisible zero-width/bidirectional/Unicode Tag characters, hidden HTML comment directives (`<!-- ... -->`), long embedded base64 payloads, guardrail-override phrasing, and credential-exfiltration directives.
- **Deterministic Tree Hashing (`contentTreeSha256`):** The crawler and client compute a SHA-256 digest over sorted POSIX file paths and raw file bytes (`<path>\0<byteLength>\0<bytes>\0`) tied to the exact 40-character GitHub commit SHA.
- **Ed25519 Catalog Signing:** `scripts/sign-registry.mjs` signs `index.json` and `denylist.json` using an `agy-registry-sig-v1` domain-separated transcript, producing `index.json.sig` and `denylist.json.sig` verified in the browser (`site/verify.js`) and client.

---

## Immediate Submission & Refresh (Issue-Ops)

Authors do not need to wait for the 6-hour scheduled crawl:

1. Open the [Submit or Refresh Plugin](https://github.com/Domush/antigravity-plugin-registry/issues/new?template=submit-plugin.yml) issue template (`.github/ISSUE_TEMPLATE/submit-plugin.yml`).
2. Enter `owner/repo` or your full GitHub repository URL.
3. Choose **Scan Mode**:
   - **Standard (index new release or commit):** Indexes a new release or commit (skips rescanning if the target commit SHA and scanner version are already cached).
   - **Force rescan (re-run security scanner on current commit):** Re-runs the full parser and security scanner on the current commit.
4. Confirm the pre-flight checklist and submit the issue.

`.github/workflows/issue-ops-submit.yml` validates repository eligibility, runs the crawler in single-repository mode, validates schema parity (`scripts/validate-output.mjs`), signs the updated catalog, deploys to GitHub Pages, posts the audit report on the issue, and automatically closes it with the `indexed` or `rejected` label.

---

## Maintainer Setup Checklist

Follow these steps when initializing or rotating a registry deployment:

1. **Configure Ed25519 Signing Key:**
   - Generate a keypair with `node ./scripts/sign-registry.mjs --keygen` (or use an existing PKCS#8 private key).
   - Pin the public key PEM and its 16-character key ID in `site/verify.js` and the companion marketplace client.
   - Add the private key PEM to **Settings → Secrets and variables → Actions** as `REGISTRY_SIGNING_PRIVATE_KEY`.
2. **Enable GitHub Pages via Actions:**
   - Set **Settings → Pages → Build and deployment → Source** to **GitHub Actions**.
3. **Create Issue-Ops Labels:**
   - Ensure the repository has these labels under **Issues → Labels**: `plugin-submission`, `indexed`, and `rejected`.
4. **Run Initial Crawl & Publish:**
   - Open **Actions → Crawl and Publish Plugin Registry** (`.github/workflows/crawl-registry.yml`) and click **Run workflow** (`workflow_dispatch`).
   - This initializes the `registry-data` branch, validates schemas, signs `index.json` and `denylist.json`, and publishes the combined catalog and web portal (`site/`) to GitHub Pages.

### Local Verification

```bash
npm ci
npm test
```

To validate a local registry output directory against all schema, size, and parity rules:

```bash
node ./scripts/validate-output.mjs ./registry-data/public
```
