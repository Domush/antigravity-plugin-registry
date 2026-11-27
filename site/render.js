// ---------------------------------------------------------------------------
// Formatting & HTML Escaping Helpers + DOM Rendering
// ---------------------------------------------------------------------------
export const CAPABILITY_LABELS = {
  runs_shell_hooks: "Shell Lifecycle Hooks",
  runs_prompt_hooks: "Prompt Lifecycle Hooks",
  unpinned_remote_runtime: "Unpinned Remote Package (npx/uvx)",
  prompt_injection_suspect: "Suspicious Prompt Directives",
  credential_access: "Accesses Credential Paths",
  process_spawn: "Spawns OS Processes",
  dynamic_code_exec: "Dynamic Code Execution",
  mcp_local_exec: "Local Executable (stdio MCP)",
  network_external_mcp: "Remote External MCP",
  network_outbound: "Outbound Network Calls",
  fs_write_workspace: "Writes Workspace Files",
  fs_read_workspace: "Reads Workspace Files",
  fs_outside_workspace: "Reads Outside Workspace",
  contains_minified: "Minified / Obfuscated Code",
  prompt_mentions_shell: "Prompt Requests Shell Commands",
  prompt_rules_only: "Prompt / Rules Only",
};

export function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function capLabel(key) {
  return CAPABILITY_LABELS[key] || key.replaceAll("_", " ");
}

export function formatDate(iso) {
  if (!iso) return "unknown";
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? "unknown"
    : d.toLocaleDateString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
      });
}

export function populateCategories(state) {
  const select = document.getElementById("filter-category");
  const cats = new Set();
  for (const p of state.index.plugins || []) {
    for (const c of p.categories || []) cats.add(c);
  }
  select.innerHTML =
    `<option value="all">All Categories</option>` +
    [...cats]
      .sort()
      .map((c) => `<option value="${esc(c)}">${esc(c)}</option>`)
      .join("");
  select.value = cats.has(state.cat) ? state.cat : "all";
  state.cat = select.value;
}

export function renderStats(state) {
  const plugins = state.index.plugins || [];
  document.getElementById("stat-total").textContent = String(plugins.length);
  document.getElementById("stat-low").textContent = String(
    plugins.filter((p) => p.security?.riskTier === "low").length
  );
  document.getElementById("stat-ui").textContent = String(
    plugins.filter((p) => p.surface?.hasSidebarUi).length
  );
  const sigEl = document.getElementById("stat-sig");
  sigEl.textContent = state.sigStatus;
  sigEl.dataset.sigState = state.sigState;
  document.getElementById("registry-meta").textContent = state.index.generatedAt
    ? `Updated ${formatDate(state.index.generatedAt)} · Scanner v${state.index.scannerVersion || "1.0.0"}`
    : "Community Registry";
}

export function renderCard(p, state) {
  const risk = p.security?.riskTier || "unverified";
  const isSaved = state.bookmarks.has(p.id);
  const caps = (p.security?.capabilities || []).slice(0, 3);
  const cliCmd = `agy plugin install ${p.repoUrl}`;

  return `
    <article class="card">
      <div class="card-head">
        <div class="card-identity">
          <img
            class="avatar"
            src="${esc(p.author?.avatarUrl || "")}"
            alt="${esc(p.author?.login || "Author")}"
            loading="lazy"
            width="34"
            height="34"
          />
          <button type="button" class="card-title-btn" data-open-plugin="${esc(p.id)}">
            <span class="card-name">${esc(p.name)}</span>
            <span class="card-sub">
              ${esc(p.author?.login || "unknown")} &middot; v${esc(p.version)} &middot; &#9733; ${esc(p.stats?.stars ?? 0)}
            </span>
          </button>
        </div>
        <button
          type="button"
          class="star-btn ${isSaved ? "is-saved" : ""}"
          data-bookmark="${esc(p.id)}"
          title="${isSaved ? "Remove from saved" : "Save plugin"}"
          aria-label="${isSaved ? "Remove from saved" : "Save plugin"}"
        >
          ${isSaved ? "&#9733;" : "&#9734;"}
        </button>
      </div>

      <p class="card-summary">${esc(p.summary || "No description provided.")}</p>

      <div class="pill-row">
        <span class="badge risk-${esc(risk)}">Risk: ${esc(risk)}</span>
        ${p.surface?.hasSidebarUi ? `<span class="badge badge-accent">Sidebar UI</span>` : ""}
        ${p.requiresCredentials ? `<span class="badge risk-elevated">API Key / OAuth</span>` : ""}
        ${caps.map((c) => `<span class="badge">${esc(capLabel(c))}</span>`).join("")}
      </div>

      <div class="card-foot">
        <div class="card-actions">
          <button type="button" class="btn btn-primary" data-open-plugin="${esc(p.id)}">
            Audit &amp; Install
          </button>
          <button type="button" class="btn btn-secondary" data-copy="${esc(cliCmd)}">
            Copy CLI
          </button>
        </div>
        <a class="muted" style="font-size:12px" href="${esc(p.repoUrl)}" target="_blank" rel="noopener noreferrer">
          GitHub &nearr;
        </a>
      </div>
    </article>
  `;
}

export function renderDrawerContent(state, { registryGithubRepo, clientPluginRepo }) {
  if (!state.drawer.open) return;
  const container = document.getElementById("drawer-inner");
  const p = (state.index.plugins || []).find((x) => x.id === state.drawer.pluginId);
  if (!p) return;

  const detail = state.drawer.detail;
  const findings = detail?.securityReport?.findings || [];
  const caps = detail?.securityReport?.capabilities || p.security?.capabilities || [];
  const cliCmd = `agy plugin install ${p.repoUrl}`;
  const shareUrl = `${window.location.origin}${window.location.pathname}?plugin=${encodeURIComponent(p.id)}`;
  const reportUrl =
    `${registryGithubRepo}/issues/new?title=${encodeURIComponent(`Report plugin: ${p.id}`)}` +
    `&body=${encodeURIComponent(`Plugin: ${p.id}\nPinned SHA: ${p.release.sha}\nReason:\n`)}`;

  let bodyHtml = "";
  if (state.drawer.loading) {
    bodyHtml = `<p class="muted">Loading security audit report and README...</p>`;
  } else if (state.drawer.error) {
    bodyHtml = `<div class="alert alert-danger">${esc(state.drawer.error)}</div>`;
  } else if (state.drawer.tab === "install") {
    const envVars = detail?.credentials?.envVars || [];
    const oauth = detail?.credentials?.oauthProviders || [];
    const slashCmds = detail?.collisions?.slashCommands || [];
    const mcpNames = detail?.collisions?.mcpServerNames || [];

    bodyHtml = `
      <section class="panel">
        <h3>Install via Antigravity CLI</h3>
        <div class="cmd-row">
          <code>${esc(cliCmd)}</code>
          <button type="button" class="btn btn-secondary" data-copy="${esc(cliCmd)}">Copy</button>
        </div>
        <p class="muted" style="margin:0;font-size:12px">
          Want 1-click GUI installs with automatic <code>contentTreeSha256</code> verification, permission diffs, and update alerts?
          Install the <a href="${esc(clientPluginRepo)}" target="_blank" rel="noopener noreferrer">Community Marketplace sidebar plugin</a>.
        </p>
      </section>

      <section class="panel">
        <h3>Verified Release Provenance</h3>
        <ul class="kv-list">
          <li><strong>Pinned Commit:</strong> <a href="${esc(p.repoUrl)}/commit/${esc(p.release.sha)}" target="_blank" rel="noopener noreferrer"><code>${esc(p.release.sha)}</code></a> (${esc(p.release.ref)})</li>
          <li><strong>Tree SHA-256:</strong> <code>${esc(p.release.contentTreeSha256)}</code></li>
          <li><strong>Pinned Archive:</strong> <a href="${esc(p.release.tarballUrl)}" target="_blank" rel="noopener noreferrer">Download audited tarball</a> (${Math.round((p.release.archiveBytes || 0) / 1024)} KB)</li>
          ${p.minAppVersion ? `<li><strong>Minimum Antigravity App:</strong> v${esc(p.minAppVersion)}</li>` : ""}
        </ul>
      </section>

      <section class="panel">
        <h3>Capabilities &amp; Components</h3>
        <div class="pill-row">
          ${caps.map((c) => `<span class="badge">${esc(capLabel(c))}</span>`).join("")}
        </div>
        ${slashCmds.length ? `<div style="font-size:12px"><strong>Slash Commands:</strong> ${slashCmds.map((c) => `<code>${esc(c)}</code>`).join(", ")}</div>` : ""}
        ${mcpNames.length ? `<div style="font-size:12px"><strong>MCP Servers:</strong> ${mcpNames.map((n) => `<code>${esc(n)}</code>`).join(", ")}</div>` : ""}
      </section>

      ${
        envVars.length > 0 || oauth.length > 0
          ? `
        <section class="panel">
          <h3>Required Credentials</h3>
          <ul class="kv-list">
            ${envVars.map((e) => `<li><code>${esc(e.name)}</code> (${e.required ? "required" : "optional"}) &mdash; ${esc(e.description)}</li>`).join("")}
            ${oauth.map((o) => `<li>OAuth Provider: <strong>${esc(o)}</strong></li>`).join("")}
          </ul>
        </section>
      `
          : ""
      }
    `;
  } else if (state.drawer.tab === "audit") {
    const history = detail?.history || [];
    bodyHtml = `
      <section class="panel">
        <h3>Static Security Findings (${findings.length})</h3>
        ${
          findings.length === 0
            ? `<p class="muted" style="margin:0">No code, manifest, or prompt-injection warnings flagged at this commit.</p>`
            : findings
                .map((f) => {
                  const badgeClass =
                    f.severity === "critical" || f.severity === "high"
                      ? "risk-high"
                      : f.severity === "medium"
                        ? "risk-elevated"
                        : "risk-low";
                  return `
                  <div class="finding">
                    <div class="finding-head">
                      <span>
                        <span class="badge ${badgeClass}">${esc(f.severity)}</span>
                        <strong>${esc(f.id)}</strong> <span class="muted">(${esc(f.layer)})</span>
                      </span>
                      <a class="btn btn-secondary" style="padding:4px 8px;font-size:12px" href="${esc(f.githubBlobUrl)}" target="_blank" rel="noopener noreferrer">
                        Inspect Line &nearr;
                      </a>
                    </div>
                    <div style="font-size:13px">${esc(f.message)}</div>
                    <div class="muted" style="font-size:12px">${esc(f.file)}:${esc(f.line)}</div>
                    ${f.snippet ? `<pre class="code-block">${esc(f.snippet)}</pre>` : ""}
                  </div>
                `;
                })
                .join("")
        }
      </section>

      ${
        history.length > 0
          ? `
        <section class="panel">
          <h3>Scanned Version History</h3>
          <ul class="kv-list">
            ${history
              .map(
                (h) => `
              <li>
                <strong>v${esc(h.version)}</strong> (<code>${esc(h.sha.slice(0, 10))}</code>) &middot;
                <span class="badge risk-${esc(h.riskTier)}">${esc(h.riskTier)}</span> &middot;
                <span class="muted">${esc((h.capabilities || []).join(", "))}</span>
              </li>
            `
              )
              .join("")}
          </ul>
        </section>
      `
          : ""
      }
    `;
  } else {
    bodyHtml = `
      ${
        detail?.latestReleaseNotes
          ? `<section class="panel"><h3>Release Notes (${esc(p.release.ref)})</h3><pre class="readme-pre">${esc(detail.latestReleaseNotes)}</pre></section>`
          : ""
      }
      <section class="panel">
        <h3>README</h3>
        <pre class="readme-pre">${esc(detail?.readmeMarkdown || "No README available.")}</pre>
      </section>
    `;
  }

  container.innerHTML = `
    <div class="drawer-head">
      <div>
        <h2 style="margin:0;font-size:18px">${esc(p.name)}</h2>
        <div class="muted" style="font-size:12px">
          ${esc(p.id)} &middot; v${esc(p.version)} &middot; ${esc(p.license)} &middot; Updated ${esc(formatDate(p.stats?.pushedAt))}
        </div>
      </div>
      <button type="button" class="btn btn-secondary" data-close-drawer>Close</button>
    </div>

    <div class="drawer-tabs">
      <button type="button" class="drawer-tab ${state.drawer.tab === "install" ? "is-active" : ""}" data-drawer-tab="install">
        Install &amp; Overview
      </button>
      <button type="button" class="drawer-tab ${state.drawer.tab === "audit" ? "is-active" : ""}" data-drawer-tab="audit">
        Security Audit (${findings.length})
      </button>
      <button type="button" class="drawer-tab ${state.drawer.tab === "readme" ? "is-active" : ""}" data-drawer-tab="readme">
        README &amp; Notes
      </button>
    </div>

    <div class="drawer-body">${bodyHtml}</div>

    <div class="drawer-foot">
      <span class="badge risk-${esc(p.security?.riskTier || "unverified")}">
        Risk: ${esc(p.security?.riskTier || "unverified")}
      </span>
      <div class="card-actions">
        <button type="button" class="btn btn-secondary" data-copy="${esc(shareUrl)}">Copy Link</button>
        <a class="btn btn-secondary" href="${esc(p.repoUrl)}" target="_blank" rel="noopener noreferrer">GitHub &nearr;</a>
        <a class="btn btn-danger" href="${esc(reportUrl)}" target="_blank" rel="noopener noreferrer">Report</a>
      </div>
    </div>
  `;
}
