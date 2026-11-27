import { renderMarkdown } from "./markdown.js";

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
  accesses_gemini_dir: "Reads ~/.gemini Data",
  contains_minified: "Minified / Obfuscated Code",
  prompt_mentions_shell: "Prompt Requests Shell Commands",
  prompt_rules_only: "Prompt / Rules Only",
};

export const CAPABILITY_TOOLTIPS = {
  runs_shell_hooks: "Executes shell commands during Antigravity lifecycle hooks (hooks.json).",
  runs_prompt_hooks: "Runs prompt evaluation hooks on lifecycle events.",
  unpinned_remote_runtime: "Invokes an unpinned remote package runner (npx/uvx/pipx/deno), bypassing commit SHA pinning.",
  prompt_injection_suspect: "Contains hidden Unicode, HTML comment directives, or guardrail-override phrasing.",
  credential_access: "References sensitive credential, token, or private key paths (~/.ssh, ~/.aws, ~/.gemini auth files).",
  process_spawn: "Spawns external OS child processes from plugin code.",
  dynamic_code_exec: "Evaluates runtime-constructed code via eval, new Function, vm, or exec.",
  mcp_local_exec: "Runs a local stdio MCP server executable on your machine.",
  network_external_mcp: "Connects to a remote HTTP/SSE MCP server endpoint.",
  network_outbound: "Makes outbound HTTP/network requests from plugin code.",
  fs_write_workspace: "Writes, modifies, or deletes files on the local filesystem.",
  fs_read_workspace: "Reads files within the active workspace.",
  fs_outside_workspace: "Reads filesystem paths outside the active workspace.",
  accesses_gemini_dir: "Reads or writes Antigravity plugin data, settings, or telemetry under ~/.gemini/.",
  contains_minified: "Contains minified, bundled, or densely escaped code harder to audit statically.",
  prompt_mentions_shell: "Prompts guide the agent to execute local shell commands or scripts.",
  prompt_rules_only: "Pure Markdown prompts, skills, or rules with no executable code or hooks.",
};

export const RISK_TOOLTIPS = {
  low: "Low risk: prompt/rules or benign metadata only, with zero high-severity findings. Click to view audit.",
  elevated: "Elevated risk: executes local/remote tools, spawns processes, or has medium/high findings. Click to view audit.",
  high: "High risk: runs shell hooks, accesses credentials, uses unpinned packages, or has critical findings. Click to view audit.",
  unverified: "Unverified: security audit data is incomplete or unavailable for this release. Click to view audit.",
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

export function capTooltip(key) {
  return CAPABILITY_TOOLTIPS[key] || capLabel(key);
}

export function riskTooltip(risk) {
  return RISK_TOOLTIPS[risk] || RISK_TOOLTIPS.unverified;
}

function safeHttpsImageUrl(rawUrl) {
  if (typeof rawUrl !== "string") return "";
  const trimmed = rawUrl.trim();
  if (!trimmed.startsWith("https://")) return "";
  try {
    const parsed = new URL(trimmed);
    return parsed.protocol === "https:" ? parsed.href : "";
  } catch {
    return "";
  }
}

function computeInitials(name) {
  const words = String(name || "")
    .trim()
    .split(/[\s/_.-]+/)
    .filter(Boolean);
  if (words.length >= 2) {
    return `${words[0][0]}${words[1][0]}`.toUpperCase();
  }
  const single = words[0] || "AG";
  return single.slice(0, 2).toUpperCase();
}

export function renderPluginIcon(p, { size = 34 } = {}) {
  const iconUrl = safeHttpsImageUrl(p?.iconUrl);
  const avatarUrl = safeHttpsImageUrl(p?.author?.avatarUrl);
  const primaryUrl = iconUrl || avatarUrl;
  const initials = computeInitials(p?.name || p?.pluginName || p?.id);
  const sizeClass = size >= 38 ? "avatar avatar-lg" : "avatar";

  if (!primaryUrl) {
    return `<span class="${sizeClass} avatar-monogram" aria-hidden="true">${esc(initials)}</span>`;
  }

  const fallbackAttr =
    iconUrl && avatarUrl && avatarUrl !== iconUrl
      ? ` data-fallback-src="${esc(avatarUrl)}"`
      : "";
  const altText = iconUrl ? `${p?.name || "Plugin"} icon` : `${p?.author?.login || "Author"}`;

  return `<img class="${sizeClass}" src="${esc(primaryUrl)}" alt="${esc(altText)}" loading="lazy" width="${esc(size)}" height="${esc(size)}" data-initials="${esc(initials)}"${fallbackAttr} />`;
}

export function swapBrokenIcon(event) {
  const img = event?.target;
  if (!img || img.tagName !== "IMG" || !img.classList?.contains("avatar")) return;
  const fallbackSrc = img.dataset?.fallbackSrc;
  if (fallbackSrc && img.dataset?.fallbackTried !== "1") {
    img.dataset.fallbackTried = "1";
    img.src = fallbackSrc;
    return;
  }
  const mono = document.createElement("span");
  mono.className = img.classList.contains("avatar-lg")
    ? "avatar avatar-monogram avatar-lg"
    : "avatar avatar-monogram";
  mono.setAttribute("aria-hidden", "true");
  mono.textContent = img.dataset?.initials || "AG";
  img.replaceWith(mono);
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
  const summaryText = p.summary || "No description provided.";

  return `
    <article class="card">
      <div class="card-head">
        <div class="card-identity">
          ${renderPluginIcon(p)}
          <button
            type="button"
            class="card-title-btn"
            data-open-plugin="${esc(p.id)}"
            data-open-tab="install"
            title="${esc(`Open ${p.name} install & overview`)}"
          >
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

      <p class="card-summary" title="${esc(summaryText)}">${esc(summaryText)}</p>

      <div class="pill-row">
        <button
          type="button"
          class="badge risk-${esc(risk)}"
          data-open-plugin="${esc(p.id)}"
          data-open-tab="audit"
          title="${esc(riskTooltip(risk))}"
        >
          Risk: ${esc(risk)}
        </button>
        ${p.surface?.hasSidebarUi ? `<span class="badge badge-accent" title="Provides a sidebar UI panel inside Antigravity">Sidebar UI</span>` : ""}
        ${p.requiresCredentials ? `<span class="badge risk-elevated" title="Requires API keys or OAuth credentials">API Key / OAuth</span>` : ""}
        ${caps.map((c) => `<span class="badge" title="${esc(capTooltip(c))}">${esc(capLabel(c))}</span>`).join("")}
      </div>

      <div class="card-foot">
        <div class="card-actions">
          <button
            type="button"
            class="btn btn-primary"
            data-open-plugin="${esc(p.id)}"
            data-open-tab="install"
            title="Inspect release provenance, permissions, and install instructions"
          >
            Audit &amp; Install
          </button>
          <button
            type="button"
            class="btn btn-secondary"
            data-copy="${esc(cliCmd)}"
            title="${esc(`Copy CLI install command: ${cliCmd}`)}"
          >
            Copy CLI
          </button>
        </div>
        <a
          class="muted"
          style="font-size:12px"
          href="${esc(p.repoUrl)}"
          target="_blank"
          rel="noopener noreferrer"
          title="Open repository on GitHub"
        >
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
          ${caps.map((c) => `<span class="badge" title="${esc(capTooltip(c))}">${esc(capLabel(c))}</span>`).join("")}
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
    const mdOpts = {
      linkMode: "anchor",
      repoUrl: p.repoUrl || "",
      sha: p.release?.sha || "",
    };
    const releaseNotesHtml = detail?.latestReleaseNotes
      ? renderMarkdown(detail.latestReleaseNotes, mdOpts)
      : "";
    const readmeHtml = detail?.readmeMarkdown
      ? renderMarkdown(detail.readmeMarkdown, mdOpts)
      : `<p class="muted" style="margin:0">No README available.</p>`;
    bodyHtml = `
      ${
        releaseNotesHtml
          ? `<section class="panel"><h3>Release Notes (${esc(p.release.ref)})</h3><div class="md-body">${releaseNotesHtml}</div></section>`
          : ""
      }
      <section class="panel">
        <h3>README</h3>
        <div class="md-body">${readmeHtml}</div>
      </section>
    `;
  }

  const risk = p.security?.riskTier || "unverified";
  container.innerHTML = `
    <div class="drawer-head">
      <div class="drawer-identity">
        ${renderPluginIcon(p, { size: 40 })}
        <div>
          <h2 style="margin:0;font-size:18px">${esc(p.name)}</h2>
          <div class="muted" style="font-size:12px">
            ${esc(p.id)} &middot; v${esc(p.version)} &middot; ${esc(p.license)} &middot; Updated ${esc(formatDate(p.stats?.pushedAt))}
          </div>
        </div>
      </div>
      <button type="button" class="btn btn-secondary" data-close-drawer title="Close plugin details (Esc)">Close</button>
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
      <button
        type="button"
        class="badge risk-${esc(risk)}"
        data-drawer-tab="audit"
        title="${esc(riskTooltip(risk))}"
      >
        Risk: ${esc(risk)}
      </button>
      <div class="card-actions">
        <button type="button" class="btn btn-secondary" data-copy="${esc(shareUrl)}" title="Copy direct link to this plugin">Copy Link</button>
        <a class="btn btn-secondary" href="${esc(p.repoUrl)}" target="_blank" rel="noopener noreferrer" title="Open repository on GitHub">GitHub &nearr;</a>
        <a class="btn btn-danger" href="${esc(reportUrl)}" target="_blank" rel="noopener noreferrer" title="Report security or policy issue on GitHub">Report</a>
      </div>
    </div>
  `;
}
