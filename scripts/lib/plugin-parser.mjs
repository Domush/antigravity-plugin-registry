import fs from "node:fs/promises";
import path from "node:path";

const SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

const HOOK_EVENTS = new Set([
  "SessionStart",
  "PreToolUse",
  "PostToolUse",
  "PreInvocation",
  "PostInvocation",
  "Stop",
]);

export async function readJsonIfExists(filePath) {
  try {
    const raw = await fs.readFile(filePath, "utf8");
    return JSON.parse(raw);
  } catch (err) {
    if (err.code === "ENOENT") return null;
    throw new Error(`Invalid JSON in ${path.basename(filePath)}: ${err.message}`);
  }
}

export async function fileExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

/**
 * Lightweight zero-dependency YAML frontmatter parser for SKILL.md and agents/*.md.
 * Handles scalar strings, quoted values, booleans, and simple single-line arrays.
 */
export function parseFrontmatter(markdown) {
  const match = markdown.match(/^\uFEFF?---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/);
  if (!match) return { data: {}, body: markdown };

  const data = {};
  const lines = match[1].split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim() || line.trim().startsWith("#")) continue;
    const kv = line.match(/^([A-Za-z0-9_-]+)\s*:\s*(.*)$/);
    if (!kv) continue;

    const key = kv[1];
    const rawVal = kv[2].trim();

    // Folded/literal multiline scalars (e.g., description: > or |)
    if (rawVal === "|" || rawVal === ">" || rawVal === "|-" || rawVal === ">-") {
      const block = [];
      while (i + 1 < lines.length && (/^\s+/.test(lines[i + 1]) || lines[i + 1].trim() === "")) {
        i += 1;
        block.push(lines[i].trim());
      }
      data[key] = block.join(rawVal.startsWith(">") ? " " : "\n").trim();
      continue;
    }

    if (rawVal === "true") {
      data[key] = true;
    } else if (rawVal === "false") {
      data[key] = false;
    } else if (
      (rawVal.startsWith('"') && rawVal.endsWith('"')) ||
      (rawVal.startsWith("'") && rawVal.endsWith("'"))
    ) {
      data[key] = rawVal.slice(1, -1);
    } else {
      data[key] = rawVal;
    }
  }

  return { data, body: markdown.slice(match[0].length) };
}

/**
 * Parse mcp_config.json:
 * - Supports local stdio (`command`, `args`) and remote HTTPS (`url` or `serverUrl`).
 * - Captures runtime-namespaced keys (`<pluginName>_<serverKey>`).
 * - Extracts declared `variables` and `${VAR}` placeholders without leaking secret values.
 */
async function parseMcpConfig(sandboxDir, pluginName) {
  const raw = await readJsonIfExists(path.join(sandboxDir, "mcp_config.json"));
  if (!raw || typeof raw !== "object") {
    return { servers: [], envVars: [], oauthProviders: [] };
  }

  const rawServers = raw.mcpServers && typeof raw.mcpServers === "object" ? raw.mcpServers : {};
  const servers = [];
  const envVarMap = new Map();
  const oauthProviders = new Set();

  const registerVar = (entry) => {
    if (!entry?.name || entry.name === "PLUGIN_ROOT" || entry.name === "PLUGIN_DATA") return;
    const prev = envVarMap.get(entry.name) || {};
    envVarMap.set(entry.name, {
      name: entry.name,
      title: entry.title || prev.title || entry.name,
      required: entry.required ?? prev.required ?? true,
      description: entry.description || prev.description || "",
      link: entry.link || prev.link || null,
    });
  };

  // Top-level variables (if declared at mcp_config.json root)
  if (Array.isArray(raw.variables)) {
    for (const v of raw.variables) registerVar(v);
  }

  const placeholderRegex = /\$\{([A-Z0-9_]+)\}/g;
  const scanForPlaceholders = (val, serverName) => {
    if (typeof val === "string") {
      for (const m of val.matchAll(placeholderRegex)) {
        registerVar({ name: m[1], required: true, description: `Referenced by MCP server "${serverName}".` });
      }
    } else if (Array.isArray(val)) {
      for (const item of val) scanForPlaceholders(item, serverName);
    } else if (val && typeof val === "object") {
      for (const v of Object.values(val)) scanForPlaceholders(v, serverName);
    }
  };

  for (const [key, cfg] of Object.entries(rawServers)) {
    if (!cfg || typeof cfg !== "object") continue;

    const remoteUrl = cfg.url || cfg.serverUrl || null;
    const transport = remoteUrl ? "http" : "stdio";

    if (Array.isArray(cfg.variables)) {
      for (const v of cfg.variables) registerVar(v);
    }

    scanForPlaceholders([cfg.command, cfg.args, cfg.env, remoteUrl, cfg.headers], key);

    for (const [envKey, envVal] of Object.entries(cfg.env || {})) {
      if (typeof envVal === "string" && (envVal === "" || /KEY|TOKEN|SECRET|AUTH/i.test(envKey))) {
        registerVar({ name: envKey, required: true, description: `Environment variable for MCP server "${key}".` });
      }
    }

    if (cfg.oauth || cfg.auth?.type === "oauth") {
      oauthProviders.add(cfg.oauth?.provider || cfg.auth?.provider || key);
    }

    // Store sanitized descriptor (never persist raw env/headers values into public JSON)
    servers.push({
      name: key,
      runtimeName: `${pluginName}_${key}`,
      transport,
      command: cfg.command || null,
      args: Array.isArray(cfg.args) ? cfg.args : [],
      url: remoteUrl,
    });
  }

  return {
    servers,
    envVars: [...envVarMap.values()],
    oauthProviders: [...oauthProviders].sort(),
  };
}

/**
 * Parse hooks.json:
 * Antigravity maps named hook groups -> event keys (PreToolUse, PostToolUse, SessionStart, etc.)
 * -> array of { matcher, hooks: [{ type: "command"|"prompt", command?, prompt?, timeout? }] }.
 */
async function parseHooksConfig(sandboxDir) {
  const raw = await readJsonIfExists(path.join(sandboxDir, "hooks.json"));
  if (!raw || typeof raw !== "object") {
    return { events: [], commandHooks: [], promptHooks: [] };
  }

  const events = new Set();
  const commandHooks = [];
  const promptHooks = [];

  const collectEventMap = (groupName, eventMap, groupEnabled = true) => {
    if (!eventMap || typeof eventMap !== "object") return;
    for (const [eventName, rules] of Object.entries(eventMap)) {
      if (!HOOK_EVENTS.has(eventName) || !Array.isArray(rules)) continue;
      events.add(eventName);

      for (const rule of rules) {
        const matcher = typeof rule?.matcher === "string" ? rule.matcher : "*";
        const handlers = Array.isArray(rule?.hooks) ? rule.hooks : [];

        for (const h of handlers) {
          if (!h || typeof h !== "object") continue;
          const record = {
            group: groupName,
            enabledByDefault: groupEnabled,
            event: eventName,
            matcher,
            type: h.type || (h.command ? "command" : "prompt"),
            command: typeof h.command === "string" ? h.command : null,
            prompt: typeof h.prompt === "string" ? h.prompt.slice(0, 240) : null,
            timeout: typeof h.timeout === "number" ? h.timeout : null,
          };

          if (record.type === "command" || record.command) {
            commandHooks.push(record);
          } else {
            promptHooks.push(record);
          }
        }
      }
    }
  };

  for (const [topKey, topVal] of Object.entries(raw)) {
    if (topKey === "$schema" || topKey === "version") continue;
    if (HOOK_EVENTS.has(topKey)) {
      collectEventMap("default", { [topKey]: topVal }, true);
    } else if (topKey === "hooks" && topVal && typeof topVal === "object") {
      collectEventMap("default", topVal, true);
    } else if (topVal && typeof topVal === "object") {
      collectEventMap(topKey, topVal, topVal.enabled !== false);
    }
  }

  return {
    events: [...events].sort(),
    commandHooks,
    promptHooks,
  };
}

/**
 * Parse one-level skills/<folder>/SKILL.md files and extract frontmatter + slash commands.
 */
async function parseSkills(sandboxDir, files) {
  const skillFiles = files.filter((f) => /^skills\/[^/]+\/SKILL\.md$/i.test(f));
  const skills = [];

  for (const relPath of skillFiles) {
    const folderName = relPath.split("/")[1];
    const content = await fs.readFile(path.join(sandboxDir, ...relPath.split("/")), "utf8");
    const { data } = parseFrontmatter(content);

    const skillName =
      typeof data.name === "string" && data.name.trim() ? data.name.trim() : folderName;
    const slashCommand = skillName.startsWith("/") ? skillName : `/${skillName}`;

    skills.push({
      name: skillName,
      slashCommand,
      description: typeof data.description === "string" ? data.description.slice(0, 240) : "",
      disableModelInvocation: data["disable-model-invocation"] === true,
      file: relPath,
    });
  }

  return skills;
}

/**
 * Parse custom agents/subagents (agents/*.md or agents/<folder>/agent.md).
 */
async function parseAgents(sandboxDir, files) {
  const agentFiles = files.filter(
    (f) => /^agents\/[^/]+\.md$/i.test(f) || /^agents\/[^/]+\/agent\.md$/i.test(f)
  );
  const agents = [];

  for (const relPath of agentFiles) {
    const content = await fs.readFile(path.join(sandboxDir, ...relPath.split("/")), "utf8");
    const { data } = parseFrontmatter(content);
    const parts = relPath.split("/");
    const fallbackName =
      parts.length === 3 ? parts[1] : parts[1].replace(/\.md$/i, "");

    agents.push({
      name: typeof data.name === "string" && data.name.trim() ? data.name.trim() : fallbackName,
      description: typeof data.description === "string" ? data.description.slice(0, 240) : "",
      mainAgent: data.mainAgent !== false,
      subagent: data.subagent !== false,
      file: relPath,
    });
  }

  return agents;
}

/**
 * Validate an extracted plugin repository and parse all Antigravity App components.
 */
export async function validateAndParsePlugin(
  sandboxDir,
  files,
  repo,
  { topic = "agy-plugin", maxReadmeBytes = 32 * 1024 } = {}
) {
  if (!sandboxDir || !Array.isArray(files) || !repo) {
    throw new Error("validateAndParsePlugin requires sandboxDir, files array, and repo metadata.");
  }

  // 1. Respect author opt-out marker
  if (await fileExists(path.join(sandboxDir, ".agy-registry-ignore"))) {
    return { valid: false, reason: "Author opted out via .agy-registry-ignore" };
  }

  // 2. Locate Antigravity plugin manifest (.antigravity-plugin/plugin.json takes precedence)
  const candidatePaths = [".antigravity-plugin/plugin.json", "plugin.json"];
  let manifestPath = null;
  let manifest = null;

  for (const rel of candidatePaths) {
    const parsed = await readJsonIfExists(path.join(sandboxDir, ...rel.split("/")));
    if (parsed && typeof parsed === "object") {
      manifestPath = rel;
      manifest = parsed;
      break;
    }
  }

  if (!manifest) {
    const pkg = await readJsonIfExists(path.join(sandboxDir, "package.json")).catch(() => null);
    if (pkg?.engines?.vscode) {
      return { valid: false, reason: "VS Code / IDE extension (engines.vscode), not an Antigravity App plugin" };
    }
    return { valid: false, reason: "Missing plugin.json or .antigravity-plugin/plugin.json" };
  }

  // 3. Validate required plugin.json identity fields
  if (typeof manifest.name !== "string" || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(manifest.name.trim())) {
    return { valid: false, reason: "Manifest field 'name' must be a valid lowercase identifier" };
  }
  if (typeof manifest.version !== "string" || !SEMVER_RE.test(manifest.version)) {
    return { valid: false, reason: "Manifest missing valid semver field: version" };
  }
  if (
    manifest.minAppVersion !== undefined &&
    manifest.minAppVersion !== null &&
    manifest.minAppVersion !== "" &&
    (typeof manifest.minAppVersion !== "string" || !SEMVER_RE.test(manifest.minAppVersion))
  ) {
    return { valid: false, reason: "Manifest field 'minAppVersion' must be a valid semver string" };
  }

  const pluginName = manifest.name.trim();
  const displayName =
    typeof manifest.displayName === "string" && manifest.displayName.trim()
      ? manifest.displayName.trim()
      : pluginName;

  // 4. Parse all standard Antigravity plugin components
  const [mcp, hooks, skills, agents] = await Promise.all([
    parseMcpConfig(sandboxDir, pluginName),
    parseHooksConfig(sandboxDir),
    parseSkills(sandboxDir, files),
    parseAgents(sandboxDir, files),
  ]);

  const ruleFiles = files.filter(
    (f) => /^rules\/[^/]+\.md$/i.test(f) || /^(AGENTS|GEMINI)\.md$/i.test(f)
  );

  // Reject empty shell repos that have a plugin.json but ship zero Antigravity components
  const components = new Set();
  if (skills.length > 0) components.add("skills");
  if (ruleFiles.length > 0) components.add("rules");
  if (agents.length > 0) components.add("agents");
  if (hooks.events.length > 0) components.add("hooks");
  if (mcp.servers.some((s) => s.transport === "stdio")) components.add("mcp_stdio");
  if (mcp.servers.some((s) => s.transport === "http")) components.add("mcp_remote");

  if (components.size === 0) {
    return {
      valid: false,
      reason: "Plugin manifest found, but repo contains no skills, rules, agents, hooks.json, or mcp_config.json",
    };
  }

  // 5. Detect Antigravity App MCP UI slots (`com.google.antigravity/ui`)
  const uiSlots = new Set();
  for (const f of files) {
    if (!/\.(json|js|mjs|cjs|ts)$/i.test(f) || f.startsWith("node_modules/")) continue;
    const text = await fs.readFile(path.join(sandboxDir, ...f.split("/")), "utf8").catch(() => "");
    if (text.includes("com.google.antigravity/ui")) {
      if (text.includes("global")) uiSlots.add("global");
      if (text.includes("aux_pane")) uiSlots.add("aux_pane");
      if (text.includes("file")) uiSlots.add("file");
      if (uiSlots.size === 0) uiSlots.add("aux_pane");
    }
  }

  // 6. Categories & tags (prefer manifest keywords/category + GitHub agy-cat-* topics)
  const toNonEmptyStrings = (arr) =>
    arr
      .filter((v) => typeof v === "string")
      .map((v) => v.trim())
      .filter((v) => v.length > 0);

  const topics = Array.isArray(repo.topics) ? toNonEmptyStrings(repo.topics) : [];
  const topicCategories = topics
    .filter((t) => t.startsWith("agy-cat-"))
    .map((t) => t.slice("agy-cat-".length))
    .filter((c) => c.length > 0);

  const manifestCategories = toNonEmptyStrings([
    ...(typeof manifest.category === "string" ? [manifest.category] : []),
    ...(Array.isArray(manifest.categories) ? manifest.categories : []),
  ]);
  const categories = [...new Set([...manifestCategories, ...topicCategories].map((c) => c.toLowerCase()))].slice(0, 5);

  const manifestKeywords = Array.isArray(manifest.keywords) ? toNonEmptyStrings(manifest.keywords) : [];
  const tags = [
    ...new Set([
      ...manifestKeywords,
      ...topics.filter((t) => t !== topic && !t.startsWith("agy-cat-")),
    ]),
  ].slice(0, 10);

  // 7. Read pre-install README (.antigravity-plugin/README.md takes precedence over root README.md)
  let readmeMarkdown = "";
  const readmeFile =
    files.find((f) => /^\.antigravity-plugin\/readme\.md$/i.test(f)) ||
    files.find((f) => /^readme\.md$/i.test(f));
  if (readmeFile) {
    const rawReadme = await fs.readFile(path.join(sandboxDir, ...readmeFile.split("/")), "utf8");
    readmeMarkdown = rawReadme.slice(0, maxReadmeBytes);
  }

  return {
    valid: true,
    manifestPath,
    manifest,
    pluginName,
    displayName,
    mcpServers: mcp.servers,
    hooks,
    skills,
    agents,
    ruleFiles,
    surface: {
      hasSidebarUi: uiSlots.size > 0,
      uiSlots: [...uiSlots].sort(),
      components: [...components].sort(),
    },
    collisions: {
      slashCommands: [...new Set(skills.map((s) => s.slashCommand))].sort(),
      mcpServerNames: [...new Set(mcp.servers.map((s) => s.runtimeName))].sort(),
      agentNames: [...new Set(agents.map((a) => a.name))].sort(),
      hookEvents: hooks.events,
    },
    credentials: {
      envVars: mcp.envVars,
      oauthProviders: mcp.oauthProviders,
    },
    categories,
    tags,
    readmeMarkdown,
  };
}
