import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { escapeHtml, renderMarkdown, resolveSafeUrl } from "../site/markdown.js";

const REPO_URL = "https://github.com/acme/sample-plugin";
const TEST_SHA = "1234567890abcdef1234567890abcdef12345678";

describe("site/markdown.js — XSS-safe zero-dependency Markdown renderer", () => {
  it("validates entry arguments and normalizes NUL bytes and line endings", () => {
    assert.equal(renderMarkdown(null), "");
    assert.equal(renderMarkdown(undefined), "");
    assert.equal(renderMarkdown(""), "");

    assert.throws(
      () => renderMarkdown("hi", { linkMode: "raw" }),
      { name: "TypeError", message: /Invalid linkMode/ }
    );
    assert.throws(
      () => renderMarkdown(123),
      { name: "TypeError", message: /requires markdown to be a string/ }
    );

    const html = renderMarkdown("Line\0 one\r\nLine two\r\r###   ", { linkMode: "anchor" });
    assert.equal(html.includes("\0"), false);
    assert.match(html, /<p>Line one Line two<\/p>/);
    assert.match(html, /<p>###<\/p>/);
  });

  it("renders headings, fenced code blocks (including unclosed EOF), HRs, blockquotes, lists, and paragraphs", () => {
    const md = [
      "# Title",
      "###### Deep Heading",
      "",
      "---",
      "",
      "> Quoted **text**",
      "> Second line",
      "",
      "- Alpha",
      "* Beta",
      "",
      "1. First",
      "2) Second",
      "",
      "```js",
      "const x = '<script>';",
      "```",
      "",
      "~~~",
      "unclosed fence at EOF",
    ].join("\n");

    const html = renderMarkdown(md);
    assert.match(html, /<h1>Title<\/h1>/);
    assert.match(html, /<h6>Deep Heading<\/h6>/);
    assert.match(html, /<hr \/>/);
    assert.match(html, /<blockquote><p>Quoted <strong>text<\/strong> Second line<\/p><\/blockquote>/);
    assert.match(html, /<ul><li>Alpha<\/li><li>Beta<\/li><\/ul>/);
    assert.match(html, /<ol><li>First<\/li><li>Second<\/li><\/ol>/);
    assert.match(html, /<pre><code class="language-js">const x = &#39;&lt;script&gt;&#39;;<\/code><\/pre>/);
    assert.match(html, /<pre><code>unclosed fence at EOF<\/code><\/pre>/);
  });

  it("renders inline code, bold, italic, strikethrough, and bare URLs without corrupting snake_case or URLs", () => {
    const md =
      "Use `snake_case_id` with **bold**, __strong__, *em*, _ital_, ~~old~~, and my_var_name. " +
      "Visit https://example.com/a_b?x=1&y=2.";

    const html = renderMarkdown(md);
    assert.match(html, /<code>snake_case_id<\/code>/);
    assert.match(html, /<strong>bold<\/strong>/);
    assert.match(html, /<strong>strong<\/strong>/);
    assert.match(html, /<em>em<\/em>/);
    assert.match(html, /<em>ital<\/em>/);
    assert.match(html, /<del>old<\/del>/);
    assert.match(html, /my_var_name/);
    assert.match(
      html,
      /<a href="https:\/\/example\.com\/a_b\?x=1&amp;y=2" target="_blank" rel="noopener noreferrer">https:\/\/example\.com\/a_b\?x=1&amp;y=2<\/a>\./
    );
  });

  it("escapes raw HTML before emphasis or auto-linking to block XSS payloads", () => {
    const xss = [
      `<script>alert("xss")</script>`,
      `<img src=x onerror="alert(1)">`,
      `<iframe src="https://evil.example/payload"></iframe>`,
      `[<img src=x onerror=alert(1)>](https://example.com)`,
      `*<script>alert(1)</script>*`,
      "`<svg onload=alert(1)>`",
    ].join("\n\n");

    const html = renderMarkdown(xss);
    assert.doesNotMatch(html, /<(?:script|img|iframe|svg)\b/i);
    assert.match(html, /&lt;script&gt;alert\(&quot;xss&quot;\)&lt;\/script&gt;/);
    assert.match(html, /&lt;img src=x onerror=&quot;alert\(1\)&quot;&gt;/);
    assert.match(html, /https:\/\/evil\.example\/payload/);
  });

  it("blocks dangerous URL schemes and protocol-relative URLs in links, images, and badges", () => {
    const badUrls = [
      "javascript:alert(1)",
      "JAVASCRIPT:alert(1)",
      "java\tscript:alert(1)",
      "data:text/html,<script>alert(1)</script>",
      "vbscript:msgbox(1)",
      "file:///etc/passwd",
      "//evil.example/steal",
      "/root-relative/path",
    ];

    for (const bad of badUrls) {
      assert.equal(resolveSafeUrl(bad, { repoUrl: REPO_URL, sha: TEST_SHA }), null);
      const rendered = renderMarkdown(
        `[Click](${bad}) ![Pic](${bad}) [![Badge](https://img.shields.io/a.svg)](${bad})`,
        { repoUrl: REPO_URL, sha: TEST_SHA }
      );
      assert.doesNotMatch(rendered, /<a\b|<button\b|<img\b/i);
      assert.match(rendered, /Click/);
    }
  });

  it("renders linked badges and standalone images as safe links without emitting <img> tags", () => {
    const md = [
      "[![Build Status](https://img.shields.io/badge/build-passing-green)](https://github.com/acme/sample-plugin/actions)",
      "![Architecture](./docs/arch.png)",
    ].join("\n\n");

    const html = renderMarkdown(md, { repoUrl: REPO_URL, sha: TEST_SHA });
    assert.doesNotMatch(html, /<img\b/i);
    assert.match(
      html,
      /<a href="https:\/\/github\.com\/acme\/sample-plugin\/actions" target="_blank" rel="noopener noreferrer">Build Status<\/a>/
    );
    assert.match(
      html,
      /<a href="https:\/\/github\.com\/acme\/sample-plugin\/blob\/1234567890abcdef1234567890abcdef12345678\/docs\/arch\.png" target="_blank" rel="noopener noreferrer">Architecture<\/a>/
    );
  });

  it("resolves relative ./ paths against commit-SHA blob URLs only on github.com and blocks escapes", () => {
    assert.equal(
      resolveSafeUrl("./docs/guide.md", { repoUrl: REPO_URL, sha: TEST_SHA }),
      `${REPO_URL}/blob/${TEST_SHA}/docs/guide.md`
    );
    assert.equal(
      resolveSafeUrl("CHANGELOG.md", { repoUrl: REPO_URL, sha: TEST_SHA }),
      `${REPO_URL}/blob/${TEST_SHA}/CHANGELOG.md`
    );
    assert.equal(resolveSafeUrl("./docs/guide.md", { repoUrl: "", sha: TEST_SHA }), null);
    assert.equal(resolveSafeUrl("./docs/guide.md", { repoUrl: "https://gitlab.com/a/b", sha: TEST_SHA }), null);
    assert.equal(resolveSafeUrl("../../../other/repo/blob/main/x", { repoUrl: REPO_URL, sha: TEST_SHA }), null);
  });

  it("supports both anchor and button linkMode outputs cleanly", () => {
    const md = "[Open Guide](./README.md) and [External](https://en.wikipedia.org/wiki/Foo_(bar))";

    const anchorHtml = renderMarkdown(md, { linkMode: "anchor", repoUrl: REPO_URL, sha: TEST_SHA });
    assert.match(anchorHtml, /<a href="https:\/\/github\.com\/acme\/sample-plugin\/blob\/[^"]+\/README\.md" target="_blank" rel="noopener noreferrer">Open Guide<\/a>/);
    assert.match(anchorHtml, /<a href="https:\/\/en\.wikipedia\.org\/wiki\/Foo_\(bar\)" target="_blank" rel="noopener noreferrer">External<\/a>/);

    const buttonHtml = renderMarkdown(md, { linkMode: "button", repoUrl: REPO_URL, sha: TEST_SHA });
    assert.doesNotMatch(buttonHtml, /<a\b/);
    assert.match(buttonHtml, /<button type="button" class="md-link" data-external-url="https:\/\/github\.com\/acme\/sample-plugin\/blob\/[^"]+\/README\.md">Open Guide<\/button>/);
    assert.match(buttonHtml, /<button type="button" class="md-link" data-external-url="https:\/\/en\.wikipedia\.org\/wiki\/Foo_\(bar\)">External<\/button>/);
    assert.equal(escapeHtml(`a&b<c>"d"'e'`), "a&amp;b&lt;c&gt;&quot;d&quot;&#39;e&#39;");
  });
});
