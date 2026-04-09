/**
 * skillscan-trace CF Worker
 *
 * Routes:
 *   POST /v1/submit          — rate-limit, R2 cache check, proxy to Fly
 *   GET  /v1/status/:job_id  — proxy status poll to Fly
 *   GET  /v1/health          — proxy to Fly
 *   GET  /report/:cache_key       — serve report JSON from R2
 *   GET  /report/:cache_key.html  — serve self-contained HTML report
 *   GET  /report/:cache_key.json  — serve report JSON from R2
 *
 * Bindings (wrangler.toml):
 *   env.TRACE_REPORTS  — R2 bucket
 *   env.RATE_LIMIT     — KV namespace
 *   env.FLY_APP_URL    — Fly app base URL
 */

const RATE_LIMIT_PER_MINUTE = 20;
const CORS_ORIGIN = "https://skillscan.sh";
const MAX_ZIP_SIZE = 2097152; // 2MB

// ── CORS helpers ──────────────────────────────────────────────────────────────

function corsHeaders(origin) {
  const allowed = [
    "https://skillscan.sh",
    "https://www.skillscan.sh",
    "http://localhost:5173",
    "http://localhost:3000",
  ];
  const allowOrigin = allowed.includes(origin) ? origin : CORS_ORIGIN;
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
  };
}

function json(data, status = 200, origin = "") {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders(origin),
    },
  });
}

// ── Rate limiting (CF KV, sliding window per IP) ──────────────────────────────

async function checkRateLimit(env, ip) {
  const key = `rl:${ip}`;
  const now = Date.now();
  const windowMs = 60_000; // 1 minute window

  let timestamps = [];
  try {
    const stored = await env.RATE_LIMIT.get(key);
    if (stored) timestamps = JSON.parse(stored);
  } catch {}

  timestamps = timestamps.filter((t) => now - t < windowMs);

  if (timestamps.length >= RATE_LIMIT_PER_MINUTE) {
    return false;
  }

  timestamps.push(now);
  await env.RATE_LIMIT.put(key, JSON.stringify(timestamps), {
    expirationTtl: 120, // 2 min TTL, covers the window
  });
  return true;
}

// ── SHA256 helper ─────────────────────────────────────────────────────────────

async function sha256(text) {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text)
  );
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ── R2 cache lookup ───────────────────────────────────────────────────────────

async function r2CacheGet(env, cacheKey) {
  try {
    const obj = await env.TRACE_REPORTS.get(`reports/${cacheKey}.json`);
    if (!obj) return null;
    return JSON.parse(await obj.text());
  } catch {
    return null;
  }
}

// ── Sibling file resolution ──────────────────────────────────────────────────

const SIBLING_MAX_FILES = 10;
const SIBLING_MAX_TOTAL_BYTES = 2 * 1024 * 1024; // 2MB
const SIBLING_ALLOWED_EXTENSIONS = new Set([".md", ".txt", ".yaml", ".yml", ".json"]);

/**
 * Extract relative file references from skill content.
 * Looks for:
 *   - Markdown links: [text](./file.md) or [text](../path/file.md)
 *   - @import directives: @import ./file.md
 *   - Bare relative paths: ./filename.md, ../path/file.yaml
 * Returns deduplicated array of relative paths.
 */
function extractRelativeRefs(content) {
  const refs = new Set();

  // Markdown links with relative paths: [text](./path) or [text](../path)
  const mdLinkRe = /\[[^\]]*\]\((\.\.[^\)]*|\.\/[^\)]*)\)/g;
  let m;
  while ((m = mdLinkRe.exec(content)) !== null) {
    refs.add(m[1].trim());
  }

  // @import directives
  const importRe = /@import\s+(\.\.?\/[^\s]+)/g;
  while ((m = importRe.exec(content)) !== null) {
    refs.add(m[1].trim());
  }

  // Bare relative paths (./foo.ext or ../foo/bar.ext) not already captured
  // Match paths starting with ./ or ../ followed by path chars, ending with an extension
  const bareRe = /(?:^|[\s"'`(,])(\.\.[\/\\][^\s"'`),]+|\.\/[^\s"'`),]+)/gm;
  while ((m = bareRe.exec(content)) !== null) {
    refs.add(m[1].trim());
  }

  return [...refs];
}

/**
 * Resolve a relative path against a base URL path.
 * e.g. base = "https://raw.githubusercontent.com/org/repo/main/skills/my-skill/SKILL.md"
 *      rel  = "./helpers.md"
 *   => "https://raw.githubusercontent.com/org/repo/main/skills/my-skill/helpers.md"
 */
function resolveRelativeUrl(baseUrl, relativePath) {
  const base = new URL(baseUrl);
  // Get directory of the base file
  const lastSlash = base.pathname.lastIndexOf("/");
  const baseDir = base.pathname.substring(0, lastSlash + 1);

  // Resolve the relative path
  const parts = (baseDir + relativePath).split("/");
  const resolved = [];
  for (const part of parts) {
    if (part === "." || part === "") continue;
    if (part === "..") {
      resolved.pop();
    } else {
      resolved.push(part);
    }
  }

  base.pathname = "/" + resolved.join("/");
  return base.toString();
}

/**
 * Check if a filename has an allowed extension for sibling fetching.
 */
function hasAllowedExtension(path) {
  const lower = path.toLowerCase();
  for (const ext of SIBLING_ALLOWED_EXTENSIONS) {
    if (lower.endsWith(ext)) return true;
  }
  return false;
}

/**
 * Extract the filename from a path (last component).
 */
function filenameFromPath(path) {
  const parts = path.replace(/\\/g, "/").split("/");
  return parts[parts.length - 1];
}

/**
 * Given a source_url and skill content, find and fetch sibling files.
 * Returns a dict of { filename: content } or null if none found / errors.
 */
async function fetchSiblingFiles(sourceUrl, skillContent) {
  const refs = extractRelativeRefs(skillContent);
  if (refs.length === 0) return null;

  const baseHost = new URL(sourceUrl).hostname;
  const files = {};
  let totalBytes = 0;
  let fetchCount = 0;

  for (const ref of refs) {
    if (fetchCount >= SIBLING_MAX_FILES) break;
    if (!hasAllowedExtension(ref)) continue;

    let resolvedUrl;
    try {
      resolvedUrl = resolveRelativeUrl(sourceUrl, ref);
    } catch {
      continue;
    }

    // Same-host restriction
    try {
      const resolved = new URL(resolvedUrl);
      if (resolved.hostname !== baseHost) continue;
    } catch {
      continue;
    }

    try {
      const resp = await fetch(resolvedUrl, {
        headers: { "User-Agent": "skillscan-trace-worker/1.0" },
        redirect: "follow",
      });
      if (!resp.ok) continue;

      const text = await resp.text();
      const byteLen = new TextEncoder().encode(text).length;

      if (totalBytes + byteLen > SIBLING_MAX_TOTAL_BYTES) continue;

      totalBytes += byteLen;
      fetchCount++;

      const filename = filenameFromPath(ref);
      // If there's a collision, use the full relative path (slashes replaced)
      const key = files[filename] !== undefined
        ? ref.replace(/[\/\\]/g, "_").replace(/^[._]+/, "")
        : filename;
      files[key] = text;
    } catch {
      // Graceful fallback: skip this file
      continue;
    }
  }

  return Object.keys(files).length > 0 ? files : null;
}

// ── Route handlers ────────────────────────────────────────────────────────────

async function handleSubmit(request, env) {
  const origin = request.headers.get("Origin") || "";
  const ip =
    request.headers.get("CF-Connecting-IP") ||
    request.headers.get("X-Forwarded-For") ||
    "unknown";

  // Rate limit (skip if force_fresh — testing convenience)
  const skipRateLimit = Boolean(body.force_fresh);
  const allowed = skipRateLimit || await checkRateLimit(env, ip);
  if (!allowed) {
    return json(
      {
        error: `Rate limit exceeded: ${RATE_LIMIT_PER_MINUTE} new traces per minute. Cached results don't count against this limit.`,
      },
      429,
      origin
    );
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON body" }, 400, origin);
  }

  const MAX_SKILL_SIZE = 524288; // 512KB

  // ── ZIP upload path ──────────────────────────────────────────────────────────
  // If a ZIP is provided, validate size and forward directly to Fly (skip R2 cache).
  if (body.skill_zip_b64) {
    let zipBytes;
    try {
      const binStr = atob(body.skill_zip_b64);
      zipBytes = binStr.length;
    } catch {
      return json({ error: "Invalid base64 in skill_zip_b64." }, 400, origin);
    }
    if (zipBytes > MAX_ZIP_SIZE) {
      return json(
        { error: `ZIP exceeds maximum size of 2MB (${MAX_ZIP_SIZE} bytes). Got ${zipBytes} bytes.` },
        413,
        origin
      );
    }
    // Forward to Fly as-is — Fly handles extraction
    const flyUrl = `${env.FLY_APP_URL}/v1/submit`;
    let flyResp;
    try {
      flyResp = await fetch(flyUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
    } catch (e) {
      return json({ error: `Trace service unreachable: ${e.message}` }, 503, origin);
    }
    const flyData = await flyResp.json();
    return json(flyData, flyResp.status, origin);
  }

  // ── Single-file path ─────────────────────────────────────────────────────────

  let skillContent = (body.skill_content || "").trim();
  const model = body.model || "gpt-4.1-mini";

  // Size check on inline skill_content
  if (skillContent && new TextEncoder().encode(skillContent).length > MAX_SKILL_SIZE) {
    return json(
      { error: `skill_content exceeds maximum size of 512KB (${MAX_SKILL_SIZE} bytes).` },
      413,
      origin
    );
  }

  // If skill_content is empty but source_url is provided, fetch it server-side
  // (browsers can't fetch raw.githubusercontent.com due to CORS)
  if (!skillContent && body.source_url) {
    try {
      const srcResp = await fetch(body.source_url, {
        headers: { "User-Agent": "skillscan-trace-worker/1.0" },
        redirect: "follow",
      });
      if (!srcResp.ok) {
        return json(
          { error: `Could not fetch source_url: HTTP ${srcResp.status}` },
          422,
          origin
        );
      }
      skillContent = (await srcResp.text()).trim();

      // Size check on fetched content
      if (new TextEncoder().encode(skillContent).length > MAX_SKILL_SIZE) {
        return json(
          { error: `Content at source_url exceeds maximum size of 512KB (${MAX_SKILL_SIZE} bytes).` },
          413,
          origin
        );
      }

      body.skill_content = skillContent;

      // Resolve and fetch sibling files referenced in the skill content
      try {
        const siblingFiles = await fetchSiblingFiles(body.source_url, skillContent);
        if (siblingFiles) {
          // Determine the main skill filename from the URL
          const urlParts = body.source_url.split("/");
          const mainFilename = urlParts[urlParts.length - 1] || "SKILL.md";
          // Package as skill_files: main file + siblings
          body.skill_files = { [mainFilename]: skillContent, ...siblingFiles };
        }
      } catch {
        // Graceful fallback: if sibling resolution fails, just use skill_content
      }
    } catch (e) {
      return json({ error: `Could not fetch source_url: ${e.message}` }, 422, origin);
    }
  }

  if (!skillContent) {
    return json({ error: "skill_content or source_url is required" }, 400, origin);
  }

  // R2 cache check (skip if force_fresh)
  const forceFresh = Boolean(body.force_fresh);
  const cacheKey = await sha256(`${skillContent}::${model}`);
  const cached = forceFresh ? null : await r2CacheGet(env, cacheKey);
  if (cached) {
    return json(
      {
        status: "done",
        cached: true,
        job_id: cacheKey,
        report_url: cached.report_url || `https://trace.skillscan.sh/report/${cacheKey}`,
        result: cached,
      },
      200,
      origin
    );
  }

  // Forward to Fly — api_key goes directly to Fly, never stored here
  const flyUrl = `${env.FLY_APP_URL}/v1/submit`;
  let flyResp;
  try {
    flyResp = await fetch(flyUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (e) {
    return json({ error: `Trace service unreachable: ${e.message}` }, 503, origin);
  }

  const flyData = await flyResp.json();
  return json(flyData, flyResp.status, origin);
}

async function handleStatus(request, env, jobId) {
  const origin = request.headers.get("Origin") || "";

  // Forward status poll to Fly
  const flyUrl = `${env.FLY_APP_URL}/v1/report/${jobId}`;
  let flyResp;
  try {
    flyResp = await fetch(flyUrl);
  } catch (e) {
    return json({ error: `Trace service unreachable: ${e.message}` }, 503, origin);
  }

  const flyData = await flyResp.json();
  return json(flyData, flyResp.status, origin);
}

async function handleReportGet(request, env, cacheKey) {
  const origin = request.headers.get("Origin") || "";

  const report = await r2CacheGet(env, cacheKey);
  if (!report) {
    return json({ error: "Report not found or expired" }, 404, origin);
  }
  return json(report, 200, origin);
}

async function handleReportHtml(request, env, cacheKey) {
  const report = await r2CacheGet(env, cacheKey);
  if (!report) {
    return new Response(
      `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Not Found</title></head>` +
      `<body style="background:oklch(0.16 0.02 260);color:#e2e8f0;font-family:system-ui;display:flex;` +
      `align-items:center;justify-content:center;min-height:100vh;margin:0;">` +
      `<h1>Report not found or expired</h1></body></html>`,
      { status: 404, headers: { "Content-Type": "text/html; charset=utf-8" } }
    );
  }

  const esc = (s) =>
    String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");

  const r = report;
  const verdict = (r.verdict || "UNKNOWN").toUpperCase();
  const skillName = r.skill_name || r.skill_file || "Unknown Skill";
  const model = r.model || "unknown";
  const duration =
    r.duration_seconds != null ? r.duration_seconds.toFixed(1) + "s" : "n/a";
  const toolCalls = Array.isArray(r.tool_calls) ? r.tool_calls : [];
  const findings = Array.isArray(r.findings) ? r.findings : [];
  const events = Array.isArray(r.events) ? r.events : [];
  const userMessages = Array.isArray(r.user_messages) ? r.user_messages : [];
  const provenance = r.provenance || {};

  const verdictColors = {
    PASS: "#22c55e",
    BLOCK: "#ef4444",
    WARN: "#eab308",
    ERROR: "#f97316",
  };
  const vc = verdictColors[verdict] || "#94a3b8";

  // ── Findings section ─────────────────────────────────────────────────────
  const findingsHtml =
    findings.length === 0
      ? `<p class="muted">No findings.</p>`
      : findings
          .map((f) => {
            const sev = (f.severity || "info").toLowerCase();
            const isHigh = sev === "critical" || sev === "high";
            const isMed = sev === "medium";
            const borderColor = isHigh ? "#ef4444" : isMed ? "#eab308" : "#475569";
            const badgeBg = isHigh ? "#7f1d1d" : isMed ? "#713f12" : "#334155";
            const badgeFg = isHigh ? "#fca5a5" : isMed ? "#fde68a" : "#cbd5e1";
            return `<div class="card" style="border-left:4px solid ${borderColor}">
              <div style="display:flex;gap:12px;align-items:center;margin-bottom:8px">
                <span style="background:${badgeBg};color:${badgeFg};padding:2px 10px;border-radius:9999px;font-size:12px;font-weight:600;text-transform:uppercase">${esc(sev)}</span>
                <code style="color:#93c5fd;font-size:13px">${esc(f.rule_id)}</code>
              </div>
              <p style="margin:0 0 6px">${esc(f.message)}</p>
              ${f.evidence ? `<pre class="pre-block" style="color:#a5b4fc">${esc(f.evidence)}</pre>` : ""}
            </div>`;
          })
          .join("");

  // ── Events timeline ──────────────────────────────────────────────────────
  const eventsHtml =
    events.length === 0
      ? `<p class="muted">No events recorded.</p>`
      : events
          .map((ev) => {
            const label = ev.tool || ev.type || ev.event || "event";
            const argStr =
              ev.arguments != null
                ? typeof ev.arguments === "string"
                  ? ev.arguments
                  : JSON.stringify(ev.arguments, null, 2)
                : null;
            const resStr =
              ev.result != null
                ? typeof ev.result === "string"
                  ? ev.result
                  : JSON.stringify(ev.result, null, 2)
                : null;
            return `<div class="card" style="padding:12px 16px">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
                <span style="color:#93c5fd;font-weight:600;font-size:14px">${esc(label)}</span>
                ${ev.timestamp ? `<span style="color:#64748b;font-size:12px">${esc(ev.timestamp)}</span>` : ""}
              </div>
              ${argStr != null ? `<pre class="pre-block">${esc(argStr)}</pre>` : ""}
              ${resStr != null ? `<pre class="pre-block" style="color:#86efac">${esc(resStr)}</pre>` : ""}
            </div>`;
          })
          .join("");

  // ── User messages ────────────────────────────────────────────────────────
  const userMsgHtml =
    userMessages.length === 0
      ? ""
      : `<section>
          <h2>User Messages</h2>
          ${userMessages
            .map((m) => {
              const text = typeof m === "string" ? m : m.content || JSON.stringify(m);
              return `<div class="card" style="padding:12px 16px">
                <p style="margin:0;white-space:pre-wrap">${esc(text)}</p>
              </div>`;
            })
            .join("")}
        </section>`;

  // ── Provenance ───────────────────────────────────────────────────────────
  const provKeys = Object.keys(provenance);
  const provenanceHtml =
    provKeys.length === 0
      ? ""
      : `<section>
          <h2>Provenance</h2>
          <div class="card" style="padding:16px">
            <dl style="margin:0;display:grid;grid-template-columns:max-content 1fr;gap:6px 16px">
              ${provKeys
                .map(
                  (k) =>
                    `<dt style="color:#94a3b8;font-size:13px;font-weight:600">${esc(k)}</dt>` +
                    `<dd style="margin:0;color:#cbd5e1;font-size:13px;word-break:break-all">${esc(
                      typeof provenance[k] === "string" ? provenance[k] : JSON.stringify(provenance[k])
                    )}</dd>`
                )
                .join("")}
            </dl>
          </div>
        </section>`;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Trace Report \u2014 ${esc(skillName)}</title>
<style>
*,*::before,*::after{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;background:oklch(0.16 0.02 260);color:#e2e8f0;line-height:1.6}
a{color:#93c5fd;text-decoration:none}
a:hover{text-decoration:underline}
pre,code{font-family:"SF Mono","Fira Code","Fira Mono",Menlo,Consolas,monospace}
h2{color:#e2e8f0;font-size:18px;margin:32px 0 12px}
.wrap{max-width:860px;margin:0 auto;padding:24px 16px 64px}
.muted{color:#94a3b8}
.card{background:oklch(0.22 0.02 260);border-radius:8px;padding:16px;margin-bottom:10px}
.pre-block{margin:4px 0 0;padding:10px;background:oklch(0.18 0.02 260);border-radius:4px;overflow-x:auto;color:#cbd5e1;font-size:12px}
.badge{display:inline-block;padding:6px 20px;border-radius:9999px;font-size:16px;font-weight:700}
.stat-label{color:#64748b;font-size:12px;text-transform:uppercase;letter-spacing:0.05em}
.stat-value{color:#cbd5e1;font-size:14px}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:32px;flex-wrap:wrap;gap:12px}
.header-links{display:flex;gap:12px}
.header-links a{padding:8px 16px;border-radius:6px;font-size:13px;font-weight:600}
.summary{background:oklch(0.20 0.02 260);border-radius:12px;padding:24px;margin-bottom:24px}
.stats{display:flex;flex-wrap:wrap;gap:24px;margin-top:16px}
footer{margin-top:48px;padding-top:24px;border-top:1px solid oklch(0.25 0.02 260);text-align:center}
footer p{color:#475569;font-size:13px}
</style>
</head>
<body>
<div class="wrap">

  <header class="header">
    <div>
      <h1 style="margin:0;font-size:24px;color:#f1f5f9">SkillScan Trace Report</h1>
      <p style="margin:4px 0 0;color:#64748b;font-size:14px">Behavioral execution trace</p>
    </div>
    <div class="header-links">
      <a href="/report/${esc(cacheKey)}.json" style="background:oklch(0.25 0.02 260);color:#93c5fd">View JSON</a>
      <a href="https://skillscan.sh/trace/run" style="background:oklch(0.30 0.06 260);color:#c4b5fd">Run on SkillScan</a>
    </div>
  </header>

  <section class="summary">
    <div style="display:flex;flex-wrap:wrap;gap:16px;align-items:center">
      <span class="badge" style="background:${vc}22;color:${vc};border:2px solid ${vc}">${verdict}</span>
      <h2 style="margin:0;font-size:20px;color:#f1f5f9">${esc(skillName)}</h2>
    </div>
    <div class="stats">
      <div><span class="stat-label">Model</span><br><span class="stat-value">${esc(model)}</span></div>
      <div><span class="stat-label">Duration</span><br><span class="stat-value">${esc(duration)}</span></div>
      <div><span class="stat-label">Tool Calls</span><br><span class="stat-value">${toolCalls.length}</span></div>
      <div><span class="stat-label">Findings</span><br><span class="stat-value">${findings.length}</span></div>
    </div>
  </section>

  <section>
    <h2>Findings</h2>
    ${findingsHtml}
  </section>

  <section>
    <h2>Event Timeline</h2>
    ${eventsHtml}
  </section>

  ${userMsgHtml}
  ${provenanceHtml}

  <footer>
    <p>Generated by <a href="https://skillscan.sh">SkillScan Trace</a></p>
  </footer>

</div>
<script>
// Embed raw report JSON for client-side use
window.__TRACE_REPORT__ = ${JSON.stringify(report).replace(/</g, "\\u003c")};
</script>
</body>
</html>`;

  return new Response(html, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "public, max-age=3600",
    },
  });
}

async function handleHealth(env) {
  try {
    const resp = await fetch(`${env.FLY_APP_URL}/v1/health`, {
      signal: AbortSignal.timeout(5000),
    });
    const data = await resp.json();
    return new Response(JSON.stringify({ worker: "ok", fly: data }), {
      headers: { "Content-Type": "application/json" },
    });
  } catch {
    return new Response(JSON.stringify({ worker: "ok", fly: "unreachable" }), {
      status: 207,
      headers: { "Content-Type": "application/json" },
    });
  }
}

// ── Main fetch handler ────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname } = url;
    const method = request.method;
    const origin = request.headers.get("Origin") || "";

    // CORS preflight
    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    if (method === "POST" && pathname === "/v1/submit") {
      return handleSubmit(request, env);
    }

    if (method === "GET" && pathname.startsWith("/v1/status/")) {
      const jobId = pathname.slice("/v1/status/".length);
      return handleStatus(request, env, jobId);
    }

    if (method === "GET" && pathname.startsWith("/report/")) {
      let cacheKey = pathname.slice("/report/".length);
      // Serve HTML permalink
      if (cacheKey.endsWith(".html")) {
        cacheKey = cacheKey.slice(0, -5);
        return handleReportHtml(request, env, cacheKey);
      }
      // Support /report/{key}.json — strip .json extension
      if (cacheKey.endsWith(".json")) {
        cacheKey = cacheKey.slice(0, -5);
      }
      return handleReportGet(request, env, cacheKey);
    }

    if (method === "GET" && pathname === "/v1/health") {
      return handleHealth(env);
    }

    return json({ error: "Not found" }, 404, origin);
  },
};
