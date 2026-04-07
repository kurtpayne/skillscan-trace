/**
 * skillscan-trace CF Worker
 *
 * Routes:
 *   POST /v1/submit          — rate-limit, R2 cache check, proxy to Fly
 *   GET  /v1/status/:job_id  — proxy status poll to Fly
 *   GET  /v1/health          — proxy to Fly
 *   GET  /report/:cache_key  — serve report JSON from R2
 *
 * Bindings (wrangler.toml):
 *   env.TRACE_REPORTS  — R2 bucket
 *   env.RATE_LIMIT     — KV namespace
 *   env.FLY_APP_URL    — Fly app base URL
 */

const RATE_LIMIT_PER_MINUTE = 5;
const CORS_ORIGIN = "https://skillscan.sh";

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

// ── Route handlers ────────────────────────────────────────────────────────────

async function handleSubmit(request, env) {
  const origin = request.headers.get("Origin") || "";
  const ip =
    request.headers.get("CF-Connecting-IP") ||
    request.headers.get("X-Forwarded-For") ||
    "unknown";

  // Rate limit
  const allowed = await checkRateLimit(env, ip);
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

  let skillContent = (body.skill_content || "").trim();
  const model = body.model || "gpt-4.1-mini";

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
      body.skill_content = skillContent;
    } catch (e) {
      return json({ error: `Could not fetch source_url: ${e.message}` }, 422, origin);
    }
  }

  if (!skillContent) {
    return json({ error: "skill_content or source_url is required" }, 400, origin);
  }

  // R2 cache check
  const cacheKey = await sha256(`${skillContent}::${model}`);
  const cached = await r2CacheGet(env, cacheKey);
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
      const cacheKey = pathname.slice("/report/".length);
      return handleReportGet(request, env, cacheKey);
    }

    if (method === "GET" && pathname === "/v1/health") {
      return handleHealth(env);
    }

    return json({ error: "Not found" }, 404, origin);
  },
};
