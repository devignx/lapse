// Minimal OAuth 2.1 provider for claude.ai custom connectors:
// RFC 8414 metadata discovery, RFC 7591 dynamic client registration,
// authorization code + PKCE (S256), refresh token rotation.
// Public clients only (token_endpoint_auth_method: none) — PKCE is the guard.

import { sha256Hex, randomHex } from "./auth.js";

const enc = new TextEncoder();

const CODE_TTL_MS = 10 * 60 * 1000; // 10 min
const ACCESS_TTL_MS = 24 * 60 * 60 * 1000; // 24 h
const REFRESH_TTL_MS = 90 * 24 * 60 * 60 * 1000; // 90 days

async function sha256Base64url(text) {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(text));
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// ---------- discovery ----------

export function authServerMetadata(origin) {
  return Response.json({
    issuer: origin,
    authorization_endpoint: `${origin}/authorize`,
    token_endpoint: `${origin}/token`,
    registration_endpoint: `${origin}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: ["journal"],
  });
}

export function protectedResourceMetadata(origin) {
  return Response.json({
    resource: origin,
    authorization_servers: [origin],
    bearer_methods_supported: ["header"],
  });
}

// ---------- dynamic client registration ----------

export async function register(request, DB) {
  const body = await request.json().catch(() => null);
  const uris = body?.redirect_uris;
  if (!Array.isArray(uris) || !uris.length || !uris.every((u) => /^https:\/\//.test(u))) {
    return Response.json(
      { error: "invalid_client_metadata", error_description: "redirect_uris must be https URLs" },
      { status: 400 }
    );
  }
  const clientId = "client_" + randomHex(16);
  await DB.prepare(
    "INSERT INTO oauth_clients (client_id, client_name, redirect_uris) VALUES (?, ?, ?)"
  )
    .bind(clientId, String(body.client_name || ""), JSON.stringify(uris))
    .run();
  return Response.json(
    {
      client_id: clientId,
      client_name: body.client_name || "",
      redirect_uris: uris,
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
    },
    { status: 201 }
  );
}

// ---------- /authorize ----------

async function getClient(DB, clientId) {
  const row = await DB.prepare("SELECT * FROM oauth_clients WHERE client_id = ?")
    .bind(clientId)
    .first();
  if (!row) return null;
  return { ...row, redirect_uris: JSON.parse(row.redirect_uris) };
}

function validateAuthorizeParams(params, client) {
  if (!client) return "Unknown client_id. Remove any manually entered client id in Claude's connector settings — registration is automatic.";
  if (params.get("response_type") !== "code") return "response_type must be 'code'";
  const redirect = params.get("redirect_uri");
  if (!client.redirect_uris.includes(redirect)) return "redirect_uri not registered for this client";
  if (!params.get("code_challenge")) return "code_challenge required (PKCE)";
  if ((params.get("code_challenge_method") || "S256") !== "S256") return "only S256 supported";
  return null;
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

function pageShell(inner) {
  return new Response(
    `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Lapse — authorize</title>
  <style>
    :root { --bg:#fff; --fg:#111; --muted:#777; --line:#e5e5e5; --error:#b3261e; }
    @media (prefers-color-scheme: dark) {
      :root { --bg:#121212; --fg:#eaeaea; --muted:#8a8a8a; --line:#2a2a2a; --error:#f2b8b5; }
    }
    * { box-sizing:border-box; margin:0; padding:0; }
    body { font-family:system-ui,sans-serif; background:var(--bg); color:var(--fg);
           min-height:100vh; display:grid; place-items:center; padding:1.5rem; line-height:1.55; }
    .box { width:100%; max-width:340px; }
    h1 { font-size:1.4rem; margin-bottom:.25rem; }
    p.sub { color:var(--muted); margin-bottom:1.25rem; font-size:.95rem; }
    form { display:grid; gap:.6rem; }
    input, button { font:inherit; color:inherit; background:transparent;
                    border:1px solid var(--line); border-radius:4px; padding:.55rem .8rem; }
    button { cursor:pointer; background:var(--fg); color:var(--bg); border-color:var(--fg); }
    .error { color:var(--error); font-size:.9rem; margin-top:.75rem; }
    p.note { color:var(--muted); font-size:.85rem; margin-top:1rem; }
    a { color:var(--fg); }
  </style>
  <style>.btn2{background:transparent;color:var(--fg)}</style>
</head>
<body>
  <div class="box">
    ${inner}
  </div>
</body>
</html>`,
    { headers: { "Content-Type": "text/html; charset=utf-8" } }
  );
}

// Logged in → one-click consent. The form POSTs the OAuth params back to us.
function consentPage(params, user, client) {
  const hidden = ["client_id", "redirect_uri", "code_challenge", "code_challenge_method", "state", "response_type", "scope"]
    .map((k) => `<input type="hidden" name="${k}" value="${esc(params.get(k))}" />`)
    .join("\n        ");
  const appName = client.client_name ? esc(client.client_name) : "This app";
  const cancel = new URL(params.get("redirect_uri"));
  cancel.searchParams.set("error", "access_denied");
  if (params.get("state")) cancel.searchParams.set("state", params.get("state"));
  return pageShell(`
    <h1>Authorize access</h1>
    <p class="sub">${appName} wants to read and write your Lapse journal, as <strong>${esc(user.email)}</strong>.</p>
    <form method="POST" action="/authorize">
        ${hidden}
      <button type="submit">Authorize</button>
    </form>
    <p class="note"><a href="${esc(cancel.toString())}">Cancel</a> · not you? <a href="/" target="_blank">switch account</a></p>`);
}

// Not logged in → we can't authorize. Send them to log in, then retry.
function loginFirstPage(params) {
  const retry = `/authorize?${params.toString()}`;
  return pageShell(`
    <h1>Log in to Lapse</h1>
    <p class="sub">To connect an AI, first log in to your Lapse account in this browser.</p>
    <p><a href="/?auth" target="_blank"><button type="button">Open Lapse login</button></a></p>
    <p class="note">Logged in? <a href="${esc(retry)}">Continue &rarr;</a></p>`);
}

export async function authorizeGet(request, DB, url, user) {
  const params = url.searchParams;
  const client = await getClient(DB, params.get("client_id"));
  const problem = validateAuthorizeParams(params, client);
  if (problem) return new Response(problem, { status: 400 });
  return user ? consentPage(params, user, client) : loginFirstPage(params);
}

export async function authorizePost(request, DB, user) {
  const form = await request.formData();
  const params = new URLSearchParams();
  for (const [k, v] of form) params.set(k, v);

  const client = await getClient(DB, params.get("client_id"));
  const problem = validateAuthorizeParams(params, client);
  if (problem) return new Response(problem, { status: 400 });

  // Consent is only valid for a logged-in session — this is where the email gate holds.
  if (!user) return loginFirstPage(params);

  const code = randomHex(32);
  await DB.prepare(
    "INSERT INTO oauth_codes (code_hash, client_id, user_id, redirect_uri, code_challenge, expires_at) VALUES (?, ?, ?, ?, ?, ?)"
  )
    .bind(
      await sha256Hex(code),
      client.client_id,
      user.id,
      params.get("redirect_uri"),
      params.get("code_challenge"),
      Date.now() + CODE_TTL_MS
    )
    .run();

  const dest = new URL(params.get("redirect_uri"));
  dest.searchParams.set("code", code);
  if (params.get("state")) dest.searchParams.set("state", params.get("state"));
  return Response.redirect(dest.toString(), 302);
}

// ---------- /token ----------

function tokenError(error, description, status = 400) {
  return Response.json({ error, error_description: description }, { status });
}

async function issueTokens(DB, userId, clientId) {
  const access = "jat_" + randomHex(32);
  const refresh = "jrt_" + randomHex(32);
  const now = Date.now();
  await DB.batch([
    DB.prepare(
      "INSERT INTO oauth_tokens (token_hash, kind, user_id, client_id, expires_at) VALUES (?, 'access', ?, ?, ?)"
    ).bind(await sha256Hex(access), userId, clientId, now + ACCESS_TTL_MS),
    DB.prepare(
      "INSERT INTO oauth_tokens (token_hash, kind, user_id, client_id, expires_at) VALUES (?, 'refresh', ?, ?, ?)"
    ).bind(await sha256Hex(refresh), userId, clientId, now + REFRESH_TTL_MS),
    // opportunistic cleanup of anything expired
    DB.prepare("DELETE FROM oauth_tokens WHERE expires_at < ?").bind(now),
    DB.prepare("DELETE FROM oauth_codes WHERE expires_at < ?").bind(now),
  ]);
  return {
    access_token: access,
    token_type: "Bearer",
    expires_in: Math.floor(ACCESS_TTL_MS / 1000),
    refresh_token: refresh,
    scope: "journal",
  };
}

export async function token(request, DB) {
  const form = await request.formData().catch(() => null);
  if (!form) return tokenError("invalid_request", "expected form-encoded body");
  const grant = form.get("grant_type");

  if (grant === "authorization_code") {
    const code = form.get("code");
    const verifier = form.get("code_verifier");
    if (!code || !verifier) return tokenError("invalid_request", "code and code_verifier required");

    const row = await DB.prepare("SELECT * FROM oauth_codes WHERE code_hash = ?")
      .bind(await sha256Hex(code))
      .first();
    // single use — burn it immediately regardless of outcome
    if (row)
      await DB.prepare("DELETE FROM oauth_codes WHERE code_hash = ?").bind(row.code_hash).run();

    if (!row || row.expires_at < Date.now()) return tokenError("invalid_grant", "code invalid or expired");
    if (form.get("client_id") && form.get("client_id") !== row.client_id)
      return tokenError("invalid_grant", "client mismatch");
    if (form.get("redirect_uri") && form.get("redirect_uri") !== row.redirect_uri)
      return tokenError("invalid_grant", "redirect_uri mismatch");
    if ((await sha256Base64url(verifier)) !== row.code_challenge)
      return tokenError("invalid_grant", "PKCE verification failed");

    return Response.json(await issueTokens(DB, row.user_id, row.client_id));
  }

  if (grant === "refresh_token") {
    const refresh = form.get("refresh_token");
    if (!refresh) return tokenError("invalid_request", "refresh_token required");
    const row = await DB.prepare(
      "SELECT * FROM oauth_tokens WHERE token_hash = ? AND kind = 'refresh'"
    )
      .bind(await sha256Hex(refresh))
      .first();
    if (!row || row.expires_at < Date.now())
      return tokenError("invalid_grant", "refresh token invalid or expired");
    // rotate: old refresh token dies with this use
    await DB.prepare("DELETE FROM oauth_tokens WHERE token_hash = ?").bind(row.token_hash).run();
    return Response.json(await issueTokens(DB, row.user_id, row.client_id));
  }

  return tokenError("unsupported_grant_type", `unsupported grant_type: ${grant}`);
}

// ---------- bearer lookup for /mcp ----------

export async function getUserByAccessToken(DB, token) {
  const row = await DB.prepare(
    "SELECT u.id, u.email FROM oauth_tokens t JOIN users u ON u.id = t.user_id WHERE t.token_hash = ? AND t.kind = 'access' AND t.expires_at > ?"
  )
    .bind(await sha256Hex(token), Date.now())
    .first();
  return row || null;
}
