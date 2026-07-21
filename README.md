# Lapse

A personal journal your AI writes for you. Talk to your AI over MCP and it logs entries as you chat; you read them back on a minimal web viewer at **[lapse.in](https://lapse.in)**. Multi-user: each account gets its own journal and its own MCP token.

Runs on **Cloudflare Workers + D1** — free tier (100k requests/day, 5GB DB), no credit card, no servers.

## How it works

```
You chat with your AI ──MCP (OAuth / bearer token)──▶ Cloudflare Worker ──▶ D1 (SQLite)
                                                             ▲
You read your journal ──email/password login────────────────┘  (same Worker serves the site)
```

- **MCP** at `POST /mcp` — 13 tools: `add_entry`, `get_entry`, `update_entry`, `delete_entry`, `get_recent`, `get_by_date_range`, `search_entries`, `get_by_tag`, `get_random`, `add_tags`, `remove_tag`, `list_tags`, `get_stats`. Plus MCP `instructions` and three prompt templates (`log_today`, `weekly_review`, `remember_this`) shipped in the handshake.
- **Two ways to authenticate MCP:**
  - **OAuth 2.1** (what claude.ai custom connectors use): discovery at `/.well-known/oauth-authorization-server`, dynamic client registration, `/authorize` login page, `/token` with PKCE + refresh-token rotation. Access/refresh tokens stored hashed.
  - **Personal bearer token** (`lapse_...`, for Claude Code CLI / opencode / scripts): **stored hashed (SHA-256)** — shown once at signup/rotation, rotatable from the dashboard.
- **Viewer** at `/` — signup/login (email + PBKDF2-hashed password), date-grouped feed, search, tag filter, sort, stats. `/home` is the public landing page. Sessions are HMAC-signed HTTP-only cookies.
- **Storage** — D1 (SQLite). Every query scoped `WHERE user_id = ?`.
- **Rate limiting** — Workers native binding, per-IP: 5/min on password endpoints (login, signup, authorize), 20/min on `/token`. 429 + `Retry-After: 60` when exceeded.

## Run locally

```bash
npm install
cp .dev.vars.example .dev.vars
npm run db:migrate:local
npm run dev            # http://localhost:8787
```

Sign up in the browser — your MCP token appears once in the Connections dialog. Local data lives in `.wrangler/state/` (gitignored).

## Deploy

The Cloudflare resources (Worker + D1) are named `journal` internally — that's just the resource id in the account, kept stable so redeploys don't re-provision. The product and its domain are Lapse / lapse.in.

```bash
npx wrangler login
npx wrangler d1 create journal        # copy database_id into wrangler.toml
npm run db:migrate:remote
npx wrangler secret put SESSION_SECRET   # paste output of: openssl rand -hex 32
npm run deploy
```

### Custom domain (lapse.in)

Cloudflare dashboard → the Worker → **Settings → Domains & Routes → Add → Custom Domain** → `lapse.in` (and `www` if wanted). Cloudflare provisions the cert. Every URL Lapse shows — the MCP endpoint, OAuth issuer, connector snippets — is derived from the request origin, so they all switch to `https://lapse.in/...` automatically once the domain is live. No code change needed.

> Existing claude.ai connections made against the old `*.workers.dev` URL may need to be removed and re-added, since the OAuth issuer origin changes.

## Connect to Lapse

### claude.ai (web / mobile / desktop)

1. Open [lapse.in](https://lapse.in), **sign up** first.
2. Claude → Settings → Connectors → **Add custom connector** → URL: `https://lapse.in/mcp`. Leave client id/secret **empty** — registration is automatic.
3. Claude redirects to the Lapse authorize page — log in with your Lapse email/password.
4. In any chat: *"log this: shipped the project today"* — entry lands in your journal.

### Claude Code CLI

Uses your personal `lapse_` token (shown once at signup, or dashboard → Connections → rotate):

```bash
claude mcp add --transport http lapse https://lapse.in/mcp \
  --scope user --header "Authorization: Bearer lapse_..."
```

### opencode / other MCP clients

Config snippet with your token is in **Connections** after signup. Local LLM clients (LM Studio, Goose) work the same way — bearer token, fully offline-capable.

Token compromised or lost? Dashboard → Connections → **rotate token**. Old token dies instantly; Claude's OAuth connection is separate and unaffected.

## Layout

```
src/worker/index.js      routing: /mcp, OAuth endpoints, /api/*, static assets
src/worker/lib/mcp.js    MCP JSON-RPC (stateless Streamable HTTP) + tools, instructions, prompts
src/worker/lib/oauth.js  OAuth 2.1: discovery, registration, authorize, token (PKCE)
src/worker/lib/db.js     D1 queries, all user-scoped
src/worker/lib/auth.js   WebCrypto: PBKDF2 passwords, SHA-256 tokens, HMAC sessions
migrations/              D1 schema
public/                  viewer + landing (vanilla HTML/CSS/JS)
```

## API (session-authenticated, used by the viewer)

- `POST /api/signup` (returns `mcp_token` once) · `POST /api/login` · `POST /api/logout` · `GET /api/me`
- `POST /api/rotate-token` (returns new `mcp_token` once)
- `GET /api/entries?limit&offset` · `?q=` search · `?tag=` filter · `?start=&end=` range
- `GET /api/tags` · `GET /api/stats` · `DELETE /api/entries/:id`
