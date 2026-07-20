# Journal

A personal log you write by talking to Claude. Claude connects over MCP and logs entries as you chat; you read them on a minimal web viewer. Multi-user: each account gets its own journal and its own MCP token.

Runs on **Cloudflare Workers + D1** — free tier (100k requests/day, 5GB DB), no credit card, no servers.

## How it works

```
You chat with Claude ──MCP (bearer token)──▶ Cloudflare Worker ──▶ D1 (SQLite)
                                                     ▲
You read your journal ──email/password login────────┘  (same Worker serves the site)
```

- **MCP** at `POST /mcp` — 13 tools: `add_entry`, `get_entry`, `update_entry`, `delete_entry`, `get_recent`, `get_by_date_range`, `search_entries`, `get_by_tag`, `get_random`, `add_tags`, `remove_tag`, `list_tags`, `get_stats`. Per-user bearer token, **stored hashed (SHA-256)** — shown once at signup/rotation, rotatable from the dashboard.
- **Viewer** at `/` — signup/login (email + PBKDF2-hashed password), entry feed, search, tag filters, stats. Sessions are HMAC-signed HTTP-only cookies.
- **Storage** — D1 (SQLite). Every query scoped `WHERE user_id = ?`.

## Run locally

```bash
npm install
cp .dev.vars.example .dev.vars
npm run db:migrate:local
npm run dev            # http://localhost:8787
```

Sign up in the browser — your MCP token appears once in the connect dialog. Local data lives in `.wrangler/state/` (gitignored).

For a real end-to-end test with Claude, localhost isn't reachable from claude.ai — tunnel it (`ngrok http 8787`) or just deploy; deploys take seconds.

## Deploy

```bash
npx wrangler login
npx wrangler d1 create journal        # copy database_id into wrangler.toml
npm run db:migrate:remote
npx wrangler secret put SESSION_SECRET   # paste output of: openssl rand -hex 32
npm run deploy
```

Live at `https://journal.<your-subdomain>.workers.dev`.

## Connect to Claude

1. Open your deployed site, sign up — the connect dialog opens with your MCP token. **Copy it now** (it's hashed at rest, never shown again; rotate to get a new one).
2. Claude → Settings → Connectors → **Add custom connector**.
3. URL: `https://journal.<your-subdomain>.workers.dev/mcp` · Auth: the bearer token.
4. In any chat: *"log this: shipped the journal project today"* — entry lands in your journal.

Token compromised or lost? Dashboard → connect → **rotate token**. Old token dies instantly; update the connector with the new one.

## Layout

```
src/worker/index.js    routing: /mcp, /api/*, static assets
src/worker/lib/mcp.js  MCP JSON-RPC (stateless Streamable HTTP) + tool definitions
src/worker/lib/db.js   D1 queries, all user-scoped
src/worker/lib/auth.js WebCrypto: PBKDF2 passwords, SHA-256 tokens, HMAC sessions
migrations/            D1 schema
public/                viewer (vanilla HTML/CSS/JS)
```

## API (session-authenticated, used by the viewer)

- `POST /api/signup` (returns `mcp_token` once) · `POST /api/login` · `POST /api/logout` · `GET /api/me`
- `POST /api/rotate-token` (returns new `mcp_token` once)
- `GET /api/entries?limit&offset` · `?q=` search · `?tag=` filter · `?start=&end=` range
- `GET /api/tags` · `GET /api/stats` · `DELETE /api/entries/:id`
