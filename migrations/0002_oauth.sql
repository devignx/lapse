-- OAuth 2.1 provider tables (claude.ai custom connectors authenticate via
-- OAuth + PKCE, not bearer headers). Codes/tokens stored as SHA-256 hashes.
CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id     TEXT PRIMARY KEY,
  client_name   TEXT NOT NULL DEFAULT '',
  redirect_uris TEXT NOT NULL,               -- JSON array of exact URIs
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS oauth_codes (
  code_hash      TEXT PRIMARY KEY,           -- SHA-256 hex of the auth code
  client_id      TEXT NOT NULL,
  user_id        INTEGER NOT NULL,
  redirect_uri   TEXT NOT NULL,
  code_challenge TEXT NOT NULL,              -- PKCE S256 challenge
  expires_at     INTEGER NOT NULL            -- ms epoch
);

CREATE TABLE IF NOT EXISTS oauth_tokens (
  token_hash TEXT PRIMARY KEY,               -- SHA-256 hex of access/refresh token
  kind       TEXT NOT NULL,                  -- 'access' | 'refresh'
  user_id    INTEGER NOT NULL,
  client_id  TEXT NOT NULL,
  expires_at INTEGER NOT NULL,               -- ms epoch
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_user ON oauth_tokens(user_id);
