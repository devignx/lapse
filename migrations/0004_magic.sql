-- Passwordless magic-link login. Tokens stored hashed, single-use, short-lived.
CREATE TABLE IF NOT EXISTS magic_links (
  token_hash TEXT PRIMARY KEY,          -- SHA-256 hex of the emailed token
  email      TEXT NOT NULL,
  expires_at INTEGER NOT NULL,          -- ms epoch
  used       INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_magic_email ON magic_links(email);
