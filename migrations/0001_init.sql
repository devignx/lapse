-- Users: self-signup. MCP bearer token stored as SHA-256 hash only —
-- the plaintext token is shown once at signup / rotation.
CREATE TABLE IF NOT EXISTS users (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  email          TEXT NOT NULL UNIQUE,
  password_hash  TEXT NOT NULL,               -- PBKDF2-SHA256 hex
  password_salt  TEXT NOT NULL,               -- hex
  api_token_hash TEXT NOT NULL UNIQUE,        -- SHA-256 hex of MCP bearer token
  created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_users_token ON users(api_token_hash);

CREATE TABLE IF NOT EXISTS entries (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL,                -- ownership enforced in query layer (D1 doesn't enforce FKs)
  content    TEXT NOT NULL,
  timestamp  TEXT NOT NULL,                   -- ISO 8601, when the event happened
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT,
  raw_source TEXT
);
CREATE INDEX IF NOT EXISTS idx_entries_user_ts ON entries(user_id, timestamp DESC);

CREATE TABLE IF NOT EXISTS tags (
  entry_id INTEGER NOT NULL,
  tag      TEXT NOT NULL,
  PRIMARY KEY (entry_id, tag)
);
CREATE INDEX IF NOT EXISTS idx_tags_tag ON tags(tag);
