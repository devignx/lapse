// D1 query layer. Every entry/tag query is scoped by user_id —
// ownership is enforced here, not by FKs (D1 doesn't enforce them).

import { hashPassword, verifyPassword, sha256Hex, randomHex } from "./auth.js";

// ---------- users ----------

export async function createUser(DB, email, password) {
  const { salt, hash } = await hashPassword(password);
  const token = "jrnl_" + randomHex(24);
  const tokenHash = await sha256Hex(token);
  const res = await DB.prepare(
    "INSERT INTO users (email, password_hash, password_salt, api_token_hash) VALUES (?, ?, ?, ?) RETURNING id, email, created_at"
  )
    .bind(email.toLowerCase().trim(), hash, salt, tokenHash)
    .first();
  return { user: res, token }; // token returned once, never stored in plaintext
}

export async function authenticate(DB, email, password) {
  const user = await DB.prepare("SELECT * FROM users WHERE email = ?")
    .bind(email.toLowerCase().trim())
    .first();
  if (!user) return null;
  const ok = await verifyPassword(password, user.password_salt, user.password_hash);
  return ok ? user : null;
}

export async function getUserById(DB, id) {
  return DB.prepare("SELECT id, email, created_at FROM users WHERE id = ?").bind(id).first();
}

export async function getUserByToken(DB, token) {
  const tokenHash = await sha256Hex(token);
  return DB.prepare("SELECT id, email FROM users WHERE api_token_hash = ?").bind(tokenHash).first();
}

export async function rotateToken(DB, userId) {
  const token = "jrnl_" + randomHex(24);
  const tokenHash = await sha256Hex(token);
  await DB.prepare("UPDATE users SET api_token_hash = ? WHERE id = ?").bind(tokenHash, userId).run();
  return token; // old token dead immediately
}

// ---------- entries ----------

async function attachTags(DB, entry) {
  if (!entry) return entry;
  const { results } = await DB.prepare("SELECT tag FROM tags WHERE entry_id = ? ORDER BY tag")
    .bind(entry.id)
    .all();
  entry.tags = results.map((r) => r.tag);
  return entry;
}

async function attachTagsAll(DB, entries) {
  return Promise.all(entries.map((e) => attachTags(DB, e)));
}

function normalizeTags(tags) {
  return [...new Set((tags || []).map((t) => String(t).trim().toLowerCase()).filter(Boolean))];
}

export async function addEntry(DB, userId, { content, timestamp, raw_source, tags }) {
  const ts = timestamp || new Date().toISOString();
  const row = await DB.prepare(
    "INSERT INTO entries (user_id, content, timestamp, raw_source) VALUES (?, ?, ?, ?) RETURNING id"
  )
    .bind(userId, content, ts, raw_source || null)
    .first();
  const clean = normalizeTags(tags);
  if (clean.length) {
    await DB.batch(
      clean.map((tag) =>
        DB.prepare("INSERT OR IGNORE INTO tags (entry_id, tag) VALUES (?, ?)").bind(row.id, tag)
      )
    );
  }
  return getEntry(DB, userId, row.id);
}

export async function getEntry(DB, userId, id) {
  const entry = await DB.prepare("SELECT * FROM entries WHERE id = ? AND user_id = ?")
    .bind(id, userId)
    .first();
  return attachTags(DB, entry);
}

export async function updateEntry(DB, userId, id, { content, timestamp }) {
  const existing = await getEntry(DB, userId, id);
  if (!existing) return null;
  await DB.prepare(
    "UPDATE entries SET content = ?, timestamp = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ? AND user_id = ?"
  )
    .bind(content ?? existing.content, timestamp ?? existing.timestamp, id, userId)
    .run();
  return getEntry(DB, userId, id);
}

export async function deleteEntry(DB, userId, id) {
  const owned = await DB.prepare("SELECT id FROM entries WHERE id = ? AND user_id = ?")
    .bind(id, userId)
    .first();
  if (!owned) return false;
  await DB.batch([
    DB.prepare("DELETE FROM tags WHERE entry_id = ?").bind(id),
    DB.prepare("DELETE FROM entries WHERE id = ?").bind(id),
  ]);
  return true;
}

export async function getRecent(DB, userId, limit = 10, offset = 0) {
  const { results } = await DB.prepare(
    "SELECT * FROM entries WHERE user_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?"
  )
    .bind(userId, limit, offset)
    .all();
  return attachTagsAll(DB, results);
}

export async function getByDateRange(DB, userId, start, end) {
  const { results } = await DB.prepare(
    "SELECT * FROM entries WHERE user_id = ? AND timestamp >= ? AND timestamp <= ? ORDER BY timestamp DESC"
  )
    .bind(userId, start, end)
    .all();
  return attachTagsAll(DB, results);
}

export async function searchEntries(DB, userId, query, limit = 20) {
  const { results } = await DB.prepare(
    "SELECT * FROM entries WHERE user_id = ? AND content LIKE ? ORDER BY timestamp DESC LIMIT ?"
  )
    .bind(userId, `%${query}%`, limit)
    .all();
  return attachTagsAll(DB, results);
}

export async function getByTag(DB, userId, tag, limit = 50) {
  const { results } = await DB.prepare(
    `SELECT e.* FROM entries e
     JOIN tags t ON t.entry_id = e.id
     WHERE e.user_id = ? AND t.tag = ?
     ORDER BY e.timestamp DESC LIMIT ?`
  )
    .bind(userId, String(tag).trim().toLowerCase(), limit)
    .all();
  return attachTagsAll(DB, results);
}

export async function getRandom(DB, userId) {
  const entry = await DB.prepare(
    "SELECT * FROM entries WHERE user_id = ? ORDER BY RANDOM() LIMIT 1"
  )
    .bind(userId)
    .first();
  return attachTags(DB, entry);
}

export async function addTags(DB, userId, entryId, tags) {
  const entry = await getEntry(DB, userId, entryId);
  if (!entry) return null;
  const clean = normalizeTags(tags);
  if (clean.length) {
    await DB.batch(
      clean.map((tag) =>
        DB.prepare("INSERT OR IGNORE INTO tags (entry_id, tag) VALUES (?, ?)").bind(entryId, tag)
      )
    );
  }
  return getEntry(DB, userId, entryId);
}

export async function removeTag(DB, userId, entryId, tag) {
  const entry = await getEntry(DB, userId, entryId);
  if (!entry) return null;
  await DB.prepare("DELETE FROM tags WHERE entry_id = ? AND tag = ?")
    .bind(entryId, String(tag).trim().toLowerCase())
    .run();
  return getEntry(DB, userId, entryId);
}

export async function listTags(DB, userId) {
  const { results } = await DB.prepare(
    `SELECT t.tag, COUNT(*) AS count FROM tags t
     JOIN entries e ON e.id = t.entry_id
     WHERE e.user_id = ?
     GROUP BY t.tag ORDER BY count DESC, t.tag`
  )
    .bind(userId)
    .all();
  return results;
}

export async function getStats(DB, userId) {
  const agg = await DB.prepare(
    `SELECT COUNT(*) AS total, MIN(timestamp) AS first_ts, MAX(timestamp) AS last_ts,
            SUM(CASE WHEN timestamp >= datetime('now', '-7 days') THEN 1 ELSE 0 END) AS last7
     FROM entries WHERE user_id = ?`
  )
    .bind(userId)
    .first();
  const tagCount = await DB.prepare(
    "SELECT COUNT(DISTINCT t.tag) AS n FROM tags t JOIN entries e ON e.id = t.entry_id WHERE e.user_id = ?"
  )
    .bind(userId)
    .first();
  return {
    total_entries: agg.total,
    first_entry: agg.first_ts,
    last_entry: agg.last_ts,
    distinct_tags: tagCount.n,
    entries_last_7_days: agg.last7 || 0,
  };
}
