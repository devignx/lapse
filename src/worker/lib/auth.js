// WebCrypto auth: PBKDF2 password hashing, SHA-256 token hashing,
// HMAC-signed session cookies. No Node crypto — runs on Workers.

const PBKDF2_ITERATIONS = 100_000;
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
export const SESSION_TTL_S = SESSION_TTL_MS / 1000;

const enc = new TextEncoder();

function toHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function randomHex(bytes) {
  return toHex(crypto.getRandomValues(new Uint8Array(bytes)));
}

export async function sha256Hex(text) {
  return toHex(await crypto.subtle.digest("SHA-256", enc.encode(text)));
}

async function pbkdf2Hex(password, saltHex) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, [
    "deriveBits",
  ]);
  const salt = Uint8Array.from(saltHex.match(/.{2}/g).map((h) => parseInt(h, 16)));
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS },
    key,
    256
  );
  return toHex(bits);
}

export async function hashPassword(password) {
  const salt = randomHex(16);
  return { salt, hash: await pbkdf2Hex(password, salt) };
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export async function verifyPassword(password, salt, expectedHash) {
  return constantTimeEqual(await pbkdf2Hex(password, salt), expectedHash);
}

// ---------- sessions ----------

async function hmacHex(secret, payload) {
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return toHex(await crypto.subtle.sign("HMAC", key, enc.encode(payload)));
}

export async function createSessionCookieValue(secret, userId) {
  const payload = `${userId}.${Date.now() + SESSION_TTL_MS}`;
  return `${payload}.${await hmacHex(secret, payload)}`;
}

export async function parseSessionCookieValue(secret, value) {
  if (!value) return null;
  const parts = value.split(".");
  if (parts.length !== 3) return null;
  const [userId, expires, sig] = parts;
  const expected = await hmacHex(secret, `${userId}.${expires}`);
  if (!constantTimeEqual(sig, expected)) return null;
  if (Date.now() > Number(expires)) return null;
  return Number(userId);
}

export function getCookie(request, name) {
  const header = request.headers.get("Cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return decodeURIComponent(v.join("="));
  }
  return null;
}

export function sessionSetCookieHeader(value, { clear = false, secure = true } = {}) {
  const maxAge = clear ? 0 : SESSION_TTL_S;
  const sec = secure ? "; Secure" : "";
  return `session=${clear ? "" : value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${sec}`;
}
