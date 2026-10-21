const ITERATIONS = 100000;
const SESSION_SECONDS = 12 * 60 * 60;
const MAX_BODY_BYTES = 1_000_000;

function json(data, status = 200, origin = "*") {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Vary": "Origin"
    }
  });
}
function b64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
function unb64(s) {
  const raw = atob(s);
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}
function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}
async function digest(text) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return b64(new Uint8Array(d));
}
async function passwordHash(password, salt, iterations = ITERATIONS) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2", hash: "SHA-256", salt: unb64(salt), iterations
  }, key, 256);
  return b64(new Uint8Array(bits));
}
function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
function validUsername(s) {
  return typeof s === "string" && /^[a-zA-Z0-9_.-]{3,32}$/.test(s);
}
function validPassword(s) {
  return typeof s === "string" && s.length >= 12 && s.length <= 256;
}
function validState(s) {
  if (!s || typeof s !== "object" || !Array.isArray(s.events) || !Array.isArray(s.countries)) return false;
  if (s.events.length > 10000 || s.countries.length > 2000) return false;
  if (s.range !== null && s.range !== undefined &&
      (typeof s.range !== "object" || !Number.isFinite(s.range.lo) || !Number.isFinite(s.range.hi) || s.range.lo > s.range.hi)) return false;
  const ids = new Set();
  for (const c of s.countries) {
    if (!c || typeof c.id !== "string" || typeof c.name !== "string" || c.name.length > 200) return false;
    if (ids.has("c:" + c.id)) return false;
    ids.add("c:" + c.id);
  }
  for (const e of s.events) {
    if (!e || typeof e.id !== "string" || typeof e.title !== "string" || e.title.length > 500 ||
        !Number.isFinite(e.start) || (e.end !== undefined && !Number.isFinite(e.end)) ||
        !Array.isArray(e.cs) || typeof e.type !== "string") return false;
    if (ids.has("e:" + e.id)) return false;
    ids.add("e:" + e.id);
  }
  return true;
}
function applyItems(state, items) {
  if (!Array.isArray(items) || items.length > 500) throw new Error("Invalid change list");
  for (const it of items) {
    if (!it || !["events", "countries"].includes(it.k) || typeof it.id !== "string") throw new Error("Invalid change");
    const arr = state[it.k];
    const i = arr.findIndex(x => x.id === it.id);
    if (it.add) {
      if (i < 0) arr.push(it.add);
    } else if (it.del) {
      if (i >= 0) arr.splice(i, 1);
    } else if (it.f && i >= 0 && typeof it.f === "object") {
      for (const [key, pair] of Object.entries(it.f)) {
        if (!["id", "title", "name", "kind", "type", "start", "end", "cs", "context", "outcome", "major"].includes(key)) continue;
        if (Array.isArray(pair) && pair.length === 2) arr[i][key] = pair[1];
      }
    }
  }
  return state;
}
async function getUser(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token || token.length > 256) return null;
  const tokenHash = await digest(token);
  const row = await env.DB.prepare(
    "SELECT users.username, users.role, sessions.expires_at FROM sessions JOIN users ON users.username=sessions.username WHERE sessions.token_hash=?"
  ).bind(tokenHash).first();
  if (!row || row.expires_at <= Math.floor(Date.now() / 1000)) {
    if (row) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(tokenHash).run();
    return null;
  }
  return { username: row.username, role: row.role, tokenHash };
}
async function readState(env) {
  const row = await env.DB.prepare("SELECT state_json FROM app_state WHERE id=1").first();
  if (!row) return { range: null, countries: [], events: [] };
  try {
    const state = JSON.parse(row.state_json);
    return validState(state) ? state : { range: null, countries: [], events: [] };
  } catch { return { range: null, countries: [], events: [] }; }
}
async function writeState(env, state) {
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare(
    "INSERT INTO app_state (id, state_json, updated_at) VALUES (1, ?, ?) ON CONFLICT(id) DO UPDATE SET state_json=excluded.state_json, updated_at=excluded.updated_at"
  ).bind(JSON.stringify(state), now).run();
}
async function handler(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allowed = env.ALLOWED_ORIGIN || "";
  if (request.method === "OPTIONS") {
    if (origin !== allowed) return new Response(null, { status: 403 });
    return new Response(null, { status: 204, headers: {
      "Access-Control-Allow-Origin": allowed,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin"
    }});
  }
  if (request.method !== "POST") return json({ ok: false, err: "method" }, 405, allowed || "*");
  if (origin !== allowed) return json({ ok: false, err: "origin" }, 403, allowed || "*");
  const len = Number(request.headers.get("Content-Length") || 0);
  if (len > MAX_BODY_BYTES) return json({ ok: false, err: "too_large" }, 413, allowed);
  let body;
  try { body = await request.json(); } catch { return json({ ok: false, err: "json" }, 400, allowed); }
  if (!body || typeof body !== "object" || JSON.stringify(body).length > MAX_BODY_BYTES) return json({ ok: false, err: "too_large" }, 413, allowed);

  if (body.a === "setup") {
    if (!env.BOOTSTRAP_SECRET || !safeEqual(String(body.secret || ""), env.BOOTSTRAP_SECRET)) {
      return json({ ok: false, err: "setup" }, 403, allowed);
    }
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first();
    if (count.n !== 0) return json({ ok: false, err: "already_setup" }, 409, allowed);
    if (!Array.isArray(body.users) || body.users.length < 1 || body.users.length > 20) return json({ ok: false, err: "users" }, 400, allowed);
    const seen = new Set();
    const statements = [];
    for (const u of body.users) {
      if (!u || !validUsername(u.username) || !validPassword(u.password) || !["admin", "editor"].includes(u.role) || seen.has(u.username.toLowerCase())) {
        return json({ ok: false, err: "invalid_user" }, 400, allowed);
      }
      seen.add(u.username.toLowerCase());
      const salt = b64(randomBytes(16));
      const hash = await passwordHash(u.password, salt);
      statements.push(env.DB.prepare(
        "INSERT INTO users (username, password_salt, password_hash, iterations, role, created_at) VALUES (?, ?, ?, ?, ?, ?)"
      ).bind(u.username, salt, hash, ITERATIONS, u.role, Math.floor(Date.now() / 1000)));
    }
    try { await env.DB.batch(statements); } catch { return json({ ok: false, err: "setup_failed" }, 500, allowed); }
    return json({ ok: true, created: statements.length }, 200, allowed);
  }

  if (body.a === "login") {
    if (!validUsername(body.username) || typeof body.password !== "string" || body.password.length > 256) {
      return json({ ok: false, err: "auth" }, 401, allowed);
    }
    const user = await env.DB.prepare("SELECT username, password_salt, password_hash, iterations FROM users WHERE username=?").bind(body.username).first();
    if (!user) {
      // Spend roughly similar effort for unknown usernames.
      await passwordHash(body.password, b64(new Uint8Array(16)), ITERATIONS);
      return json({ ok: false, err: "auth" }, 401, allowed);
    }
    const candidate = await passwordHash(body.password, user.password_salt, user.iterations);
    if (!safeEqual(candidate, user.password_hash)) return json({ ok: false, err: "auth" }, 401, allowed);
    const token = b64(randomBytes(32)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    const expires = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
    await env.DB.prepare("INSERT INTO sessions (token_hash, username, expires_at) VALUES (?, ?, ?)").bind(await digest(token), user.username, expires).run();
    return json({ ok: true, token, role: user.role, expires }, 200, allowed);
  }

  const user = await getUser(request, env);
  if (!user) return json({ ok: false, err: "auth" }, 401, allowed);

  if (body.a === "logout") {
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(user.tokenHash).run();
    return json({ ok: true }, 200, allowed);
  }
  if (body.a === "admin_create_user") {
    if (user.role !== "admin") return json({ ok: false, err: "forbidden" }, 403, allowed);
    const u = body.user;
    if (!u || !validUsername(u.username) || !validPassword(u.password) || !["admin", "editor"].includes(u.role)) return json({ ok: false, err: "invalid_user" }, 400, allowed);
    const salt = b64(randomBytes(16));
    const hash = await passwordHash(u.password, salt);
    try {
      await env.DB.prepare("INSERT INTO users (username, password_salt, password_hash, iterations, role, created_at) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(u.username, salt, hash, ITERATIONS, u.role, Math.floor(Date.now() / 1000)).run();
    } catch { return json({ ok: false, err: "user_exists" }, 409, allowed); }
    return json({ ok: true }, 200, allowed);
  }
  if (body.a === "admin_list_users") {
    if (user.role !== "admin") return json({ ok: false, err: "forbidden" }, 403, allowed);
    const result = await env.DB.prepare("SELECT username, role, created_at FROM users ORDER BY username").all();
    return json({ ok: true, users: result.results || [] }, 200, allowed);
  }
  if (body.a === "save") {
    const state = await readState(env);
    try { applyItems(state, body.items || []); } catch { return json({ ok: false, err: "changes" }, 400, allowed); }
    if (body.range !== undefined) state.range = body.range;
    if (!validState(state)) return json({ ok: false, err: "state" }, 400, allowed);
    await writeState(env, state);
    return json({ ok: true, state, role: user.role }, 200, allowed);
  }
  return json({ ok: false, err: "action" }, 400, allowed);
}
export default {
  async fetch(request, env) {
    try {
      return await handler(request, env);
    } catch (err) {
      console.error("Worker request failed:", err);
      return json(
        { ok: false, err: "server" },
        500,
        env.ALLOWED_ORIGIN || "*"
      );
    }
  }
};
