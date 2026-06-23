'use strict';

const http = require('node:http');
const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');
const path = require('node:path');

const PORT = parseInt(process.env.PORT || '3939', 10);
const WALL_PASSWORD = process.env.WALL_PASSWORD || '';
const DB_PATH = path.join(__dirname, 'wall_data.sqlite');
const KEY_PATTERN = /^[a-z][a-z0-9_]{0,59}$/; // namespaced keys like fortune50_overrides, g20_colors
const MAX_BODY = 10 * 1024 * 1024; // 10MB

// --- DB setup ---
const db = new DatabaseSync(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS wall_settings (
    key        TEXT UNIQUE NOT NULL,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS wall_settings_history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_history_key ON wall_settings_history(key);
`);

// --- Helpers ---
function timingSafeEqual(a, b) {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) {
    crypto.timingSafeEqual(ba, Buffer.alloc(ba.length)); // consume time
    return false;
  }
  return crypto.timingSafeEqual(ba, bb);
}

function checkPassword(req) {
  const header = req.headers['x-wall-password'] || '';
  return WALL_PASSWORD !== '' && timingSafeEqual(header, WALL_PASSWORD);
}

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Wall-Password');
}

function json(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(new Error('Request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function parseKey(url) {
  // /api/wall/:key  or  /api/wall/:key/history
  const m = url.match(/^\/api\/wall\/([^/?#]+)(\/history)?(\?.*)?$/);
  if (!m) return null;
  return { key: decodeURIComponent(m[1]), history: !!m[2] };
}

// --- Prepared statements ---
const stmtGet     = db.prepare('SELECT value, updated_at FROM wall_settings WHERE key = ?');
const stmtUpsert  = db.prepare(`
  INSERT INTO wall_settings (key, value, updated_at) VALUES (?, ?, ?)
  ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
`);
const stmtHistory = db.prepare(
  'SELECT value, updated_at FROM wall_settings_history WHERE key = ? ORDER BY id DESC LIMIT 20'
);
const stmtInsertHistory = db.prepare(
  'INSERT INTO wall_settings_history (key, value, updated_at) VALUES (?, ?, ?)'
);
const stmtPruneHistory = db.prepare(`
  DELETE FROM wall_settings_history
  WHERE key = ? AND id NOT IN (
    SELECT id FROM wall_settings_history WHERE key = ? ORDER BY id DESC LIMIT 20
  )
`);

// --- Request handler ---
const server = http.createServer(async (req, res) => {
  cors(res);

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = req.url || '/';

  // Health
  if (url === '/api/health' && req.method === 'GET') {
    return json(res, 200, { status: 'ok', time: new Date().toISOString() });
  }

  // /api/wall/:key routes
  const parsed = parseKey(url);
  if (!parsed) {
    return json(res, 404, { error: 'Not found' });
  }

  const { key, history } = parsed;

  if (!KEY_PATTERN.test(key)) {
    return json(res, 400, { error: `Invalid key "${key}". Must match ^[a-z][a-z0-9_]{0,59}$` });
  }

  // GET /api/wall/:key/history — password required
  if (history && req.method === 'GET') {
    if (!checkPassword(req)) return json(res, 401, { error: 'Unauthorized' });
    const rows = stmtHistory.all(key);
    return json(res, 200, { key, history: rows });
  }

  // GET /api/wall/:key — no password
  if (!history && req.method === 'GET') {
    const row = stmtGet.get(key);
    if (!row) return json(res, 404, { error: `No data found for key "${key}"` });
    return json(res, 200, { key, value: row.value, updated_at: row.updated_at });
  }

  // POST /api/wall/:key — password required
  if (!history && req.method === 'POST') {
    if (!checkPassword(req)) return json(res, 401, { error: 'Unauthorized' });

    let raw;
    try {
      raw = await readBody(req);
    } catch (e) {
      return json(res, 413, { error: e.message });
    }

    let body;
    try {
      body = JSON.parse(raw);
    } catch {
      return json(res, 400, { error: 'Malformed JSON' });
    }

    if (!Object.prototype.hasOwnProperty.call(body, 'value')) {
      return json(res, 400, { error: 'Missing "value" field in body' });
    }

    const value = typeof body.value === 'string' ? body.value : JSON.stringify(body.value);
    const now = new Date().toISOString();

    // Archive existing value before overwriting
    const existing = stmtGet.get(key);
    if (existing) {
      stmtInsertHistory.run(key, existing.value, existing.updated_at);
      stmtPruneHistory.run(key, key);
    }

    stmtUpsert.run(key, value, now);
    return json(res, 200, { key, updated_at: now });
  }

  return json(res, 405, { error: 'Method not allowed' });
});

server.listen(PORT, () => {
  console.log(`Wall server listening on port ${PORT}`);
  console.log(`DB: ${DB_PATH}`);
  if (!WALL_PASSWORD) console.warn('WARNING: WALL_PASSWORD not set — POST endpoints are inaccessible');
});
