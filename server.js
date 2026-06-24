const express = require('express');
const path = require('path');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const JWT_SECRET = process.env.JWT_SECRET;
const IS_STAGING = process.env.USERNODE_ENV === 'staging';

// Paths that stay open without authentication. Add a path here (and add it
// with `app.get`/`app.post` below) if you deliberately want it public.
// Everything else requires a valid platform-issued JWT.
const PUBLIC_API_PATHS = new Set(['/health', '/api/env']);
// Public path prefixes that bypass the JWT gate. `/explorer-api/*` is a
// transparent proxy to the public block explorer used by the bridge.
const PUBLIC_PREFIXES = ['/explorer-api/'];

app.use(express.json({ limit: '2mb' }));

// Verify platform-issued JWT if one was passed, then enforce auth on
// anything not explicitly marked public. The iframe adds `?token=…`
// on load; the frontend script forwards the token via `x-usernode-token`
// on subsequent fetches.
app.use((req, res, next) => {
  const token = req.query.token || req.headers['x-usernode-token'];
  if (token && JWT_SECRET) {
    try { req.user = jwt.verify(token, JWT_SECRET); } catch {}
  }

  // Static assets (CSS/JS/images) are always served; the API and the HTML
  // shell are gated so direct hits to the staging/prod subdomain don't
  // leak app data to the public internet.
  if (req.method !== 'GET' || req.path.startsWith('/api/')) {
    if (PUBLIC_API_PATHS.has(req.path)) return next();
    if (PUBLIC_PREFIXES.some((p) => req.path.startsWith(p))) return next();
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
});

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// Public, non-sensitive environment hints for the client. Used by the
// frontend to know whether to run the staging-only demo seeder.
app.get('/api/env', (_req, res) => {
  res.json({ staging: IS_STAGING });
});

// ── Notes CRUD ────────────────────────────────────────────────────────────
// Every note row stores only CIPHERTEXT for the sensitive parts (title,
// content, tags live inside the encrypted blob). The server never sees
// plaintext. Cosmetic flags (pinned/archived/color) and timestamps are kept
// in the clear so we can order/filter efficiently. Ownership is enforced on
// every query via req.user.id.

const COLORS = new Set([
  'default', 'red', 'orange', 'yellow', 'green', 'teal', 'blue', 'purple', 'pink', 'gray',
]);

function sanitizeColor(c) {
  return COLORS.has(c) ? c : 'default';
}

function serializeNote(row) {
  return {
    id: row.id,
    ciphertext: row.ciphertext,
    pinned: row.pinned,
    archived: row.archived,
    color: row.color,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

// List the caller's notes (both active and archived; the client splits them).
app.get('/api/notes', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, ciphertext, pinned, archived, color, created_at, updated_at
         FROM notes
        WHERE user_id = $1
        ORDER BY pinned DESC, updated_at DESC`,
      [req.user.id]
    );
    res.json({ notes: rows.map(serializeNote) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create a note. Body: { ciphertext, pinned?, archived?, color? }.
app.post('/api/notes', async (req, res) => {
  try {
    const { ciphertext, pinned, archived, color } = req.body || {};
    if (typeof ciphertext !== 'string' || !ciphertext) {
      return res.status(400).json({ error: 'ciphertext required' });
    }
    const { rows } = await pool.query(
      `INSERT INTO notes (user_id, usernode_pubkey, ciphertext, pinned, archived, color)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, ciphertext, pinned, archived, color, created_at, updated_at`,
      [
        req.user.id,
        req.user.usernode_pubkey || null,
        ciphertext,
        !!pinned,
        !!archived,
        sanitizeColor(color),
      ]
    );
    res.json({ note: serializeNote(rows[0]) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update a note. Any subset of { ciphertext, pinned, archived, color }.
// Scoped to the owner so a user can only mutate their own rows.
app.patch('/api/notes/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) return res.status(400).json({ error: 'bad id' });

    const { ciphertext, pinned, archived, color } = req.body || {};
    const sets = [];
    const vals = [];
    let i = 1;
    if (typeof ciphertext === 'string' && ciphertext) {
      sets.push(`ciphertext = $${i++}`); vals.push(ciphertext);
    }
    if (typeof pinned === 'boolean') { sets.push(`pinned = $${i++}`); vals.push(pinned); }
    if (typeof archived === 'boolean') { sets.push(`archived = $${i++}`); vals.push(archived); }
    if (typeof color === 'string') { sets.push(`color = $${i++}`); vals.push(sanitizeColor(color)); }
    if (!sets.length) return res.status(400).json({ error: 'nothing to update' });
    sets.push(`updated_at = NOW()`);

    vals.push(id);
    vals.push(req.user.id);
    const { rows } = await pool.query(
      `UPDATE notes SET ${sets.join(', ')}
        WHERE id = $${i++} AND user_id = $${i++}
        RETURNING id, ciphertext, pinned, archived, color, created_at, updated_at`,
      vals
    );
    if (!rows.length) return res.status(404).json({ error: 'not found' });
    res.json({ note: serializeNote(rows[0]) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete a note, scoped to the owner.
app.delete('/api/notes/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) return res.status(400).json({ error: 'bad id' });
    const { rowCount } = await pool.query(
      `DELETE FROM notes WHERE id = $1 AND user_id = $2`,
      [id, req.user.id]
    );
    if (!rowCount) return res.status(404).json({ error: 'not found' });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Key-verification token ────────────────────────────────────────────────
// One ciphertext blob per user. The client encrypts a known constant with
// its derived key and stores the result here on first unlock; on later
// unlocks it decrypts this to confirm the derived key still matches.
app.get('/api/keycheck', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT ciphertext FROM notes_keycheck WHERE user_id = $1`,
      [req.user.id]
    );
    res.json({ keycheck: rows.length ? rows[0].ciphertext : null });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/keycheck', async (req, res) => {
  try {
    const { ciphertext } = req.body || {};
    if (typeof ciphertext !== 'string' || !ciphertext) {
      return res.status(400).json({ error: 'ciphertext required' });
    }
    await pool.query(
      `INSERT INTO notes_keycheck (user_id, ciphertext)
       VALUES ($1, $2)
       ON CONFLICT (user_id) DO UPDATE SET ciphertext = EXCLUDED.ciphertext`,
      [req.user.id, ciphertext]
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.use(express.static(path.join(__dirname, 'public')));

// HTML shell: serve the app if authenticated, otherwise an "open in Usernode"
// landing page so stray visits to the staging URL don't reveal the app.
app.get('*', (req, res) => {
  if (!req.user) {
    return res.status(401).send(`<!doctype html><meta charset=utf-8><title>Open in Usernode</title>
<body style="font-family:system-ui;background:#09090b;color:#e4e4e7;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0">
  <div style="max-width:24rem;padding:2rem;text-align:center">
    <h1 style="font-size:1.25rem;margin:0 0 0.5rem">Open this app inside Usernode</h1>
    <p style="color:#a1a1aa;font-size:0.9rem;margin:0 0 1.25rem">This page is served via the platform; direct visits aren't authenticated.</p>
    <a href="https://social-vibecoding.usernodelabs.org" style="display:inline-block;padding:0.5rem 1rem;background:#7c3aed;color:white;border-radius:0.5rem;text-decoration:none;font-size:0.9rem">Go to Usernode</a>
  </div>
</body>`);
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

async function start() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS notes (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      usernode_pubkey VARCHAR(255),
      ciphertext TEXT NOT NULL,
      pinned BOOLEAN NOT NULL DEFAULT false,
      archived BOOLEAN NOT NULL DEFAULT false,
      color VARCHAR(32) NOT NULL DEFAULT 'default',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS notes_user_idx ON notes (user_id)`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS notes_keycheck (
      user_id INTEGER PRIMARY KEY,
      ciphertext TEXT NOT NULL
    )
  `);

  // Both tables hold per-user private content (encrypted note blobs and the
  // per-user key-verification token). A stranger seeing every row would be a
  // problem, so they are copied schema-only into staging.
  await pool.query(`COMMENT ON TABLE notes IS 'staging:private'`);
  await pool.query(`COMMENT ON TABLE notes_keycheck IS 'staging:private'`);

  app.listen(port, () => console.log(`Listening on :${port}`));
}

start().catch(err => { console.error(err); process.exit(1); });
