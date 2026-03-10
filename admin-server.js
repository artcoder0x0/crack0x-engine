// ══════════════════════════════════════════════════════════════════════════════
// CRACK0X — LICENSE ADMIN SERVER
// Run: node admin-server.js
// Dashboard: http://localhost:3000
//
// This is your private C2 server. Run it on your own machine.
// The distributed app POSTs to this server to register licenses.
// You open http://localhost:3000 to manage everything.
// ══════════════════════════════════════════════════════════════════════════════

const express    = require('express');
const fs         = require('fs');
const path       = require('path');
const crypto     = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3006;
const DB_FILE = path.join(__dirname, 'licenses_db.json');

// ── Change this to a strong secret. The distributed app must send this
//    in the X-License-Secret header, otherwise all write requests are rejected.

const API_SECRET = process.env.API_SECRET || 'crack0x-secret-2024';
// ── Admin dashboard password (for the web UI login)
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

app.use(express.json({ limit: '1mb' }));

// ══════════════════════════════════════════════════════════════════════════════
// DB HELPERS
// ══════════════════════════════════════════════════════════════════════════════

function readDB() {
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
  } catch {
    return { version: 1, last_updated: new Date().toISOString(), records: {} };
  }
}

function writeDB(db) {
  db.last_updated = new Date().toISOString();
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf-8');
}

// ══════════════════════════════════════════════════════════════════════════════
// MIDDLEWARE
// ══════════════════════════════════════════════════════════════════════════════

// Verify API secret for write endpoints (called by the distributed app)
function requireSecret(req, res, next) {
  const secret = req.headers['x-license-secret'];
  if (secret !== API_SECRET) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

// Simple session token for admin UI
const adminSessions = new Set();

function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'] || req.query.token;
  if (!adminSessions.has(token)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// CORS for dashboard requests
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, X-License-Secret, X-Admin-Token');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ══════════════════════════════════════════════════════════════════════════════
// ADMIN AUTH
// ══════════════════════════════════════════════════════════════════════════════

app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Invalid password' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  adminSessions.add(token);
  // Sessions expire after 8 hours
  setTimeout(() => adminSessions.delete(token), 8 * 60 * 60 * 1000);
  res.json({ token });
});

app.post('/api/admin/logout', requireAdmin, (req, res) => {
  const token = req.headers['x-admin-token'];
  adminSessions.delete(token);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════════════════════
// APP-FACING ENDPOINTS (called by the distributed Electron app)
// These require the API_SECRET header.
// ══════════════════════════════════════════════════════════════════════════════

// Register or update a license (called on every createLicense / validation)
app.post('/api/licenses/register', requireSecret, (req, res) => {
  try {
    const licenseData = req.body;
    if (!licenseData.machine_id || !licenseData.license_key) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const db = readDB();
    const machineId = licenseData.machine_id;
    const existing = db.records[machineId];

    const historyEntry = {
      license_key:         licenseData.license_key,
      generated_at:        licenseData.created_at,
      expires_at:          licenseData.expires_at,
      total_days_consumed: licenseData.total_days_consumed ?? licenseData.days_deducted ?? 0,
      generation_number:   licenseData.generation_count ?? 1,
      revoked:             false
    };

    const existingHistory = existing?.history ?? [];
    const alreadyLogged = existingHistory.some(h => h.license_key === licenseData.license_key);
    const updatedHistory = alreadyLogged
      ? existingHistory
      : [...existingHistory, historyEntry];

    db.records[machineId] = {
      machine_id:           machineId,
      hostname:             licenseData.hostname ?? existing?.hostname ?? 'unknown',
      platform:             licenseData.platform ?? existing?.platform ?? 'unknown',
      license_key:          licenseData.license_key,
      original_created_at:  licenseData.original_created_at ?? licenseData.created_at,
      last_generated_at:    licenseData.created_at,
      expires_at:           licenseData.expires_at,
      activated:            licenseData.activated ?? existing?.activated ?? false,
      activation_date:      licenseData.activation_date ?? existing?.activation_date ?? null,
      total_days_consumed:  licenseData.total_days_consumed ?? licenseData.days_deducted ?? 0,
      generation_count:     licenseData.generation_count ?? 1,
      revoked:              existing?.revoked ?? false,  // NEVER overwrite revocation from app
      revoked_at:           existing?.revoked_at ?? null,
      revoked_reason:       existing?.revoked_reason ?? null,
      notes:                existing?.notes ?? '',
      last_seen:            new Date().toISOString(),
      ip:                   req.ip,
      history:              updatedHistory
    };

    writeDB(db);
    res.json({ ok: true, revoked: db.records[machineId].revoked });
  } catch (err) {
    console.error('register error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Check license status (called by app on startup/validation)
// Returns just enough for the app to know if it's been revoked centrally.
app.get('/api/licenses/check/:machineId', requireSecret, (req, res) => {
  try {
    const db = readDB();
    const record = db.records[req.params.machineId];

    if (!record) {
      return res.json({ found: false, revoked: false });
    }

    // Update last_seen and IP
    record.last_seen = new Date().toISOString();
    record.ip = req.ip;
    writeDB(db);

    res.json({
      found:   true,
      revoked: record.revoked,
      revoked_reason: record.revoked_reason ?? null
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// ADMIN API ENDPOINTS (called by dashboard, require admin token)
// ══════════════════════════════════════════════════════════════════════════════

// List all licenses
app.get('/api/admin/licenses', requireAdmin, (req, res) => {
  const db = readDB();
  const records = Object.values(db.records).sort(
    (a, b) => new Date(b.last_generated_at) - new Date(a.last_generated_at)
  );
  res.json(records);
});

// Stats
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const db = readDB();
  const records = Object.values(db.records);
  const now = new Date();
  res.json({
    total:     records.length,
    active:    records.filter(r => !r.revoked && new Date(r.expires_at) > now).length,
    revoked:   records.filter(r => r.revoked).length,
    expired:   records.filter(r => !r.revoked && new Date(r.expires_at) <= now).length,
    activated: records.filter(r => r.activated).length
  });
});

// Revoke
app.post('/api/admin/revoke/:machineId', requireAdmin, (req, res) => {
  try {
    const db = readDB();
    const record = db.records[req.params.machineId];
    if (!record) return res.status(404).json({ error: 'Not found' });

    record.revoked        = true;
    record.revoked_at     = new Date().toISOString();
    record.revoked_reason = req.body.reason ?? '';
    record.history = record.history.map(h =>
      h.license_key === record.license_key ? { ...h, revoked: true } : h
    );
    writeDB(db);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Reinstate
app.post('/api/admin/reinstate/:machineId', requireAdmin, (req, res) => {
  try {
    const db = readDB();
    const record = db.records[req.params.machineId];
    if (!record) return res.status(404).json({ error: 'Not found' });

    record.revoked        = false;
    record.revoked_at     = null;
    record.revoked_reason = null;
    writeDB(db);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Update notes
app.put('/api/admin/notes/:machineId', requireAdmin, (req, res) => {
  try {
    const db = readDB();
    const record = db.records[req.params.machineId];
    if (!record) return res.status(404).json({ error: 'Not found' });

    record.notes = req.body.notes ?? '';
    writeDB(db);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete record
app.delete('/api/admin/licenses/:machineId', requireAdmin, (req, res) => {
  try {
    const db = readDB();
    if (!db.records[req.params.machineId]) return res.status(404).json({ error: 'Not found' });
    delete db.records[req.params.machineId];
    writeDB(db);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin-initiated regenerate: creates a new key for a machine,
// respecting the original 30-day pool
app.post('/api/admin/regenerate/:machineId', requireAdmin, (req, res) => {
  try {
    const db = readDB();
    const record = db.records[req.params.machineId];
    if (!record) return res.status(404).json({ error: 'Not found' });

    const now = new Date();
    const anchor = new Date(record.original_created_at);
    const daysSinceOrigin = Math.max(
      1,
      Math.min(30, Math.floor((now - anchor) / 86400000))
    );
    const validityDays = Math.max(1, 30 - daysSinceOrigin);
    const expiresAt = new Date(now.getTime() + validityDays * 86400000);

    // Generate new key
    const rawKey = crypto.randomBytes(32).toString('base64').substring(0, 24);
    const newKey = rawKey.match(/.{1,4}/g).join('-');

    const newHistory = {
      license_key:         newKey,
      generated_at:        now.toISOString(),
      expires_at:          expiresAt.toISOString(),
      total_days_consumed: daysSinceOrigin,
      generation_number:   record.generation_count + 1,
      revoked:             false
    };

    record.license_key         = newKey;
    record.last_generated_at   = now.toISOString();
    record.expires_at          = expiresAt.toISOString();
    record.total_days_consumed = daysSinceOrigin;
    record.generation_count    = record.generation_count + 1;
    record.activated           = false;
    record.activation_date     = null;
    record.revoked             = false;  // reinstate automatically on admin regen
    record.revoked_at          = null;
    record.revoked_reason      = null;
    record.history             = [...(record.history ?? []), newHistory];

    writeDB(db);

    res.json({
      ok:          true,
      newKey,
      validityDays,
      daysConsumed: daysSinceOrigin,
      expiresAt:   expiresAt.toISOString(),
      message:     `New key generated. Valid for ${validityDays} days (${daysSinceOrigin} of 30 consumed).`
    });
  } catch (err) {
    console.error('regenerate error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// SERVE DASHBOARD
// ══════════════════════════════════════════════════════════════════════════════
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin-dashboard.html'));
});

// ══════════════════════════════════════════════════════════════════════════════
// START
// ══════════════════════════════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log('');
  console.log('  ██████╗██████╗  █████╗  ██████╗██╗  ██╗ ██████╗ ██╗  ██╗');
  console.log(' ██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔═████╗╚██╗██╔╝');
  console.log(' ██║     ██████╔╝███████║██║     █████╔╝ ██║██╔██║ ╚███╔╝ ');
  console.log(' ██║     ██╔══██╗██╔══██║██║     ██╔═██╗ ████╔╝██║ ██╔██╗ ');
  console.log(' ╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗╚██████╔╝██╔╝ ██╗');
  console.log('  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝');
  console.log('');
  console.log(`  License Admin Server running`);
  console.log(`  Dashboard  →  http://localhost:${PORT}`);
  console.log(`  DB file    →  ${DB_FILE}`);
  console.log('');
  console.log('  ⚠  Set API_SECRET and ADMIN_PASSWORD env vars before deploying');
  console.log('');

});
