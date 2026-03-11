const express = require('express');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3006;
const DB_FILE = path.join(__dirname, 'licenses_db.json');

const API_SECRET     = process.env.API_SECRET     || 'crack0x-secret-2024';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'crack0x-admin';

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

function requireSecret(req, res, next) {
  if (req.headers['x-license-secret'] !== API_SECRET) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

const adminSessions = new Set();

function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'] || req.query.token;
  if (!adminSessions.has(token)) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

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
  if (req.body.password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Invalid password' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  adminSessions.add(token);
  setTimeout(() => adminSessions.delete(token), 8 * 60 * 60 * 1000);
  res.json({ token });
});

app.post('/api/admin/logout', requireAdmin, (req, res) => {
  adminSessions.delete(req.headers['x-admin-token']);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════════════════════
// APP-FACING ENDPOINTS
// ══════════════════════════════════════════════════════════════════════════════

// Register / update license
app.post('/api/licenses/register', requireSecret, (req, res) => {
  try {
    const licenseData = req.body;
    if (!licenseData.machine_id || !licenseData.license_key) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const db       = readDB();
    const machineId = licenseData.machine_id;
    const existing  = db.records[machineId];

    const historyEntry = {
      license_key:         licenseData.license_key,
      generated_at:        licenseData.created_at,
      expires_at:          licenseData.expires_at,
      total_days_consumed: licenseData.total_days_consumed ?? licenseData.days_deducted ?? 0,
      generation_number:   licenseData.generation_count ?? 1,
      revoked:             false
    };

    const existingHistory = existing?.history ?? [];
    const alreadyLogged   = existingHistory.some(h => h.license_key === licenseData.license_key);
    const updatedHistory  = alreadyLogged ? existingHistory : [...existingHistory, historyEntry];

    db.records[machineId] = {
      machine_id:           machineId,
      hostname:             licenseData.hostname        ?? existing?.hostname        ?? 'unknown',
      platform:             licenseData.platform        ?? existing?.platform        ?? 'unknown',
      license_key:          licenseData.license_key,
      original_created_at:  licenseData.original_created_at ?? licenseData.created_at,
      last_generated_at:    licenseData.created_at,
      expires_at:           licenseData.expires_at,
      activated:            licenseData.activated        ?? existing?.activated        ?? false,
      activation_date:      licenseData.activation_date  ?? existing?.activation_date  ?? null,
      total_days_consumed:  licenseData.total_days_consumed ?? licenseData.days_deducted ?? 0,
      generation_count:     licenseData.generation_count ?? 1,
      revoked:              existing?.revoked    ?? false,  // NEVER overwrite revocation from app
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

// Check revocation status (called on every validation)
app.get('/api/licenses/check/:machineId', requireSecret, (req, res) => {
  try {
    const db     = readDB();
    const record = db.records[req.params.machineId];

    if (!record) return res.json({ found: false, revoked: false });

    record.last_seen = new Date().toISOString();
    record.ip        = req.ip;
    writeDB(db);

    res.json({
      found:               true,
      revoked:             record.revoked,
      revoked_reason:      record.revoked_reason      ?? null,
      original_created_at: record.original_created_at,
      total_days_consumed: record.total_days_consumed,
      generation_count:    record.generation_count,
      created_at:          record.original_created_at
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ── NEW: Fetch full license data (called when local file is deleted) ──────────
// Allows the app to restore itself from the server without generating a new key.
app.get('/api/licenses/fetch/:machineId', requireSecret, (req, res) => {
  try {
    const db     = readDB();
    const record = db.records[req.params.machineId];

    if (!record) return res.json({ found: false });

    // Return the full license object the app needs to reconstruct its local file
    const license = {
      license_key:         record.license_key,
      created_at:          record.last_generated_at,
      original_created_at: record.original_created_at,
      expires_at:          record.expires_at,
      activated:           record.activated,
      activation_date:     record.activation_date,
      machine_id:          record.machine_id,
      hostname:            record.hostname,
      platform:            record.platform,
      is_renewal:          (record.generation_count ?? 1) > 1,
      days_deducted:       record.total_days_consumed ?? 0,
      total_days_consumed: record.total_days_consumed ?? 0,
      original_validity:   30,
      actual_validity:     Math.max(1, 30 - (record.total_days_consumed ?? 0)),
      generation_count:    record.generation_count ?? 1,
      revoked:             record.revoked ?? false
    };

    res.json({ found: true, license });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// ADMIN API ENDPOINTS
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/admin/licenses', requireAdmin, (req, res) => {
  const db = readDB();
  const records = Object.values(db.records).sort(
    (a, b) => new Date(b.last_generated_at) - new Date(a.last_generated_at)
  );
  res.json(records);
});

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const db      = readDB();
  const records = Object.values(db.records);
  const now     = new Date();
  res.json({
    total:     records.length,
    active:    records.filter(r => !r.revoked && new Date(r.expires_at) > now).length,
    revoked:   records.filter(r => r.revoked).length,
    expired:   records.filter(r => !r.revoked && new Date(r.expires_at) <= now).length,
    activated: records.filter(r => r.activated).length
  });
});

app.post('/api/admin/revoke/:machineId', requireAdmin, (req, res) => {
  try {
    const db = readDB();
    const record = db.records[req.params.machineId];
    if (!record) return res.status(404).json({ error: 'Not found' });
    record.revoked        = true;
    record.revoked_at     = new Date().toISOString();
    record.revoked_reason = req.body.reason ?? '';
    record.history        = record.history.map(h =>
      h.license_key === record.license_key ? { ...h, revoked: true } : h
    );
    writeDB(db);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

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
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.put('/api/admin/notes/:machineId', requireAdmin, (req, res) => {
  try {
    const db = readDB();
    const record = db.records[req.params.machineId];
    if (!record) return res.status(404).json({ error: 'Not found' });
    record.notes = req.body.notes ?? '';
    writeDB(db);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/admin/licenses/:machineId', requireAdmin, (req, res) => {
  try {
    const db = readDB();
    if (!db.records[req.params.machineId]) return res.status(404).json({ error: 'Not found' });
    delete db.records[req.params.machineId];
    writeDB(db);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/admin/regenerate/:machineId', requireAdmin, (req, res) => {
  try {
    const db = readDB();
    const record = db.records[req.params.machineId];
    if (!record) return res.status(404).json({ error: 'Not found' });

    const now            = new Date();
    const anchor         = new Date(record.original_created_at);
    const daysSinceOrigin = Math.max(1, Math.min(30, Math.floor((now - anchor) / 86400000)));
    const validityDays   = Math.max(1, 30 - daysSinceOrigin);
    const expiresAt      = new Date(now.getTime() + validityDays * 86400000);

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
    record.revoked             = false;
    record.revoked_at          = null;
    record.revoked_reason      = null;
    record.history             = [...(record.history ?? []), newHistory];

    writeDB(db);
    res.json({
      ok: true, newKey, validityDays,
      daysConsumed: daysSinceOrigin,
      expiresAt:    expiresAt.toISOString(),
      message:      `New key generated. Valid for ${validityDays} days (${daysSinceOrigin} of 30 consumed).`
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
  console.log(`\n  CRACK0X License Server\n  Port: ${PORT}\n  DB: ${DB_FILE}\n`);
});
