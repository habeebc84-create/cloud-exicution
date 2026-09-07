require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const { Pool } = require('pg');
const { v4: uuidv4 } = require('uuid');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// ── DB Pool ──────────────────────────────────────────────────
const pool = new Pool({
  host:     process.env.DB_HOST     || 'db',
  port:     parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME     || 'cloudguard',
  user:     process.env.DB_USER     || 'cloudguard',
  password: process.env.DB_PASSWORD || 'cloudguard_secret',
});

// Retry DB connection on startup (DB may not be ready immediately)
async function waitForDB(retries = 10) {
  for (let i = 0; i < retries; i++) {
    try {
      await pool.query('SELECT 1');
      console.log('✅  Connected to PostgreSQL');
      return;
    } catch (e) {
      console.log(`⏳  Waiting for DB... attempt ${i + 1}/${retries}`);
      await new Promise(r => setTimeout(r, 2000));
    }
  }
  console.error('❌  Could not connect to PostgreSQL. Exiting.');
  process.exit(1);
}

// ── Health ───────────────────────────────────────────────────
app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', timestamp: new Date() });
  } catch (e) {
    res.status(503).json({ status: 'db_unavailable', error: e.message });
  }
});

// ── Threat Events ────────────────────────────────────────────
// GET  /api/events         — list latest 200 events
// POST /api/events         — save a new event
app.get('/api/events', async (_req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM threat_events ORDER BY ts DESC LIMIT 200`
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/events', async (req, res) => {
  const { type, protocol, ip_address, message, score, model } = req.body;
  if (!type || !message) {
    return res.status(400).json({ error: 'type and message are required' });
  }
  try {
    const { rows } = await pool.query(
      `INSERT INTO threat_events (id, type, protocol, ip_address, message, score, model)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING *`,
      [uuidv4(), type, protocol, ip_address, message, score, model]
    );
    res.status(201).json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Alerts / Incidents ───────────────────────────────────────
// GET   /api/alerts           — list all alerts
// POST  /api/alerts           — create new alert
// PATCH /api/alerts/:id/resolve — resolve an alert
app.get('/api/alerts', async (_req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM alerts ORDER BY ts DESC`
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/alerts', async (req, res) => {
  const { severity, title, source } = req.body;
  if (!severity || !title) {
    return res.status(400).json({ error: 'severity and title are required' });
  }
  try {
    const { rows } = await pool.query(
      `INSERT INTO alerts (id, severity, title, source, status)
       VALUES ($1,$2,$3,$4,'open')
       RETURNING *`,
      [uuidv4(), severity, title, source]
    );
    res.status(201).json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch('/api/alerts/:id/resolve', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `UPDATE alerts SET status='resolved', resolved_at=NOW()
       WHERE id=$1 RETURNING *`,
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Alert not found' });
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Reports ──────────────────────────────────────────────────
// GET  /api/reports  — list saved reports
// POST /api/reports  — save a report
app.get('/api/reports', async (_req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, title, threat_count, event_count, model, created_at
       FROM reports ORDER BY created_at DESC`
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/reports', async (req, res) => {
  const { title, threat_count, event_count, model, payload } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO reports (id, title, threat_count, event_count, model, payload)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING *`,
      [uuidv4(), title, threat_count, event_count, model, JSON.stringify(payload)]
    );
    res.status(201).json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Audit Log ────────────────────────────────────────────────
// GET  /api/audit  — list audit log entries
// POST /api/audit  — add entry
app.get('/api/audit', async (_req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM audit_logs ORDER BY ts DESC LIMIT 500`
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/audit', async (req, res) => {
  const { category, message } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO audit_logs (id, category, message) VALUES ($1,$2,$3) RETURNING *`,
      [uuidv4(), category, message]
    );
    res.status(201).json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Connected Devices ────────────────────────────────────────
// GET   /api/devices      — list all connected cloud devices
// PATCH /api/devices/:id  — update device status or isolation
app.get('/api/devices', async (_req, res) => {
  try {
    const { rows } = await pool.query(`SELECT * FROM devices ORDER BY name ASC`);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch('/api/devices/:id', async (req, res) => {
  const { id } = req.params;
  const { status, isolated } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE devices SET status = COALESCE($1, status), isolated = COALESCE($2, isolated), updated_at = NOW()
       WHERE id = $3 RETURNING *`,
      [status, isolated, id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Device not found' });
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Stats ────────────────────────────────────────────────────
app.get('/api/stats', async (_req, res) => {
  try {
    const [events, alerts, threats] = await Promise.all([
      pool.query(`SELECT COUNT(*) AS count FROM threat_events`),
      pool.query(`SELECT COUNT(*) AS count FROM alerts WHERE status='open'`),
      pool.query(`SELECT COUNT(*) AS count FROM alerts WHERE severity IN ('critical','high') AND status='open'`)
    ]);
    res.json({
      total_events:    parseInt(events.rows[0].count),
      open_alerts:     parseInt(alerts.rows[0].count),
      active_threats:  parseInt(threats.rows[0].count),
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Start ────────────────────────────────────────────────────
waitForDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀  CloudGuard API running on port ${PORT}`);
  });
});
