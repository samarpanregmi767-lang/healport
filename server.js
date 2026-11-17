// HealPort prototype API. One file, two modes:
//   MODE=vulnerable  -> Version 1 (intentional flaws, for the "before" attacks)
//   MODE=secure      -> Version 2 (controls from the STRIDE table, for the "after" attacks)
require('dotenv').config();
const express = require('express'), Database = require('better-sqlite3');
const bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'), crypto = require('crypto');
const SECURE = process.env.MODE === 'secure';
const SECRET = process.env.JWT_SECRET || 'dev-only-change-me';
const KEY = crypto.createHash('sha256').update(process.env.DATA_KEY || 'change-this-data-key').digest();
const db = new Database(SECURE ? 'secure.db' : 'vulnerable.db');
db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT);
CREATE TABLE IF NOT EXISTS appointments(id INTEGER PRIMARY KEY, patient_id INT, doctor TEXT, time TEXT, reason TEXT);
CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY, patient_id INT, note TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts TEXT, user TEXT, action TEXT)`);

// S/I: AES-256-GCM encryption of medical notes (secure mode only)
const enc = t => { if (!SECURE) return t; const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const d = Buffer.concat([c.update(t, 'utf8'), c.final()]); return [iv, c.getAuthTag(), d].map(b => b.toString('hex')).join(':'); };
const dec = t => { if (!SECURE) return t; const [iv, tag, d] = t.split(':').map(h => Buffer.from(h, 'hex'));
  const c = crypto.createDecipheriv('aes-256-gcm', KEY, iv); c.setAuthTag(tag); return c.update(d, null, 'utf8') + c.final('utf8'); };
// R: audit log (secure mode only)
const log = (user, action) => SECURE && db.prepare('INSERT INTO audit(ts,user,action) VALUES(?,?,?)').run(new Date().toISOString(), user, action);

if (!db.prepare('SELECT COUNT(*) n FROM users').get().n) {
  const add = db.prepare('INSERT INTO users(username,password,role) VALUES(?,?,?)');
  [['admin', 'Admin#2026', 'admin'], ['dr.kim', 'Doc#2026', 'doctor'], ['pat1', 'Pat1#2026', 'patient'], ['pat2', 'Pat2#2026', 'patient']]
    .forEach(([u, p, r]) => add.run(u, SECURE ? bcrypt.hashSync(p, 10) : p, r));
  db.prepare('INSERT INTO records(patient_id,note) VALUES(?,?)').run(3, enc('Hypertension, Amlodipine 5mg'));
  db.prepare('INSERT INTO records(patient_id,note) VALUES(?,?)').run(4, enc('Type 2 diabetes, Metformin 500mg'));
}

const app = express();
app.use(express.json({ limit: '10kb' }));
if (SECURE) { // D + I: security headers and rate limiting
  const helmet = require('helmet'), rl = require('express-rate-limit');
  app.use(helmet());
  app.use('/api/', rl({ windowMs: 60_000, max: 100 }));
  app.use('/api/login', rl({ windowMs: 3_600_000, max: 5, skipSuccessfulRequests: true, message: { error: 'Too many login attempts' } }));
}

// S + E: authentication and role-based access control
const auth = (...roles) => (req, res, next) => {
  try { req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET); } catch { return res.status(401).json({ error: 'Login required' }); }
  if (SECURE && roles.length && !roles.includes(req.user.role)) { log(req.user.username, 'DENIED ' + req.method + ' ' + req.originalUrl); return res.status(403).json({ error: 'Forbidden' }); }
  next();
};

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  let u;
  if (!SECURE) { // VULNERABLE: string concatenation = SQL injection
    try { u = db.prepare(`SELECT * FROM users WHERE username='${username}' AND password='${password}'`).get(); } catch { return res.status(500).json({ error: 'SQL error' }); }
  } else {
    if (typeof username !== 'string' || typeof password !== 'string' || username.length > 50) return res.status(400).json({ error: 'Invalid input' });
    u = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (u && !bcrypt.compareSync(password, u.password)) u = null;
  }
  if (!u) { log(String(username), 'failed login'); return res.status(401).json({ error: 'Invalid credentials' }); }
  log(u.username, 'login');
  res.json({ token: jwt.sign({ id: u.id, username: u.username, role: u.role }, SECRET, SECURE ? { expiresIn: '1h' } : {}) });
});

app.get('/api/appointments', auth(), (req, res) => {
  const rows = SECURE && req.user.role === 'patient'
    ? db.prepare('SELECT * FROM appointments WHERE patient_id = ?').all(req.user.id)
    : db.prepare('SELECT * FROM appointments').all();
  res.json(rows);
});
app.post('/api/appointments', auth('patient'), (req, res) => {
  const { doctor, time, reason } = req.body || {};
  if (SECURE && !(typeof doctor === 'string' && /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/.test(time) && String(reason || '').length <= 200)) return res.status(400).json({ error: 'Invalid input' });
  db.prepare('INSERT INTO appointments(patient_id,doctor,time,reason) VALUES(?,?,?,?)').run(req.user.id, doctor, time, reason);
  log(req.user.username, 'booked appointment'); res.status(201).json({ ok: true });
});

app.get('/api/records/:id', auth(), (req, res) => {
  const r = db.prepare('SELECT * FROM records WHERE id = ?').get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Not found' });
  // VULNERABLE: no ownership check (IDOR). SECURE: patients may only read their own.
  if (SECURE && req.user.role === 'patient' && r.patient_id !== req.user.id) { log(req.user.username, 'DENIED record ' + r.id); return res.status(403).json({ error: 'Forbidden' }); }
  log(req.user.username, 'read record ' + r.id); res.json({ id: r.id, patient_id: r.patient_id, note: dec(r.note) });
});
app.post('/api/records', auth('doctor'), (req, res) => {
  const { patient_id, note } = req.body || {};
  if (SECURE && !(Number.isInteger(patient_id) && typeof note === 'string' && note.length <= 500)) return res.status(400).json({ error: 'Invalid input' });
  db.prepare('INSERT INTO records(patient_id,note) VALUES(?,?)').run(patient_id, enc(note));
  log(req.user.username, 'added record for patient ' + patient_id); res.status(201).json({ ok: true });
});

app.get('/api/admin/users', auth('admin'), (req, res) => res.json(db.prepare('SELECT id,username,role FROM users').all()));
app.get('/api/admin/audit', auth('admin'), (req, res) => res.json(db.prepare('SELECT * FROM audit ORDER BY id DESC LIMIT 100').all()));

app.listen(process.env.PORT || 3000, () => console.log(`HealPort API [${SECURE ? 'SECURE' : 'VULNERABLE'}] on port ${process.env.PORT || 3000}`));
