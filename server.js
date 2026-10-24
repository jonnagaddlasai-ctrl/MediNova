const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || 'development';
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error('Set SESSION_SECRET to a random secret of at least 32 characters in .env');
  process.exit(1);
}
if (NODE_ENV === 'production') app.set('trust proxy', 1);
const allowedOrigin = process.env.FRONTEND_ORIGIN || '';
if (allowedOrigin) {
  app.use(cors({ origin: allowedOrigin, credentials: true, methods: ['GET','POST','OPTIONS'], allowedHeaders: ['Content-Type'] }));
  app.options('*', cors({ origin: allowedOrigin, credentials: true }));
}

const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'users.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)`);

app.disable('x-powered-by');
app.use(helmet({
  // This app currently contains inline CSS/JS; add nonces before enabling a strict CSP.
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: '10kb', strict: true }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: 'draft-7', legacyHeaders: false }));
app.use(session({
  name: 'hh.sid',
  secret: SESSION_SECRET,
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: dataDir, concurrentDB: true }),
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    sameSite: NODE_ENV === 'production' && allowedOrigin ? 'none' : 'lax',
    secure: NODE_ENV === 'production',
    maxAge: 8 * 60 * 60 * 1000
  }
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 10,
  standardHeaders: 'draft-7', legacyHeaders: false,
  message: { error: 'Too many attempts. Please wait 15 minutes and try again.' }
});
const cleanEmail = value => typeof value === 'string' && value.trim().length <= 254
  ? value.trim().toLowerCase() : '';
function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
}
function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Please sign in to continue.' });
  next();
}
function createSession(req, user, res) {
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'Could not create a secure session.' });
    req.session.user = { id: user.id, email: user.email };
    req.session.save(err2 => {
      if (err2) return res.status(500).json({ error: 'Could not save session.' });
      res.json({ ok: true, user: req.session.user });
    });
  });
}

app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'Smart Healthcare & Biotech backend' }));
app.get('/api/auth/me', (req, res) => res.json({ user: req.session.user || null }));

app.post('/api/auth/register', authLimiter, async (req, res) => {
  const email = cleanEmail(req.body && req.body.email);
  const password = req.body && req.body.password;
  if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (typeof password !== 'string' || password.length < 12 || password.length > 128) {
    return res.status(400).json({ error: 'Password must be 12–128 characters long.' });
  }
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password)) {
    return res.status(400).json({ error: 'Use at least one uppercase letter, one lowercase letter, and one number.' });
  }
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)').run(email, hash);
    return createSession(req, { id: Number(result.lastInsertRowid), email }, res);
  } catch (err) {
    if (String(err.code) === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({ error: 'An account with this email already exists.' });
    console.error('Registration error:', err.message);
    return res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const email = cleanEmail(req.body && req.body.email);
  const password = req.body && req.body.password;
  if (!validEmail(email) || typeof password !== 'string' || password.length > 128) {
    return res.status(400).json({ error: 'Enter a valid email and password.' });
  }
  try {
    const user = db.prepare('SELECT id, email, password_hash FROM users WHERE email = ?').get(email);
    const ok = user ? await bcrypt.compare(password, user.password_hash) : false;
    if (!ok) return res.status(401).json({ error: 'Incorrect email or password.' });
    return createSession(req, { id: user.id, email: user.email }, res);
  } catch (err) {
    console.error('Login error:', err.message);
    return res.status(500).json({ error: 'Sign-in failed. Please try again.' });
  }
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  req.session.destroy(err => {
    res.clearCookie('hh.sid', { httpOnly: true, sameSite: 'lax', secure: NODE_ENV === 'production' });
    if (err) return res.status(500).json({ error: 'Could not sign out.' });
    res.json({ ok: true });
  });
});

// Example of a protected API route. Keep actual medical data in a properly governed database.
app.get('/api/account', requireAuth, (req, res) => res.json({ user: req.session.user }));

app.use(express.static(path.join(__dirname, 'public'), {
  index: 'index.html',
  setHeaders(res, filePath) {
    if (filePath.endsWith('.html')) res.setHeader('Cache-Control', 'no-store');
  }
}));
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.use((err, _req, res, _next) => {
  console.error('Unhandled server error:', err.message);
  res.status(500).json({ error: 'An unexpected server error occurred.' });
});
app.listen(PORT, () => console.log(`Smart Healthcare & Biotech running on http://localhost:${PORT}`));
