const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
require('dotenv').config();
const app = express();
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/purehai';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const SESSION_DURATION_SECONDS = 12 * 60 * 60;
const REMEMBERED_SESSION_DURATION_SECONDS = 30 * 24 * 60 * 60;
const LOGIN_RESET_KEY = process.env.LOGIN_RESET_KEY || '';
const scrypt = promisify(crypto.scrypt);
const loginAttempts = new Map();
const resetAttempts = new Map();

app.use(express.json({ limit: '1mb' }));

function signSession(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', SESSION_SECRET).update(encoded).digest('base64url');
  return `${encoded}.${signature}`;
}

function signedPayload(req, cookieName) {
  if (!SESSION_SECRET || SESSION_SECRET.length < 32) return false;
  const token = req.headers.cookie?.split(';').map(value => value.trim()).find(value => value.startsWith(`${cookieName}=`))
    ?.slice(cookieName.length + 1);
  if (!token) return false;
  const [encoded, signature] = token.split('.');
  if (!encoded || !signature) return false;
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(encoded).digest();
  let received;
  try { received = Buffer.from(signature, 'base64url'); } catch { return false; }
  if (received.length !== expected.length || !crypto.timingSafeEqual(received, expected)) return false;
  try {
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString());
    return Number(payload.exp) > Math.floor(Date.now() / 1000) ? payload : false;
  } catch { return false; }
}

async function hasValidSession(req) {
  const payload = signedPayload(req, 'purehai_session');
  if (!payload?.username || !payload?.credentialVersion) return false;
  const registration = await AuthConfig.findOne({ key: 'owner' }).lean();
  return Boolean(
    registration?.username &&
    payload.username === registration.username &&
    payload.credentialVersion === registration.credentialVersion
  );
}

function setSessionCookie(res, username, credentialVersion, rememberMe = false) {
  const duration = rememberMe ? REMEMBERED_SESSION_DURATION_SECONDS : SESSION_DURATION_SECONDS;
  const expiresAt = Math.floor(Date.now() / 1000) + duration;
  const token = signSession({ username, credentialVersion, exp: expiresAt });
  res.setHeader('Set-Cookie', `purehai_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${duration}${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`);
}

function validUsername(username) {
  return /^[a-zA-Z0-9._-]{3,32}$/.test(username);
}

function validPassword(password) {
  return typeof password === 'string' && password.length >= 8 && password.length <= 128;
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = await scrypt(password, salt, 64);
  return `${salt}:${derivedKey.toString('hex')}`;
}

async function passwordMatches(password, storedHash) {
  const [salt, storedKey] = String(storedHash || '').split(':');
  if (!salt || !/^[0-9a-f]{128}$/.test(storedKey || '')) return false;
  const derivedKey = await scrypt(password, salt, 64);
  return crypto.timingSafeEqual(derivedKey, Buffer.from(storedKey, 'hex'));
}

function resetKeyMatches(providedKey) {
  if (LOGIN_RESET_KEY.length < 32 || typeof providedKey !== 'string') return false;
  const expected = Buffer.from(LOGIN_RESET_KEY);
  const received = Buffer.from(providedKey);
  return expected.length === received.length && crypto.timingSafeEqual(expected, received);
}

async function requireAuth(req, res, next) {
  try {
    if (await hasValidSession(req)) return next();
    return res.status(401).json({ error: 'Please log in with your username and password.' });
  } catch (err) { next(err); }
}

app.get('/login.css', (req, res) => res.sendFile(path.join(__dirname, 'login.css')));
app.get('/login.js', (req, res) => res.sendFile(path.join(__dirname, 'login.js')));
app.get('/style.css', (req, res) => res.sendFile(path.join(__dirname, 'style.css')));
app.get('/script.js', (req, res) => res.sendFile(path.join(__dirname, 'script.js')));
app.get('/', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  hasValidSession(req).then(authenticated => {
    res.sendFile(path.join(__dirname, authenticated ? 'index.html' : 'login.html'));
  }).catch(err => {
    console.error('Could not check login session:', err.message);
    res.status(500).send('Could not check login session.');
  });
});
app.get('/index.html', requireAuth, (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/api/auth/session', async (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const [credentials, authenticated] = await Promise.all([
      AuthConfig.findOne({ key: 'owner', username: { $exists: true }, passwordHash: { $exists: true } }).lean(),
      hasValidSession(req)
    ]);
    res.json({ authenticated, credentialsConfigured: Boolean(credentials) });
  } catch (err) { next(err); }
});

app.post('/api/auth/setup', async (req, res, next) => {
  const username = String(req.body?.username || '').trim().toLowerCase();
  const password = req.body?.password;
  if (!validUsername(username)) return res.status(400).json({ error: 'Username 3-32 characters ka ho; letters, numbers, dot, underscore ya hyphen use karein.' });
  if (!validPassword(password)) return res.status(400).json({ error: 'Password kam-se-kam 8 aur zyada-se-zyada 128 characters ka hona chahiye.' });
  try {
    const passwordHash = await hashPassword(password);
    const credentialVersion = crypto.randomBytes(16).toString('hex');
    const legacyCredentials = await AuthConfig.findOneAndUpdate(
      { key: 'owner', $or: [{ username: { $exists: false } }, { passwordHash: { $exists: false } }] },
      { $set: { username, passwordHash, credentialVersion }, $unset: { phone: 1 } },
      { new: true }
    );
    const credentials = legacyCredentials || await AuthConfig.create({ key: 'owner', username, passwordHash, credentialVersion });
    setSessionCookie(res, username, credentials.credentialVersion, req.body?.rememberMe === true);
    res.json({ ok: true });
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ error: 'Login pehle se set hai. Apne username aur password se login karein.' });
    next(err);
  }
});

app.post('/api/auth/login', async (req, res, next) => {
  const username = String(req.body?.username || '').trim().toLowerCase();
  const password = req.body?.password;
  if (!validUsername(username) || typeof password !== 'string' || password.length > 128) {
    return res.status(400).json({ error: 'Username aur password darj karein.' });
  }
  const now = Date.now();
  for (const [key, attempt] of loginAttempts) {
    if (now - attempt.startedAt >= 15 * 60 * 1000) loginAttempts.delete(key);
  }
  const attempt = loginAttempts.get(req.ip);
  if (attempt && attempt.count >= 10) {
    res.setHeader('Retry-After', String(Math.ceil((15 * 60 * 1000 - (now - attempt.startedAt)) / 1000)));
    return res.status(429).json({ error: 'Bahut baar galat login hua. 15 minute baad dobara try karein.' });
  }
  try {
    const credentials = await AuthConfig.findOne({ key: 'owner' }).lean();
    if (!credentials?.username || !await passwordMatches(password, credentials.passwordHash)) {
      if (!attempt || now - attempt.startedAt >= 15 * 60 * 1000) loginAttempts.set(req.ip, { startedAt: now, count: 1 });
      else attempt.count += 1;
      return res.status(401).json({ error: 'ID ya password sahi nahi hai.' });
    }
    loginAttempts.delete(req.ip);
    setSessionCookie(res, credentials.username, credentials.credentialVersion, req.body?.rememberMe === true);
    res.json({ ok: true });
  } catch (err) { next(err); }
});

app.post('/api/auth/reset', async (req, res, next) => {
  if (LOGIN_RESET_KEY.length < 32) {
    return res.status(503).json({ error: 'Forgot password reset set nahi hai. Admin .env mein LOGIN_RESET_KEY configure karein.' });
  }
  const now = Date.now();
  for (const [key, attempt] of resetAttempts) {
    if (now - attempt.startedAt >= 15 * 60 * 1000) resetAttempts.delete(key);
  }
  const attempt = resetAttempts.get(req.ip);
  if (attempt && attempt.count >= 5) {
    res.setHeader('Retry-After', String(Math.ceil((15 * 60 * 1000 - (now - attempt.startedAt)) / 1000)));
    return res.status(429).json({ error: 'Reset key bahut baar galat dala gaya. 15 minute baad try karein.' });
  }
  if (!resetKeyMatches(req.body?.resetKey)) {
    if (!attempt || now - attempt.startedAt >= 15 * 60 * 1000) resetAttempts.set(req.ip, { startedAt: now, count: 1 });
    else attempt.count += 1;
    return res.status(401).json({ error: 'Admin reset key sahi nahi hai.' });
  }
  const username = String(req.body?.username || '').trim().toLowerCase();
  const password = req.body?.password;
  if (!validUsername(username)) return res.status(400).json({ error: 'Username 3-32 characters ka ho; letters, numbers, dot, underscore ya hyphen use karein.' });
  if (!validPassword(password)) return res.status(400).json({ error: 'Password kam-se-kam 8 aur zyada-se-zyada 128 characters ka hona chahiye.' });
  try {
    const passwordHash = await hashPassword(password);
    const credentialVersion = crypto.randomBytes(16).toString('hex');
    await AuthConfig.findOneAndUpdate(
      { key: 'owner' },
      { $set: { username, passwordHash, credentialVersion }, $setOnInsert: { key: 'owner' }, $unset: { phone: 1 } },
      { upsert: true, runValidators: true }
    );
    loginAttempts.clear();
    resetAttempts.delete(req.ip);
    setSessionCookie(res, username, credentialVersion);
    res.json({ ok: true });
  } catch (err) { next(err); }
});

app.post('/api/auth/logout', (req, res) => {
  res.setHeader('Set-Cookie', `purehai_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`);
  res.json({ ok: true });
});

const customerSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  name: { type: String, required: true, trim: true },
  phone: { type: String, default: '' },
  address: { type: String, default: '' },
  since: { type: String, default: '' },
  rate: { type: Number, default: 20 },
  status: { type: String, enum: ['Active', 'Inactive'], default: 'Active' }
}, { timestamps: true });

const deliverySchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  customerId: { type: String, required: true },
  date: { type: String, required: true },
  qty: { type: Number, required: true, min: 1 },
  rate: { type: Number, required: true, min: 0 },
  notes: { type: String, default: '' }
}, { timestamps: true });

const paymentSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  customerId: { type: String, required: true },
  date: { type: String, required: true },
  method: { type: String, default: 'Cash' },
  amount: { type: Number, required: true, min: 0.01 },
  notes: { type: String, default: '' }
}, { timestamps: true });
const settingsSchema = new mongoose.Schema({
  key: { type: String, unique: true, default: 'main' },
  businessName: { type: String, default: 'PUREHAI' },
  ownerName: { type: String, default: 'Owner' },
  businessPhone: { type: String, default: '' },
  defaultRate: { type: Number, default: 20 },
  businessAddress: { type: String, default: '' }
}, { timestamps: true });
const authConfigSchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true },
  username: { type: String },
  passwordHash: { type: String },
  credentialVersion: { type: String },
  phone: { type: String, select: false }
}, { timestamps: true });

const Customer = mongoose.model('Customer', customerSchema);
const Delivery = mongoose.model('Delivery', deliverySchema);
const Payment = mongoose.model('Payment', paymentSchema);
const Settings = mongoose.model('Settings', settingsSchema);
const AuthConfig = mongoose.model('AuthConfig', authConfigSchema);

function cleanDocs(docs) { return docs.map(doc => { const obj = doc.toObject(); delete obj._id; delete obj.__v; delete obj.createdAt; delete obj.updatedAt; return obj; }); }
app.get('/api/health', (req, res) => res.json({ ok: true, database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' }));

app.get('/api/data', requireAuth, async (req, res, next) => {
  try {
    const [customers, deliveries, payments, settingsDoc] = await Promise.all([
      Customer.find().sort({ createdAt: -1 }), Delivery.find().sort({ createdAt: -1 }), Payment.find().sort({ createdAt: -1 }), Settings.findOne({ key: 'main' })
    ]);
    const settings = settingsDoc ? { businessName: settingsDoc.businessName, ownerName: settingsDoc.ownerName, businessPhone: settingsDoc.businessPhone, defaultRate: settingsDoc.defaultRate, businessAddress: settingsDoc.businessAddress } : { businessName: 'PUREHAI', ownerName: 'Owner', businessPhone: '', defaultRate: 20, businessAddress: '' };
    res.json({ data: { customers: cleanDocs(customers), deliveries: cleanDocs(deliveries), payments: cleanDocs(payments), settings } });
  } catch (err) { next(err); }
});

// The current frontend edits an in-memory snapshot, so this endpoint saves that snapshot.
// It is intended for this single-owner local app, not simultaneous multi-user editing.
app.put('/api/data', requireAuth, async (req, res, next) => {
  const { customers = [], deliveries = [], payments = [], settings = {} } = req.body || {};
  if (![customers, deliveries, payments].every(Array.isArray)) return res.status(400).json({ error: 'customers, deliveries and payments must be arrays' });
  try {
    await Promise.all([Customer.deleteMany({}), Delivery.deleteMany({}), Payment.deleteMany({})]);
    if (customers.length) await Customer.insertMany(customers.map(c => ({ id: String(c.id), name: String(c.name || '').trim(), phone: String(c.phone || ''), address: String(c.address || ''), since: String(c.since || ''), rate: Number(c.rate ?? 20), status: c.status === 'Inactive' ? 'Inactive' : 'Active' })));
    if (deliveries.length) await Delivery.insertMany(deliveries.map(d => ({ id: String(d.id), customerId: String(d.customerId), date: String(d.date), qty: Number(d.qty), rate: Number(d.rate), notes: String(d.notes || '') })));
    if (payments.length) await Payment.insertMany(payments.map(p => ({ id: String(p.id), customerId: String(p.customerId), date: String(p.date), method: String(p.method || 'Cash'), amount: Number(p.amount), notes: String(p.notes || '') })));
    const savedSettings = await Settings.findOneAndUpdate({ key: 'main' }, { $set: {
      businessName: String(settings.businessName || 'PUREHAI'), ownerName: String(settings.ownerName || 'Owner'),
      businessPhone: String(settings.businessPhone || ''), defaultRate: Number(settings.defaultRate ?? 20), businessAddress: String(settings.businessAddress || '')
    } }, { new: true, upsert: true, runValidators: true });
    res.json({ ok: true, data: { customers, deliveries, payments, settings: { businessName: savedSettings.businessName, ownerName: savedSettings.ownerName, businessPhone: savedSettings.businessPhone, defaultRate: savedSettings.defaultRate, businessAddress: savedSettings.businessAddress } } });
  } catch (err) { next(err); }
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Server/database error', details: process.env.NODE_ENV === 'production' ? undefined : err.message });
});

mongoose.connect(MONGODB_URI).then(() => {
  console.log('MongoDB connected:', MONGODB_URI.replace(/:\/\/.*@/, '://<credentials>@'));
  app.listen(PORT, () => console.log(`PUREHAI running at http://localhost:${PORT}`));
}).catch(err => {
  console.error('Could not connect to MongoDB. Is MongoDB running?');
  console.error(err.message);
  process.exit(1);
});
