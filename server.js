const express   = require('express');
const fs        = require('fs');
const path      = require('path');
const crypto    = require('crypto');
const bcrypt    = require('bcryptjs');
const Babel     = require('@babel/standalone');
const postcss   = require('postcss');
const tailwind  = require('tailwindcss');

const app  = express();
const PORT = process.env.PORT || 3002;
app.use(express.json());

// ─── Security headers ─────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// ─── Firebase config ────────────────────────────────────────────────────────
const API_KEY    = process.env.FIREBASE_API_KEY;
const PROJECT_ID = process.env.FIREBASE_PROJECT_ID || 'r3zahlen';
if (!API_KEY) { console.error('FEHLER: FIREBASE_API_KEY fehlt in .env'); process.exit(1); }
const firebaseConfig = JSON.stringify({
  apiKey:            API_KEY,
  authDomain:        process.env.FIREBASE_AUTH_DOMAIN        || `${PROJECT_ID}.firebaseapp.com`,
  projectId:         PROJECT_ID,
  storageBucket:     process.env.FIREBASE_STORAGE_BUCKET     || `${PROJECT_ID}.firebasestorage.app`,
  messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID || '',
  appId:             process.env.FIREBASE_APP_ID             || '',
});

// ─── Server-side Firestore proxy (bypasses security rules via anon auth) ────
let _idToken = null, _refreshToken = null, _tokenExpiry = 0;

async function getToken() {
  const now = Date.now();
  if (_idToken && now < _tokenExpiry - 60_000) return _idToken;
  if (_refreshToken) {
    try {
      const r = await fetch(`https://securetoken.googleapis.com/v1/token?key=${API_KEY}`,
        { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'},
          body:`grant_type=refresh_token&refresh_token=${_refreshToken}` });
      const d = await r.json();
      if (d.id_token) { _idToken=d.id_token; _refreshToken=d.refresh_token; _tokenExpiry=now+(+d.expires_in||3600)*1000; return _idToken; }
    } catch {}
  }
  // Anonymous sign-in
  const r = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${API_KEY}`,
    { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({returnSecureToken:true}) });
  const d = await r.json();
  _idToken=d.idToken; _refreshToken=d.refreshToken; _tokenExpiry=now+(+d.expiresIn||3600)*1000;
  return _idToken;
}

function fsUrl(col, docId='') {
  return `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/${col}${docId?'/'+docId:''}`;
}

function toFsValue(v) {
  if (v === null || v === undefined) return { nullValue: null };
  if (typeof v === 'string')  return { stringValue: v };
  if (typeof v === 'boolean') return { booleanValue: v };
  if (typeof v === 'number')  return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
  if (Array.isArray(v))       return { arrayValue: { values: v.map(toFsValue) } };
  if (typeof v === 'object')  return { mapValue: { fields: Object.fromEntries(Object.entries(v).map(([k,val])=>[k,toFsValue(val)])) } };
  return { stringValue: String(v) };
}

function fromFsValue(fv) {
  if (!fv) return null;
  if ('stringValue'  in fv) return fv.stringValue;
  if ('integerValue' in fv) return parseInt(fv.integerValue);
  if ('doubleValue'  in fv) return fv.doubleValue;
  if ('booleanValue' in fv) return fv.booleanValue;
  if ('nullValue'    in fv) return null;
  if ('arrayValue'   in fv) return (fv.arrayValue.values||[]).map(fromFsValue);
  if ('mapValue'     in fv) return Object.fromEntries(Object.entries(fv.mapValue.fields||{}).map(([k,v])=>[k,fromFsValue(v)]));
  return null;
}

async function fsGetCollection(col) {
  try {
    const token = await getToken();
    const r = await fetch(fsUrl(col), { headers:{ Authorization:`Bearer ${token}` } });
    if (!r.ok) { console.warn('fsGet failed', r.status, col); return null; }
    const d = await r.json();
    if (!d.documents) return [];
    return d.documents.map(doc => ({ id: doc.name.split('/').pop(), ...Object.fromEntries(Object.entries(doc.fields||{}).map(([k,v])=>[k,fromFsValue(v)])) }));
  } catch(e) { console.warn('fsGetCollection error:', e.message); return null; }
}

async function fsSet(col, docId, data) {
  try {
    const token = await getToken();
    const fields = Object.fromEntries(Object.entries(data).map(([k,v])=>[k,toFsValue(v)]));
    if (docId) {
      await fetch(fsUrl(col, docId), { method:'PATCH', headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'}, body:JSON.stringify({fields}) });
    } else {
      const r = await fetch(fsUrl(col), { method:'POST', headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'}, body:JSON.stringify({fields}) });
      const d = await r.json(); return d.name?.split('/').pop();
    }
  } catch(e) { console.warn('fsSet error:', e.message); }
}

async function fsDelete(col, docId) {
  try {
    const token = await getToken();
    await fetch(fsUrl(col, docId), { method:'DELETE', headers:{Authorization:`Bearer ${token}`} });
  } catch(e) { console.warn('fsDelete error:', e.message); }
}

async function fsGetDoc(col, docId) {
  try {
    const token = await getToken();
    const r = await fetch(fsUrl(col, docId), { headers:{ Authorization:`Bearer ${token}` } });
    if (!r.ok) { console.warn('fsGetDoc failed', r.status, col, docId); return null; }
    const d = await r.json();
    if (!d.fields) return null;
    return Object.fromEntries(Object.entries(d.fields).map(([k,v])=>[k,fromFsValue(v)]));
  } catch(e) { console.warn('fsGetDoc error:', e.message); return null; }
}

// ─── HMAC session system ──────────────────────────────────────────────────────
const SESSION_SECRET = process.env.SESSION_SECRET ||
  crypto.createHash('sha256').update((process.env.FIREBASE_API_KEY || '') + ':session-v1').digest('hex');
const SESSION_TTL = 7 * 24 * 3600_000;

function createSession(user) {
  const payload = { ...user, exp: Date.now() + SESSION_TTL };
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig  = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verifySession(token) {
  if (!token) return null;
  try {
    const dot = token.lastIndexOf('.');
    if (dot < 0) return null;
    const data = token.slice(0, dot), sig = token.slice(dot + 1);
    const expected = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
    const a = Buffer.from(sig, 'ascii'), b = Buffer.from(expected, 'ascii');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    if (Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

function authMiddleware(req, res, next) {
  const payload = verifySession(req.headers['x-session']);
  if (!payload) return res.status(401).json({ error: 'Sitzung abgelaufen – bitte neu anmelden' });
  req.user = payload;
  next();
}

// ─── Rate limiter (simple in-memory) ─────────────────────────────────────────
const _loginAttempts = new Map();
function loginRateLimit(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const now = Date.now();
  const entry = _loginAttempts.get(ip) || { count: 0, resetAt: now + 60_000 };
  if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + 60_000; }
  entry.count++;
  _loginAttempts.set(ip, entry);
  if (entry.count > 20) return res.status(429).json({ error: 'Zu viele Anmeldeversuche – bitte warten' });
  next();
}

// ─── API routes ──────────────────────────────────────────────────────────────
// POST /api/login  { name, pin }  → verify credentials, return HMAC session token
app.post('/api/login', loginRateLimit, async (req, res) => {
  try {
    const { name, pin } = req.body || {};
    if (!name || !pin) return res.status(400).json({ error: 'Name und PIN erforderlich' });

    const nameLC = String(name).trim().toLowerCase();
    const pinStr = String(pin).trim();

    // ── Owner / admin login ───────────────────────────────────────────────────
    if (nameLC === 'admin') {
      const authDoc = await fsGetDoc('config', 'auth');
      const storedPin = authDoc?.adminPin || null;
      if (!storedPin) {
        // No PIN set — accept default hardcoded fallback (first-run only)
        const DEFAULT_OWNER_PIN = 'K21ADMIN';
        if (pinStr !== DEFAULT_OWNER_PIN) return res.status(401).json({ error: 'Name oder PIN nicht korrekt' });
      } else {
        // Compare: bcrypt hash or plaintext legacy
        const isHash = String(storedPin).startsWith('$2');
        const ok = isHash
          ? await bcrypt.compare(pinStr, storedPin)
          : String(storedPin) === pinStr;
        if (!ok) return res.status(401).json({ error: 'Name oder PIN nicht korrekt' });
        // Auto-migrate plaintext to bcrypt
        if (!isHash) {
          const hashed = await bcrypt.hash(pinStr, 12);
          await fsSet('config', 'auth', { ...authDoc, adminPin: hashed });
        }
      }
      const userInfo = { id: '__owner__', name: 'Admin', role: 'owner' };
      return res.json({ ok: true, ...userInfo, token: createSession(userInfo) });
    }

    // ── Regular user login ────────────────────────────────────────────────────
    const users = await fsGetCollection('cafe-users');
    if (!users) return res.status(503).json({ error: 'Firestore nicht erreichbar' });

    const u = users.find(x => (x.name || '').trim().toLowerCase() === nameLC);
    if (!u) return res.status(401).json({ error: 'Name oder PIN nicht korrekt' });

    const storedPin = u.pin != null ? String(u.pin) : '';
    const isHash = storedPin.startsWith('$2');
    const ok = isHash
      ? await bcrypt.compare(pinStr, storedPin)
      : storedPin === pinStr;
    if (!ok) return res.status(401).json({ error: 'Name oder PIN nicht korrekt' });

    // Auto-migrate plaintext PIN to bcrypt
    if (!isHash) {
      const hashed = await bcrypt.hash(pinStr, 12);
      await fsSet('cafe-users', u.id, { ...u, pin: hashed });
    }

    const userInfo = { id: u.id, name: u.name, role: u.role || 'kassierer', farbe: u.farbe || '#8b5cf6', areaAccess: u.areaAccess || '__all__', dsgvoConsent: u.dsgvoConsent || false };
    return res.json({ ok: true, ...userInfo, token: createSession(userInfo) });
  } catch (e) {
    console.error('login error:', e.message);
    res.status(500).json({ error: 'Interner Fehler' });
  }
});

// POST /api/logout
app.post('/api/logout', (req, res) => res.json({ ok: true }));

// GET /api/data?c=k21-cafe  → read the 'data' document
app.get('/api/data', async (req, res) => {
  const col = req.query.c || 'k21-cafe';
  const data = await fsGetDoc(col, 'data');
  if (data === null) return res.status(503).json({ error: 'Firestore nicht erreichbar' });
  res.json(data);
});

// POST /api/data?c=k21-cafe  → overwrite the 'data' document
app.post('/api/data', async (req, res) => {
  const col = req.query.c || 'k21-cafe';
  await fsSet(col, 'data', req.body);
  res.json({ ok: true });
});

// GET /api/doc?c=config&d=cafe-profiles  → read any single document
app.get('/api/doc', async (req, res) => {
  const col = req.query.c; const docId = req.query.d;
  if (!col || !docId) return res.status(400).json({ error: 'missing c or d' });
  const data = await fsGetDoc(col, docId);
  if (data === null) return res.status(503).json({ error: 'Firestore nicht erreichbar' });
  res.json(data);
});

// GET /api/users?c=cafe-users   → list all users in a collection
app.get('/api/users', async (req, res) => {
  const col = req.query.c || 'cafe-users';
  const users = await fsGetCollection(col);
  if (users === null) return res.status(503).json({ error: 'Firestore nicht erreichbar' });
  res.json(users);
});

// POST /api/users?c=cafe-users   → create user  { body: user data }
app.post('/api/users', authMiddleware, async (req, res) => {
  const col = req.query.c || 'cafe-users';
  const id = await fsSet(col, null, { ...req.body, createdAt: new Date().toISOString() });
  res.json({ id });
});

// PUT /api/users/:id?c=cafe-users  → update user
// Merge with the existing document so fields not sent (e.g. pin) are preserved —
// a bare PATCH would wipe them.
app.put('/api/users/:id', authMiddleware, async (req, res) => {
  const col = req.query.c || 'cafe-users';
  const existing = await fsGetDoc(col, req.params.id) || {};
  await fsSet(col, req.params.id, { ...existing, ...req.body });
  res.json({ ok: true });
});

// DELETE /api/users/:id?c=cafe-users
app.delete('/api/users/:id', authMiddleware, async (req, res) => {
  const col = req.query.c || 'cafe-users';
  await fsDelete(col, req.params.id);
  res.json({ ok: true });
});

// GET /api/admin-pin   → owner PIN from Firestore
app.get('/api/admin-pin', async (req, res) => {
  try {
    const token = await getToken();
    const r = await fetch(fsUrl('config','auth'), { headers:{ Authorization:`Bearer ${token}` } });
    const d = await r.json();
    const pin = fromFsValue(d?.fields?.adminPin);
    res.json({ pin: pin || null });
  } catch { res.json({ pin: null }); }
});

// POST /api/admin-pin  { pin: '...' }  → save owner PIN
app.post('/api/admin-pin', async (req, res) => {
  await fsSet('config', 'auth', { adminPin: req.body.pin });
  res.json({ ok: true });
});

// POST /api/change-pin  { oldPin, newPin }
app.post('/api/change-pin', authMiddleware, async (req, res) => {
  try {
    const { oldPin, newPin } = req.body || {};
    if (!oldPin || !newPin) return res.status(400).json({ error: 'Alter und neuer PIN erforderlich' });
    const newStr = String(newPin).trim();
    if (newStr.length < 4) return res.status(400).json({ error: 'PIN muss mind. 4 Zeichen haben' });
    if (req.user.id === '__owner__') {
      const authDoc = await fsGetDoc('config', 'auth') || {};
      const stored = authDoc.adminPin || null;
      const ok = stored ? (stored.startsWith('$2') ? await bcrypt.compare(String(oldPin), stored) : String(oldPin) === stored) : String(oldPin) === 'K21ADMIN';
      if (!ok) return res.status(401).json({ error: 'Alter PIN ist nicht korrekt' });
      await fsSet('config', 'auth', { ...authDoc, adminPin: await bcrypt.hash(newStr, 12) });
    } else {
      const u = await fsGetDoc('cafe-users', req.user.id);
      if (!u) return res.status(404).json({ error: 'Benutzer nicht gefunden' });
      const stored = u.pin != null ? String(u.pin) : '';
      const ok = stored.startsWith('$2') ? await bcrypt.compare(String(oldPin), stored) : stored === String(oldPin);
      if (!ok) return res.status(401).json({ error: 'Alter PIN ist nicht korrekt' });
      await fsSet('cafe-users', req.user.id, { ...u, pin: await bcrypt.hash(newStr, 12) });
    }
    res.json({ ok: true });
  } catch(e) { console.error('change-pin:', e.message); res.status(500).json({ error: 'Fehler beim PIN-Ändern' }); }
});

// ─── Build HTML ──────────────────────────────────────────────────────────────
let compiledHtml;

async function build() {
  const tmpl = fs.readFileSync(path.join(__dirname, 'template.html'), 'utf8');
  const twInput = '@tailwind base;\n@tailwind components;\n@tailwind utilities;';
  const twResult = await postcss([tailwind({ content:[{raw:tmpl,extension:'html'}], theme:{extend:{}}, plugins:[] })]).process(twInput, {from:undefined});
  let html = tmpl.replace(/<script type="text\/babel">([\s\S]*?)<\/script>/, (_, jsx) => {
    const result = Babel.transform(jsx, { presets:['react'], plugins:['transform-optional-chaining','transform-nullish-coalescing-operator'], sourceType:'script' });
    return `<script>\n${result.code}\n</script>`;
  });
  html = html.replace('__TAILWIND_CSS__', twResult.css);
  compiledHtml = html;
  console.log(`App built — CSS: ${(twResult.css.length/1024).toFixed(1)} KB`);
}

build().catch(err => {
  console.error('Build error:', err.message);
  compiledHtml = `<!DOCTYPE html><html><body><pre style="color:red;padding:24px">BUILD ERROR:\n${err.message}</pre></body></html>`;
});

// ─── Static files with cache headers ─────────────────────────────────────────
app.use('/fonts', express.static(path.join(__dirname, 'fonts'), { maxAge: '365d' }));
app.use('/logo.png', express.static(path.join(__dirname, 'logo.png'), { maxAge: '7d' }));

app.get('/', (req, res) => {
  if (!compiledHtml) { res.status(503).send('Wird gestartet…'); return; }
  const html = compiledHtml.replace('"__FIREBASE_CONFIG__"', firebaseConfig);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache');
  res.send(html);
});

app.use(express.static(__dirname));
app.listen(PORT, () => console.log(`K21 Café läuft auf http://localhost:${PORT}`));
