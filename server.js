const express   = require('express');
const fs        = require('fs');
const path      = require('path');
const Babel     = require('@babel/standalone');
const postcss   = require('postcss');
const tailwind  = require('tailwindcss');

const app  = express();
const PORT = process.env.PORT || 3002;
app.use(express.json());

// ─── Firebase config ────────────────────────────────────────────────────────
const API_KEY     = 'AIzaSyAB9ugtPhwbXTJc9mZia6a_x54LEYLz5PE';
const PROJECT_ID  = 'r3zahlen';
const firebaseConfig = JSON.stringify({
  apiKey:            API_KEY,
  authDomain:        'r3zahlen.firebaseapp.com',
  projectId:         PROJECT_ID,
  storageBucket:     'r3zahlen.firebasestorage.app',
  messagingSenderId: '1071865171603',
  appId:             '1:1071865171603:web:399ef56359d043e7544766',
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

// ─── API routes ──────────────────────────────────────────────────────────────
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

// GET /api/users?c=cafe-users   → list all users in a collection
app.get('/api/users', async (req, res) => {
  const col = req.query.c || 'cafe-users';
  const users = await fsGetCollection(col);
  if (users === null) return res.status(503).json({ error: 'Firestore nicht erreichbar' });
  res.json(users);
});

// POST /api/users?c=cafe-users   → create user  { body: user data }
app.post('/api/users', async (req, res) => {
  const col = req.query.c || 'cafe-users';
  const id = await fsSet(col, null, { ...req.body, createdAt: new Date().toISOString() });
  res.json({ id });
});

// PUT /api/users/:id?c=cafe-users  → update user
app.put('/api/users/:id', async (req, res) => {
  const col = req.query.c || 'cafe-users';
  await fsSet(col, req.params.id, req.body);
  res.json({ ok: true });
});

// DELETE /api/users/:id?c=cafe-users
app.delete('/api/users/:id', async (req, res) => {
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
