require('dotenv').config();
const express = require('express');
const fs      = require('fs');
const path    = require('path');
const Babel   = require('@babel/standalone');

const app  = express();
const PORT = process.env.PORT || 3002;

const firebaseConfig = JSON.stringify({
  apiKey:            process.env.FIREBASE_API_KEY,
  authDomain:        process.env.FIREBASE_AUTH_DOMAIN,
  projectId:         process.env.FIREBASE_PROJECT_ID,
  storageBucket:     process.env.FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
  appId:             process.env.FIREBASE_APP_ID,
});

let compiledHtml;
try {
  const tmpl = fs.readFileSync(path.join(__dirname, 'template.html'), 'utf8');
  const compiled = tmpl.replace(
    /<script type="text\/babel">([\s\S]*?)<\/script>/,
    (_, jsx) => {
      const result = Babel.transform(jsx, {
        presets: ['react'],
        plugins: ['transform-optional-chaining', 'transform-nullish-coalescing-operator'],
        sourceType: 'script',
      });
      return `<script>\n${result.code}\n</script>`;
    }
  );
  compiledHtml = compiled;
  console.log('JSX compiled successfully at startup');
} catch (err) {
  console.error('Babel compilation error:', err.message);
  const errMsg = (err.message || 'Unknown error').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  compiledHtml = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Compile Error</title></head><body>
    <pre style="padding:24px;font-family:monospace;font-size:13px;color:#dc2626;background:#fef2f2;margin:24px;white-space:pre-wrap">BABEL COMPILE ERROR:\n${errMsg}</pre>
  </body></html>`;
}

app.get('/', (req, res) => {
  const html = compiledHtml.replace('"__FIREBASE_CONFIG__"', firebaseConfig);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

app.use(express.static(__dirname));

app.listen(PORT, () => {
  console.log(`K21 Café läuft auf http://localhost:${PORT}`);
});
