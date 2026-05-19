const express   = require('express');
const fs        = require('fs');
const path      = require('path');
const Babel     = require('@babel/standalone');
const postcss   = require('postcss');
const tailwind  = require('tailwindcss');

const app  = express();
const PORT = process.env.PORT || 3002;

// Firebase web config — intentionally hardcoded (public client config, no secret)
const firebaseConfig = JSON.stringify({
  apiKey:            "AIzaSyAB9ugtPhwbXTJc9mZia6a_x54LEYLz5PE",
  authDomain:        "r3zahlen.firebaseapp.com",
  projectId:         "r3zahlen",
  storageBucket:     "r3zahlen.firebasestorage.app",
  messagingSenderId: "1071865171603",
  appId:             "1:1071865171603:web:399ef56359d043e7544766",
});

let compiledHtml;

async function build() {
  const tmpl = fs.readFileSync(path.join(__dirname, 'template.html'), 'utf8');

  // 1. Generate only the CSS classes actually used in the template
  const twInput = '@tailwind base;\n@tailwind components;\n@tailwind utilities;';
  const twResult = await postcss([
    tailwind({
      content: [{ raw: tmpl, extension: 'html' }],
      theme: { extend: {} },
      plugins: [],
    }),
  ]).process(twInput, { from: undefined });

  // 2. Compile JSX → plain JS
  let html = tmpl.replace(
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

  // 3. Inline the generated CSS (replaces the __TAILWIND_CSS__ placeholder)
  html = html.replace('__TAILWIND_CSS__', twResult.css);

  compiledHtml = html;
  console.log(`App built — CSS: ${(twResult.css.length / 1024).toFixed(1)} KB`);
}

build().catch(err => {
  console.error('Build error:', err.message);
  const msg = (err.message || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  compiledHtml = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Build Error</title></head><body>
    <pre style="padding:24px;font-family:monospace;font-size:13px;color:#dc2626;background:#fef2f2;margin:24px;white-space:pre-wrap">BUILD ERROR:\n${msg}</pre>
  </body></html>`;
});

app.get('/', (req, res) => {
  if (!compiledHtml) { res.status(503).send('Starting…'); return; }
  const html = compiledHtml.replace('"__FIREBASE_CONFIG__"', firebaseConfig);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache');
  res.send(html);
});

app.use(express.static(__dirname));

app.listen(PORT, () => console.log(`K21 Café läuft auf http://localhost:${PORT}`));
