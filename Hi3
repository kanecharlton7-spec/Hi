// Local embed proxy. Requires Node 18+. No dependencies.
// Run:  node proxy-server.js   then open http://localhost:8080
const http = require('http');
const dns = require('dns').promises;
const net = require('net');

const PORT = process.env.PORT || 8080;
const HOST = '127.0.0.1'; // local only. Do not expose this publicly.

const UI = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Embed Browser</title>
<style>
:root{--bg:#f6f7f9;--bar:#fff;--text:#1c2430;--muted:#6a7482;--accent:#2457d6;--line:#d9dee5}
@media(prefers-color-scheme:dark){:root{--bg:#14181f;--bar:#1d232c;--text:#e8ecf1;--muted:#8c97a6;--accent:#6c93f5;--line:#2c3541}}
*{box-sizing:border-box}html,body{height:100%;margin:0;background:var(--bg);color:var(--text);font:15px/1.4 system-ui,sans-serif}
body{display:flex;flex-direction:column}header{display:flex;gap:8px;padding:10px;background:var(--bar);border-bottom:1px solid var(--line)}
button,input{font:inherit;color:inherit}button{background:transparent;border:1px solid var(--line);border-radius:8px;padding:0 12px;cursor:pointer}
#go{background:var(--accent);border-color:var(--accent);color:#fff}
input{flex:1;min-width:0;height:38px;padding:0 12px;border:1px solid var(--line);border-radius:8px;background:var(--bg)}
main{flex:1;position:relative}iframe{position:absolute;inset:0;width:100%;height:100%;border:0;background:#fff}
#msg{padding:8px 12px;font-size:13px;color:var(--muted);border-top:1px solid var(--line);background:var(--bar)}
</style></head><body>
<header><button id="reload" aria-label="Reload">↻</button>
<input id="url" placeholder="Enter a website address" autocomplete="off" spellcheck="false">
<button id="go">Open</button></header>
<main><iframe id="frame" title="Embedded site"></iframe></main>
<div id="msg">Pages load through the local proxy. Sites that depend on logins or heavy scripts may not work.</div>
<script>
const f=document.getElementById('frame'),i=document.getElementById('url'),m=document.getElementById('msg');let cur='';
function norm(v){v=v.trim();if(!v)return'';if(!/^[a-z][a-z0-9+.-]*:\\/\\//i.test(v))v='https://'+v;try{return new URL(v).href}catch{return''}}
function load(v){const h=norm(v);if(!h){m.textContent='Not a valid address. Try example.com.';return}
cur=h;i.value=h;f.src='/proxy?url='+encodeURIComponent(h);m.textContent='Loading '+h}
document.getElementById('go').onclick=()=>load(i.value);
i.addEventListener('keydown',e=>{if(e.key==='Enter')load(i.value)});
document.getElementById('reload').onclick=()=>{if(cur)load(cur)};
</script></body></html>`;

// Injected into proxied HTML so link clicks and GET forms stay inside the proxy.
const INJECT = (base) => `<base href="${base}"><script>(function(){
function p(u){try{return '/proxy?url='+encodeURIComponent(new URL(u,${JSON.stringify(base)}).href)}catch(e){return null}}
document.addEventListener('click',function(e){var a=e.target.closest&&e.target.closest('a[href]');
if(!a||a.href.startsWith('javascript:')||a.href.startsWith('mailto:')||a.getAttribute('href').startsWith('#'))return;
var t=p(a.href);if(t){e.preventDefault();location.href=t}},true);
document.addEventListener('submit',function(e){var f=e.target;if((f.method||'get').toLowerCase()!=='get')return;
e.preventDefault();var u=new URL(f.action||${JSON.stringify(base)},${JSON.stringify(base)});
new FormData(f).forEach(function(v,k){u.searchParams.set(k,v)});location.href=p(u.href)},true);
})();</script>`;

function isPrivate(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a >= 224;
  }
  const l = ip.toLowerCase();
  return l === '::1' || l === '::' || l.startsWith('fc') || l.startsWith('fd') ||
    l.startsWith('fe80') || l.startsWith('::ffff:');
}

async function assertPublic(hostname) {
  const addrs = await dns.lookup(hostname, { all: true });
  if (!addrs.length || addrs.some(a => isPrivate(a.address))) throw new Error('Blocked: private or local address');
}

const DROP = new Set(['x-frame-options', 'content-security-policy', 'content-security-policy-report-only',
  'content-encoding', 'content-length', 'transfer-encoding', 'set-cookie', 'strict-transport-security',
  'connection', 'keep-alive']);

async function handleProxy(req, res, target) {
  let url;
  try { url = new URL(target); } catch { res.writeHead(400); return res.end('Invalid URL'); }
  if (!/^https?:$/.test(url.protocol)) { res.writeHead(400); return res.end('Only http and https are supported'); }
  try { await assertPublic(url.hostname); } catch (e) { res.writeHead(403); return res.end(e.message); }

  let upstream;
  try {
    upstream = await fetch(url, {
      redirect: 'manual',
      signal: AbortSignal.timeout(20000),
      headers: {
        'user-agent': req.headers['user-agent'] || 'Mozilla/5.0',
        'accept': req.headers['accept'] || '*/*',
        'accept-language': req.headers['accept-language'] || 'en-US,en;q=0.9',
      },
    });
  } catch (e) { res.writeHead(502); return res.end('Could not reach site: ' + e.message); }

  const headers = {};
  upstream.headers.forEach((v, k) => { if (!DROP.has(k)) headers[k] = v; });

  if (upstream.status >= 300 && upstream.status < 400 && headers.location) {
    headers.location = '/proxy?url=' + encodeURIComponent(new URL(headers.location, url).href);
    res.writeHead(upstream.status, headers); return res.end();
  }

  const type = upstream.headers.get('content-type') || '';
  const body = Buffer.from(await upstream.arrayBuffer());
  if (type.includes('text/html')) {
    let html = body.toString('utf8');
    html = /<head[^>]*>/i.test(html)
      ? html.replace(/<head[^>]*>/i, m => m + INJECT(url.href))
      : INJECT(url.href) + html;
    res.writeHead(upstream.status, headers);
    return res.end(html);
  }
  res.writeHead(upstream.status, headers);
  res.end(body);
}

http.createServer((req, res) => {
  const u = new URL(req.url, `http://${req.headers.host}`);
  if (u.pathname === '/proxy') return handleProxy(req, res, u.searchParams.get('url') || '');
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(UI);
}).listen(PORT, HOST, () => console.log(`Embed browser running at http://localhost:${PORT}`));
