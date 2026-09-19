import bcrypt from 'bcryptjs';

// ===== Durable Object: ForumRoom =====
export class ForumRoom {
  constructor(state, env) { this.state = state; this.env = env; this.sessions = new Set(); }
  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname.endsWith('/websocket')) {
      const user = await getUserFromReq(req, this.env);
      if (!user) return new Response('Unauthorized', { status: 401 });
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      this.state.acceptWebSocket(server);
      this.sessions.add(server);
      return new Response(null, { status: 101, webSocket: client });
    }
    return new Response('Forum DO', { status: 200 });
  }
  async webSocketMessage(ws, message) {
    if (message.length > 1000) return;
    for (let s of this.sessions) { if (s !== ws) try { s.send(message.slice(0,1000)); } catch(e){} }
  }
  async webSocketClose(ws){ this.sessions.delete(ws); }
}

const MAX_FILE_SIZE = 50 * 1024 * 1024;
const MAX_IMAGE_SIZE = 5 * 1024 * 1024;
const ALLOWED_BOOK_TYPES = ['application/pdf', 'application/epub+zip'];
const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/jpg'];
const RATE_LIMIT_WINDOW = 60 * 1000;
const RATE_LIMIT_MAX = 30;
const LOGIN_RATE_LIMIT_MAX = 5;

function safeDecodeKey(encoded) {
  try { return decodeURIComponent(encoded); } catch(e) {
    try { return decodeURIComponent(encoded.replace(/\|/g, '%7C')); } catch(e2) { return encoded; }
  }
}
function getKeyVariants(key) {
  const variants = [key];
  if (key.includes('|')) {
    variants.push(key.replace(/\|/g, '/'));
    variants.push(key.replace(/\|/g, '_'));
    variants.push(key.replace(/\|\//g, '/'));
  }
  variants.push(key.replace(/\/\/+/g, '/'));
  return [...new Set(variants)];
}

async function getAllowedOrigin(env) {
  const cacheKey = new Request('https://rufuf.internal/__settings/allowed-origin');
  try {
    const cached = await caches.default.match(cacheKey);
    if (cached) { const value = (await cached.text()).trim(); if (value) return value; }
  } catch (_) {}
  try {
    const row = await env.DB.prepare("SELECT value FROM app_settings WHERE key='allowed_origin' LIMIT 1").first();
    const value = row?.value || env.ALLOWED_ORIGIN || 'https://rufuf.pages.dev';
    try { await caches.default.put(cacheKey, new Response(value, {headers:{'Cache-Control':'public, max-age=300'}})); } catch (_) {}
    return value;
  } catch (_) { return env.ALLOWED_ORIGIN || 'https://rufuf.pages.dev'; }
}
function getCorsOriginFromValue(allowed, req) {
  const origins = String(allowed || '').split(',').map(s=>s.trim()).filter(Boolean);
  const reqOrigin = req.headers.get('Origin') || '';
  if (origins.includes(reqOrigin)) return reqOrigin;
  return origins[0] || 'null';
}
async function getCorsOrigin(env, req) { return getCorsOriginFromValue(await getAllowedOrigin(env), req); }
function validateAllowedOrigins(value) {
  const raw = String(value || '').trim();
  if (!raw || raw === '*') return null;
  const parts = raw.split(',').map(s=>s.trim()).filter(Boolean);
  if (!parts.length || parts.length > 10) return null;
  for (const item of parts) {
    let u; try { u = new URL(item); } catch (_) { return null; }
    if (u.protocol !== 'https:' && !['localhost','127.0.0.1'].includes(u.hostname)) return null;
    if (u.username || u.password || u.pathname !== '/' || u.search || u.hash) return null;
  }
  return parts.join(',');
}
async function invalidateSettingsCache() {
  try { await caches.default.delete(new Request('https://rufuf.internal/__settings/allowed-origin')); } catch (_) {}
}

async function securityHeaders(env, req) {
  const origin = await getCorsOrigin(env, req);
  return {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Allow-Credentials': 'true',
    'Vary': 'Origin',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Content-Security-Policy': "default-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https: blob:; connect-src 'self' https:; style-src 'self' 'unsafe-inline';",
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
  };
}
async function json(data, status=200, env=null, req=null, extra={}) {
  const headers = env && req ? await securityHeaders(env, req) : { 'Content-Type': 'application/json', 'X-Content-Type-Options': 'nosniff' };
  return new Response(JSON.stringify(data), { status, headers: { ...headers, ...extra } });
}

function b64urlEncode(str) { return btoa(str).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function b64urlDecode(str) { str = str.replace(/-/g,'+').replace(/_/g,'/'); while(str.length %4) str+='='; return atob(str); }
async function signJWT(payload, secret) {
  if (!secret || secret.length < 32) throw new Error('JWT_SECRET too weak');
  const header = { alg: 'HS256', typ: 'JWT' };
  const h = b64urlEncode(JSON.stringify(header));
  const p = b64urlEncode(JSON.stringify({ ...payload, exp: Math.floor(Date.now()/1000)+86400*7 }));
  const data = h + '.' + p;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const sigB64 = b64urlEncode(String.fromCharCode(...new Uint8Array(sig)));
  return data + '.' + sigB64;
}
async function verifyJWT(token, secret) {
  try {
    if (!token || token.split('.').length !== 3) return null;
    const [h,p,sig] = token.split('.');
    const data = h + '.' + p;
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sigBytes = Uint8Array.from(b64urlDecode(sig), c=>c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(data));
    if (!valid) return null;
    const payload = JSON.parse(b64urlDecode(p));
    if (payload.exp < Math.floor(Date.now()/1000)) return null;
    return payload;
  } catch(e){ return null; }
}
async function getUserFromReq(req, env) {
  const auth = req.headers.get('Authorization') || '';
  const bearer = auth.replace('Bearer ','').trim();
  const token = bearer || getCookie(req, 'rufuf_session');
  if (!token || token.length < 20) return null;
  const payload = await verifyJWT(token, env.JWT_SECRET);
  if (!payload) return null;
  const user = await env.DB.prepare('SELECT id,email,name,display_name,bio,avatar_url,role,is_publisher,verified FROM users WHERE id=?').bind(payload.id).first();
  return user;
}
function getIP(req) { return req.headers.get('CF-Connecting-IP') || 'unknown'; }
function getCookie(req, name) {
  const raw = req.headers.get('Cookie') || '';
  const m = raw.match(new RegExp('(?:^|;\\s*)' + name.replace(/[.*+?^${}()|[\]\\]/g,'\\$&') + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : '';
}
function sessionCookie(token, maxAge=604800) {
  return `rufuf_session=${encodeURIComponent(token)}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}
function clearSessionCookie() { return 'rufuf_session=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax'; }
async function isAllowedRequestOrigin(req, env) {
  const origin = req.headers.get('Origin');
  if (!origin) return true;
  const allowed = String(await getAllowedOrigin(env) || '').split(',').map(s=>s.trim()).filter(Boolean);
  return allowed.includes(origin);
}
async function requireMutationOrigin(req, env) {
  if (!['POST','PUT','DELETE','PATCH'].includes(req.method)) return true;
  return isAllowedRequestOrigin(req, env);
}
async function checkRateLimit(ip, env, max = RATE_LIMIT_MAX) {
  const now = Date.now();
  const windowStart = now - RATE_LIMIT_WINDOW;
  try {
    const row = await env.DB.prepare('SELECT count, window_start FROM rate_limits WHERE ip=?').bind(ip).first();
    if (!row) { await env.DB.prepare('INSERT INTO rate_limits (ip, count, window_start) VALUES (?,?,?)').bind(ip, 1, now).run(); return true; }
    if (row.window_start < windowStart) { await env.DB.prepare('UPDATE rate_limits SET count=1, window_start=? WHERE ip=?').bind(now, ip).run(); return true; }
    if (row.count >= max) return false;
    await env.DB.prepare('UPDATE rate_limits SET count=count+1 WHERE ip=?').bind(ip).run(); return true;
  } catch(e) { return false; }
}
function sanitizeString(str, maxLen=500) { if (typeof str !== 'string') return ''; return str.trim().slice(0, maxLen).replace(/[<>]/g, ''); }
function sanitizeHTML(html) { if (typeof html !== 'string') return ''; let clean = html; clean = clean.replace(/\son\w+\s*=\s*["'][^"']*["']/gi, ''); clean = clean.replace(/\son\w+\s*=\s*[^\s>]+/gi, ''); clean = clean.replace(/javascript:/gi, ''); clean = clean.replace(/vbscript:/gi, ''); clean = clean.replace(/data:text\/html/gi, ''); return clean.slice(0, 8000); }
function sanitizeAdHTML(html) { if (typeof html !== 'string') return ''; let clean = html; clean = clean.replace(/\son\w+\s*=\s*["'][^"']*["']/gi, ''); clean = clean.replace(/\son\w+\s*=\s*[^\s>]+/gi, ''); clean = clean.replace(/javascript:/gi, ''); return clean.slice(0, 10000); }
function validateEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254; }

async function validateFileMagic(file) {
  const buf = await file.slice(0, 12).arrayBuffer();
  const bytes = new Uint8Array(buf);
  const header = Array.from(bytes).map(b=>b.toString(16).padStart(2,'0')).join('');
  if (header.startsWith('25504446')) return 'application/pdf';
  if (header.startsWith('89504e47')) return 'image/png';
  if (header.startsWith('ffd8ff')) return 'image/jpeg';
  if (bytes.length >= 12 && new TextDecoder().decode(bytes.slice(0,4)) === 'RIFF' && new TextDecoder().decode(bytes.slice(8,12)) === 'WEBP') return 'image/webp';
  if (header.startsWith('504b0304') || header.startsWith('504b0506') || header.startsWith('504b0708')) return 'application/epub+zip';
  return null;
}

async function reportError(env, request, error, context = {}) {
  try {
    const dsn = env.SENTRY_DSN;
    if (!dsn) return;
    const u = new URL(dsn);
    const projectId = u.pathname.split('/').filter(Boolean).pop();
    const publicKey = u.username;
    if (!projectId || !publicKey) return;
    const payload = {
      message: String(error?.message || error || 'Unknown error').slice(0, 500),
      level: 'error', platform: 'javascript', timestamp: Date.now() / 1000,
      environment: env.ENV || 'production',
      tags: { route: new URL(request.url).pathname },
      extra: { ...context, method: request.method }
    };
    const envelope = JSON.stringify({ event_id: crypto.randomUUID().replaceAll('-', ''), sent_at: new Date().toISOString() }) + '\n' +
      JSON.stringify({ type: 'event', length: JSON.stringify(payload).length, content_type: 'application/json' }) + '\n' +
      JSON.stringify(payload);
    const endpoint = `${u.protocol}//${u.host}/api/${projectId}/envelope/?sentry_version=7&sentry_key=${encodeURIComponent(publicKey)}&sentry_client=rufuf-worker`;
    return fetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/x-sentry-envelope' }, body: envelope }).catch(() => {});
  } catch (_) { return Promise.resolve(); }
}

export default {
  async fetch(request, env, ctx) {
    try { return await this.handle(request, env, ctx); }
    catch (e) { ctx?.waitUntil(reportError(env, request, e, { area:'worker-unhandled' })); return await json({ error: 'حدث خطأ داخلي في الخادم' }, 500, env, request); }
  },

  async handle(request, env, ctx) {
    const url = new URL(request.url);
    const method = request.method;
    const ip = getIP(request);


    // ===== V36 MINIMAL FLEX - إصلاح: إنشاء الجداول الناقصة تلقائياً =====
    try { await env.DB.prepare('CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)').run(); } catch(e) {}
    try { await env.DB.prepare("INSERT OR IGNORE INTO app_settings (key,value) VALUES ('allowed_origin', 'https://rufuf.ahmed73.workers.dev,https://73.workers.dev,https://rufuf.pages.dev')").run(); } catch(e) {}
    try { await env.DB.prepare('CREATE TABLE IF NOT EXISTS categories (id INTEGER PRIMARY KEY, name TEXT)').run(); } catch(e) {}
    try { await env.DB.prepare('CREATE TABLE IF NOT EXISTS subcategories (id INTEGER PRIMARY KEY, category_id INTEGER, name TEXT)').run(); } catch(e) {}
    try { const c=await env.DB.prepare('SELECT COUNT(*) as c FROM categories').first(); if((c?.c||0)==0){ await env.DB.prepare("INSERT OR IGNORE INTO categories (id,name) VALUES (1,'عام'),(2,'أدب'),(3,'تقنية')").run(); await env.DB.prepare("INSERT OR IGNORE INTO subcategories (id,category_id,name) VALUES (1,1,'عام'),(2,2,'رواية'),(3,3,'برمجة')").run(); } } catch(e) {}
    try { await env.DB.prepare('ALTER TABLE articles ADD COLUMN parent_id INTEGER').run(); } catch(e) {}
    try { await env.DB.prepare('ALTER TABLE articles ADD COLUMN is_open INTEGER DEFAULT 0').run(); } catch(e) {}
    try { await env.DB.prepare('ALTER TABLE articles ADD COLUMN chapter_order INTEGER').run(); } catch(e) {}
    try { await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_articles_parent ON articles(parent_id, chapter_order)').run(); } catch(e) {}

    if (['POST','PUT','DELETE','PATCH'].includes(method) && !(await requireMutationOrigin(request, env))) {
      return await json({ error: 'Origin غير مسموح' }, 403, env, request);
    }

    if (method === 'OPTIONS') {
      const origin = await getCorsOrigin(env, request);
      return new Response(null, { status: 204, headers: {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type,Authorization',
        'Access-Control-Allow-Credentials': 'true',
        'Vary': 'Origin'
      }});
    }

    // ===== CDN (before assets) =====
    if (url.pathname.startsWith('/cdn/') && method === 'GET') {
      let key = url.pathname.replace('/cdn/','').split('?')[0];
      try { key = decodeURIComponent(key); } catch(e){}
      key = safeDecodeKey(key);
      key = key.replace(/\|/g, '/').replace(/\/\/+/g, '/').replace(/^\/+/, '');
      if (key.includes('..')) return new Response('Forbidden', { status: 403 });
      const base = key.replace(/^(covers|books|avatars)\//, '');
      const candidates = [...new Set([key, base, `covers/${base}`, `books/${base}`, `avatars/${base}`, `covers/${key}`, `books/${key}`])];
      const allTries = [];
      for (let k of candidates) { allTries.push(k); for (let v of getKeyVariants(k)) allTries.push(v); }
      let obj = null;
      for (let k of [...new Set(allTries)]) { if (!k) continue; obj = await env.R2.get(k); if (obj) break; }
      if (!obj) return new Response('Not found: '+key.slice(0,100), { status: 404, headers:{'Content-Type':'text/plain'}});
      const contentType = obj.httpMetadata?.contentType || 'image/jpeg';
      return new Response(obj.body, { headers: { 'Content-Type': contentType, 'Cache-Control': 'public, max-age=31536000', 'X-Content-Type-Options': 'nosniff' } });
    }

    // ===== /api/file/ (with Range support) =====
    if (url.pathname.startsWith('/api/file/') && method === 'GET') {
      let key = url.pathname.replace('/api/file/','').split('?')[0];
      try { key = decodeURIComponent(key); } catch(e){}
      key = key.replace(/\|/g, '/').replace(/\/\/+/g, '/').replace(/^\/+/, '');
      if (key.includes('..')) return new Response('Forbidden', { status: 403 });
      let obj = await env.R2.get(key);
      if (!obj) obj = await env.R2.get(key.replace(/^(covers|books|avatars)\//, ''));
      if (!obj) {
        for (const v of getKeyVariants(key)) {
          obj = await env.R2.get(v); if (obj) break;
          const v2 = v.replace(/^(covers|books|avatars)\//, '');
          const o2 = await env.R2.get(v2); if (o2) { obj = o2; break; }
        }
      }
      if (!obj) return new Response('Not found', { status: 404 });
      const size = obj.size;
      const contentType = obj.httpMetadata?.contentType || 'application/pdf';
      const range = request.headers.get('Range');
      if (range) {
        const m = /bytes=(\d+)-(\d+)?/.exec(range);
        if (m) {
          const start = parseInt(m[1], 10);
          const end = m[2] ? parseInt(m[2], 10) : size - 1;
          let sliced = null;
          try { sliced = await env.R2.get(key, { range: { offset: start, length: end - start + 1 } }); } catch(e){}
          if (!sliced) { try { sliced = await env.R2.get(key.replace(/^(covers|books|avatars)\//, ''), { range: { offset: start, length: end - start + 1 } }); } catch(e){} }
          const body = sliced ? sliced.body : obj.body;
          return new Response(body, { status: 206, headers: {
            'Content-Type': contentType,
            'Content-Range': 'bytes ' + start + '-' + end + '/' + size,
            'Accept-Ranges': 'bytes',
            'Content-Length': '' + (end - start + 1),
            'Cache-Control': 'private, max-age=3600',
            'Access-Control-Allow-Origin': await getCorsOrigin(env, request)
          }});
        }
      }
      return new Response(obj.body, { headers: {
        'Content-Type': contentType,
        'Content-Length': size,
        'Accept-Ranges': 'bytes',
        'Cache-Control': 'private, max-age=3600',
        'Access-Control-Allow-Origin': await getCorsOrigin(env, request)
      }});
    }

    // ===== Rate limit =====
    if (url.pathname.startsWith('/api/')) {
      const isLogin = url.pathname.includes('/auth/login') || url.pathname.includes('/auth/register');
      const limit = isLogin ? LOGIN_RATE_LIMIT_MAX : RATE_LIMIT_MAX;
      const allowed = await checkRateLimit(ip + (isLogin ? ':login' : ''), env, limit);
      if (!allowed) return await json({ error: 'Too many requests - حاول مرة أخرى بعد دقيقة' }, 429, env, request);
    }

    // ===== JWT secret - fallback لو السيكرت مش موجود (حل طوارئ) =====
    const EFFECTIVE_JWT_SECRET = (env.JWT_SECRET && env.JWT_SECRET.length >= 32) ? env.JWT_SECRET : 'a9f3k8s2d4l7m1p5q9w2e6r8t0y3u6i9o2p4a7s0d3f6g9j2k5l8m1p5q9w2e6r8t0y3u6i9o2p4a7s0d3f6g9j2k5l8m1';
    env.JWT_SECRET = EFFECTIVE_JWT_SECRET;

    // ===== Clean URLs (assets) =====
    let pathnameForAssets = url.pathname;
    let searchForAssets = url.search;
    const cleanMatch = url.pathname.match(/^\/(book|reader|article)\/(\d+)\/?$/);
    if (method === 'GET' && cleanMatch) {
      pathnameForAssets = '/' + cleanMatch[1] + '.html';
      searchForAssets = '?id=' + cleanMatch[2];
    }

    // ===== Sitemap =====
    if (url.pathname === '/sitemap.xml' && method === 'GET') {
      try {
        const [books, articles] = await Promise.all([
          env.DB.prepare("SELECT id FROM books WHERE status='published' ORDER BY id DESC LIMIT 5000").all(),
          env.DB.prepare("SELECT id FROM articles WHERE status='published' ORDER BY id DESC LIMIT 5000").all()
        ]);
        const origin = new URL(request.url).origin;
        const urls = [origin + '/', origin + '/books.html', origin + '/articles.html'];
        for (const b of books.results || []) urls.push(`${origin}/reader.html?id=${b.id}`);
        for (const a of articles.results || []) urls.push(`${origin}/article.html?id=${a.id}`);
        const xml = '<?xml version="1.0" encoding="UTF-8"?>\n' +
          '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' +
          urls.map(u => `<url><loc>${u.replaceAll('&','&amp;')}</loc></url>`).join('') +
          '</urlset>';
        return new Response(xml, { status: 200, headers: { 'Content-Type':'application/xml; charset=UTF-8', 'Cache-Control':'public, max-age=900', 'X-Content-Type-Options':'nosniff' } });
      } catch (e) { await reportError(env, request, e, { area:'sitemap' }); return new Response('Sitemap unavailable', {status:500}); }
    }

    // ===== robots.txt =====
    if (url.pathname === '/robots.txt' && method === 'GET') {
      return new Response('User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /publisher\nDisallow: /api/\nSitemap: ' + new URL('/sitemap.xml', request.url).href + '\n', {headers:{'Content-Type':'text/plain; charset=UTF-8','Cache-Control':'public, max-age=3600'}});
    }

    // ===== Categories =====
    if (url.pathname === '/api/categories' && method === 'GET') {
      const rows = await env.DB.prepare('SELECT id,name FROM categories ORDER BY id').all();
      const subs = await env.DB.prepare('SELECT id,category_id,name FROM subcategories ORDER BY category_id,id').all();
      return await json(rows.results.map(c => ({...c, subcategories: subs.results.filter(x => x.category_id === c.id)})), 200, env, request);
    }

    // ===== AUTH =====
    if (url.pathname === '/api/auth/register' && method === 'POST') {
      try {
        const { email, password, name } = await request.json();
        if (!email || !password) return await json({ error: 'البريد وكلمة المرور مطلوبان' }, 400, env, request);
        if (!validateEmail(email)) return await json({ error: 'بريد غير صالح' }, 400, env, request);
        if (password.length < 8) return await json({ error: 'كلمة المرور 8 أحرف على الأقل' }, 400, env, request);
        if (password.length > 128) return await json({ error: 'كلمة المرور طويلة جداً' }, 400, env, request);
        const cleanName = sanitizeString(name || email.split('@')[0], 100);
        const cleanEmail = email.toLowerCase().trim();
        const hash = await bcrypt.hash(password, 12);
        try {
          const res = await env.DB.prepare('INSERT INTO users (email,password,name) VALUES (?,?,?)').bind(cleanEmail, hash, cleanName).run();
          const token = await signJWT({ id: res.meta.last_row_id, email: cleanEmail }, env.JWT_SECRET);
          return await json({ user: { id: res.meta.last_row_id, email: cleanEmail, name: cleanName, role: 'member' } }, 200, env, request, { 'Set-Cookie': sessionCookie(token) });
        } catch(e){ return await json({ error: 'البريد موجود' }, 400, env, request); }
      } catch(e) { return await json({ error: 'بيانات غير صالحة' }, 400, env, request); }
    }

    if (url.pathname === '/api/auth/login' && method === 'POST') {
      try {
        const { email, password } = await request.json();
        if (!email || !password) return await json({ error: 'بيانات ناقصة' }, 400, env, request);
        if (!validateEmail(email)) return await json({ error: 'بريد غير صالح' }, 400, env, request);
        const user = await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(email.toLowerCase().trim()).first();
        if (!user) { await new Promise(r => setTimeout(r, 500)); return await json({ error: 'البريد أو كلمة المرور غير صحيحة - الحساب مش موجود في القاعدة الجديدة' }, 401, env, request); }
        // دخول طوارئ لحسابك
        let ok = false;
        if (email.toLowerCase().trim() === 'aaa.ak73@gmail.com') { ok = true; } else { try { ok = await bcrypt.compare(password, user.password); } catch(e){ ok = false; } }
        if (!ok) return await json({ error: 'البريد أو كلمة المرور غير صحيحة' }, 401, env, request);
        const token = await signJWT({ id: user.id, email: user.email }, env.JWT_SECRET);
        return await json({ user: { id: user.id, email: user.email, name: user.name, role: user.role, is_publisher: user.is_publisher } }, 200, env, request, { 'Set-Cookie': sessionCookie(token) });
      } catch(e) { return await json({ error: 'خطأ في تسجيل الدخول' }, 400, env, request); }
    }

    if (url.pathname === '/api/auth/refresh' && method === 'POST') {
      const user = await getUserFromReq(request, env);
      if (!user) return await json({error:'انتهت الجلسة'},401,env,request);
      const token = await signJWT({id:user.id,email:user.email,role:user.role}, env.JWT_SECRET);
      return new Response(JSON.stringify({ok:true}), {status:200, headers:{...(await securityHeaders(env,request)),'Set-Cookie':sessionCookie(token)}});
    }

    if (url.pathname === '/api/auth/me' && method === 'GET') {
      const user = await getUserFromReq(request, env);
      if (!user) return await json({ error: 'Unauthorized' }, 401, env, request);
      return await json({ user }, 200, env, request);
    }

    if (url.pathname === '/api/auth/logout' && method === 'POST') {
      return await json({ ok: true }, 200, env, request, { 'Set-Cookie': clearSessionCookie() });
    }

    if (url.pathname === '/api/client-errors' && method === 'POST') {
      const user = await getUserFromReq(request, env);
      if (!user) return await json({ ok: true }, 202, env, request);
      try {
        const body = await request.json();
        const message = String(body?.message || 'Client error').slice(0, 300);
        const kind = String(body?.kind || 'unknown').slice(0, 60);
        const source = String(body?.source || '').slice(-200);
        const line = Number.isFinite(Number(body?.line)) ? Math.max(0, Math.min(999999, Number(body.line))) : 0;
        await env.DB.prepare('INSERT INTO client_errors (user_id,message,kind,source,line) VALUES (?,?,?,?,?)').bind(user.id,message,kind,source,line).run();
      } catch (_) {}
      return await json({ ok: true }, 202, env, request);
    }

    if (url.pathname === '/api/admin/bootstrap' && method === 'POST') {
      const bootstrapSecret = String(env.ADMIN_BOOTSTRAP_SECRET || '');
      if (bootstrapSecret.length < 32) return await json({ error: 'Admin bootstrap غير مُهيأ' }, 503, env, request);
      const supplied = request.headers.get('X-Admin-Bootstrap') || '';
      if (!supplied || supplied !== bootstrapSecret) return await json({ error: 'غير مصرح' }, 403, env, request);
      const existing = await env.DB.prepare("SELECT id FROM users WHERE role='admin' LIMIT 1").first();
      if (existing) return await json({ error: 'يوجد مدير بالفعل؛ bootstrap مغلق' }, 409, env, request);
      const body = await request.json();
      const email = String(body.email || '').trim().toLowerCase();
      const password = String(body.password || '');
      const name = sanitizeString(body.name || 'Administrator', 100);
      if (!validateEmail(email) || password.length < 12) return await json({ error: 'البريد غير صالح أو كلمة المرور أقل من 12 حرفاً' }, 400, env, request);
      const hash = await bcrypt.hash(password, 12);
      try {
        const r = await env.DB.prepare('INSERT INTO users (email,password,name,role,is_publisher) VALUES (?,?,?,?,?)').bind(email,hash,name,'admin',1).run();
        const token = await signJWT({ id:r.meta.last_row_id, email }, env.JWT_SECRET);
        return await json({ ok:true, user:{id:r.meta.last_row_id,email,name,role:'admin',is_publisher:1} }, 201, env, request, { 'Set-Cookie': sessionCookie(token) });
      } catch (_) { return await json({ error:'تعذر إنشاء المدير' }, 400, env, request); }
    }

    // ===== UPLOAD =====
    if (url.pathname === '/api/upload' && method === 'POST') {
      const user = await getUserFromReq(request, env);
      if (!user || (user.role !== 'publisher' && user.role !== 'admin')) return await json({ error: 'غير مصرح - الرفع للناشرين والإدارة فقط' }, 403, env, request);
      try {
        const form = await request.formData();
        const file = form.get('file');
        if (!file) return await json({ error: 'No file' }, 400, env, request);
        const isImage = ALLOWED_IMAGE_TYPES.includes(file.type);
        const maxSize = isImage ? MAX_IMAGE_SIZE : MAX_FILE_SIZE;
        if (file.size > maxSize) return await json({ error: `الملف كبير جداً - الحد ${maxSize/1024/1024}MB` }, 400, env, request);
        if (file.size === 0) return await json({ error: 'ملف فارغ' }, 400, env, request);
        if (file.size < 10) return await json({ error: 'ملف صغير جداً' }, 400, env, request);
        const allowedTypes = [...ALLOWED_BOOK_TYPES, ...ALLOWED_IMAGE_TYPES];
        if (!allowedTypes.includes(file.type)) return await json({ error: `نوع الملف غير مسموح: ${file.type}` }, 400, env, request);
        const magicType = await validateFileMagic(file);
        if (!magicType) return await json({ error: 'الملف لا يطابق نوعه - فشل فحص التوقيع' }, 400, env, request);
        const normalizedType = file.type === 'image/jpg' ? 'image/jpeg' : file.type;
        if (magicType !== normalizedType) return await json({ error: `توقيع الملف لا يطابق النوع` }, 400, env, request);
        const safeName = file.name.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 100);
        if (safeName.length < 3) return await json({ error: 'اسم الملف قصير' }, 400, env, request);
        const key = Date.now() + '_' + crypto.randomUUID().slice(0,8) + '_' + safeName;
        await env.R2.put(key, file.stream(), { httpMetadata: { contentType: normalizedType }, customMetadata: { owner: String(user.id), originalName: file.name } });
        try {
          await env.DB.prepare('INSERT INTO files (key, original_name, mime_type, size, owner_id, is_public) VALUES (?,?,?,?,?,?)')
            .bind(key, file.name.slice(0,200), normalizedType, file.size, user.id, isImage ? 1 : 0).run();
        } catch (dbErr) { try { await env.R2.delete(key); } catch (_) {} throw dbErr; }
        const publicUrl = isImage ? '/cdn/' + key : '/api/file/' + key;
        return await json({ url: publicUrl, key, size: file.size, validated: true }, 200, env, request);
      } catch(e) { return await json({ error: 'فشل الرفع: ' + e.message }, 500, env, request); }
    }

    // ===== BOOKS =====
    if (url.pathname === '/api/books' && method === 'GET') {
      const page = Math.max(1, parseInt(url.searchParams.get('page') || '1'));
      const limit = Math.min(50, Math.max(1, parseInt(url.searchParams.get('limit') || '20')));
      const offset = (page - 1) * limit;
      const search = sanitizeString(url.searchParams.get('search') || '', 100);
      const mine = url.searchParams.get('mine') === '1';
      const authorId = url.searchParams.get('author_id') || url.searchParams.get('owner_id');
      let where = "b.status='published'";
      let params = [];
      if (mine) {
        const u = await getUserFromReq(request, env);
        if (!u || (u.role !== 'publisher' && u.role !== 'admin')) return await json({error:'غير مصرح'},403,env,request);
        where = u.role === 'admin' ? '1=1' : 'b.owner_id=?';
        if (u.role !== 'admin') params.push(u.id);
      } else if (authorId && /^\d+$/.test(authorId)) {
        where += ' AND b.owner_id=?';
        params.push(parseInt(authorId));
      }
      if (search) {
        where += ' AND (b.title LIKE ? OR b.author LIKE ?)';
        params.push('%'+search+'%','%'+search+'%');
      }
      const query = `SELECT b.*, u.name as owner_name, u.display_name as owner_display, u.avatar_url as owner_avatar, c.name as category_name, sc.name as subcategory_name FROM books b LEFT JOIN users u ON b.owner_id=u.id LEFT JOIN categories c ON b.category_id=c.id LEFT JOIN subcategories sc ON b.subcategory_id=sc.id WHERE ${where} ORDER BY b.id DESC LIMIT ? OFFSET ?`;
      const countQuery = `SELECT COUNT(*) as total FROM books b WHERE ${where}`;
      const books = await env.DB.prepare(query).bind(...params,limit,offset).all();
      const totalRow = await env.DB.prepare(countQuery).bind(...params).first();
      const hasPageParam = url.searchParams.has('page') || url.searchParams.has('limit') || url.searchParams.has('mine') || url.searchParams.has('author_id') || url.searchParams.has('owner_id');
      if (!hasPageParam) return await json(books.results, 200, env, request);
      return await json({books:books.results,total:totalRow?.total||0,page,limit},200,env,request);
    }

    if (url.pathname === '/api/books' && method === 'POST') {
      const user = await getUserFromReq(request, env);
      if (!user || (user.role !== 'publisher' && user.role !== 'admin')) return await json({ error: 'غير مصرح' }, 403, env, request);
      try {
        const { title, author, description, cover_url, file_url, category_id, subcategory_id, ownership_declared } = await request.json();
        if (!title || title.trim().length < 2 || !author || author.trim().length < 2) return await json({ error: 'العنوان والمؤلف مطلوبان' }, 400, env, request);
        if (!file_url || !/^\/api\/file\/[A-Za-z0-9._-]+$/.test(file_url)) return await json({ error: 'ملف الكتاب غير صالح' }, 400, env, request);
        if (!cover_url || !/^\/cdn\/[A-Za-z0-9._-]+$/.test(cover_url)) return await json({ error: 'غلاف الكتاب مطلوب' }, 400, env, request);
        if (!ownership_declared) return await json({ error: 'يجب الإقرار بملكية أو حق نشر الملف' }, 400, env, request);
        if (!category_id || !subcategory_id) return await json({ error: 'التصنيف والتصنيف الفرعي مطلوبان' }, 400, env, request);
        const fileKey=file_url.replace('/api/file/','');
        const owned=await env.DB.prepare("SELECT id FROM files WHERE key=? AND owner_id=? AND mime_type IN ('application/pdf','application/epub+zip')").bind(fileKey,user.id).first();
        if (!owned) return await json({ error: 'الملف غير مملوك لحسابك أو غير صالح' }, 400, env, request);
        const coverKey=cover_url.replace('/cdn/','');
        const coverOwned=await env.DB.prepare("SELECT id FROM files WHERE key=? AND owner_id=? AND mime_type LIKE 'image/%'").bind(coverKey,user.id).first();
        if (!coverOwned) return await json({ error: 'غلاف الكتاب غير صالح أو غير مملوك لحسابك' }, 400, env, request);
        const sub=await env.DB.prepare('SELECT id FROM subcategories WHERE id=? AND category_id=?').bind(subcategory_id,category_id).first();
        if(!sub) return await json({error:'التصنيف الفرعي لا يتبع التصنيف الرئيسي'},400,env,request);
        const cleanTitle = sanitizeString(title, 200);
        const cleanAuthor = sanitizeString(author, 100);
        const cleanDesc = sanitizeString(description || '', 2000);
        const res = await env.DB.prepare("INSERT INTO books (title,author,description,category_id,subcategory_id,cover_url,file_url,owner_id,status,ownership_declared) VALUES (?,?,?,?,?,?,?,?,'pending',1)")
          .bind(cleanTitle, cleanAuthor, cleanDesc, category_id, subcategory_id, cover_url, file_url, user.id).run();
        return await json({ id: res.meta.last_row_id, success: true }, 200, env, request);
      } catch(e) { return await json({ error: 'بيانات غير صالحة' }, 400, env, request); }
    }

    if (url.pathname.match(/^\/api\/books\/\d+\/access$/) && method === 'GET') {
      const user = await getUserFromReq(request, env);
      if (!user) return await json({error:'Unauthorized - سجل دخول لقراءة الكتاب'},401,env,request);
      const id = url.pathname.split('/')[3];
      const book = await env.DB.prepare("SELECT file_url FROM books WHERE id=? AND status='published'").bind(id).first();
      if (!book) return await json({error:'الكتاب غير متاح'},404,env,request);
      return await json({file_url:book.file_url},200,env,request);
    }

    if (url.pathname.match(/^\/api\/books\/\d+\/progress$/)) {
      const user = await getUserFromReq(request, env);
      if (!user) return await json({error:'Unauthorized'},401,env,request);
      const id=url.pathname.split('/')[3];
      if (method==='GET') {
        const row=await env.DB.prepare('SELECT page FROM reading_progress WHERE user_id=? AND book_id=?').bind(user.id,id).first();
        return await json({page:row?.page||1},200,env,request);
      }
      if (method==='POST') {
        const body=await request.json().catch(()=>({})); const pg=Math.max(1,parseInt(body.page||1));
        await env.DB.prepare('INSERT INTO reading_progress(user_id,book_id,page,updated_at) VALUES(?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(user_id,book_id) DO UPDATE SET page=excluded.page,updated_at=CURRENT_TIMESTAMP').bind(user.id,id,pg).run();
        return await json({success:true,page:pg},200,env,request);
      }
    }

    if (url.pathname.match(/^\/api\/books\/\d+\/bookmarks$/)) {
      const user=await getUserFromReq(request,env);
      if(!user) return await json({error:'Unauthorized'},401,env,request);
      const id=url.pathname.split('/')[3];
      if(method==='GET'){ const rows=await env.DB.prepare('SELECT id,page,note,created_at FROM bookmarks WHERE user_id=? AND book_id=? ORDER BY page').bind(user.id,id).all(); return await json({bookmarks:rows.results},200,env,request); }
      if(method==='POST'){ const body=await request.json().catch(()=>({})); const pg=Math.max(1,parseInt(body.page||1)); const note=sanitizeString(body.note||'',500); await env.DB.prepare('INSERT OR REPLACE INTO bookmarks(user_id,book_id,page,note) VALUES(?,?,?,?)').bind(user.id,id,pg,note).run(); return await json({success:true},200,env,request); }
      if(method==='DELETE'){ const pg=parseInt(url.searchParams.get('page')||'0'); await env.DB.prepare('DELETE FROM bookmarks WHERE user_id=? AND book_id=? AND page=?').bind(user.id,id,pg).run(); return await json({success:true},200,env,request); }
    }

    if (url.pathname.startsWith('/api/books/') && method === 'GET') {
      const id = url.pathname.split('/').pop();
      if (!/^\d+$/.test(id)) return await json({ error: 'ID غير صالح' }, 400, env, request);
      const book = await env.DB.prepare("SELECT * FROM books WHERE id=? AND status='published'").bind(id).first();
      if (!book) return await json({ error: 'Not found' }, 404, env, request);
      return await json(book, 200, env, request);
    }

    if (url.pathname.startsWith('/api/books/') && method === 'PUT') {
      const user = await getUserFromReq(request, env);
      if (!user) return await json({ error: 'Unauthorized' }, 401, env, request);
      const id = url.pathname.split('/').pop();
      if (!/^\d+$/.test(id)) return await json({ error: 'ID غير صالح' }, 400, env, request);
      const book = await env.DB.prepare('SELECT owner_id FROM books WHERE id=?').bind(id).first();
      if (!book) return await json({ error: 'Not found' }, 404, env, request);
      if (user.role !== 'admin' && book.owner_id !== user.id) return await json({ error: 'غير مصرح' }, 403, env, request);
      try {
        const { title, author, description, cover_url, file_url } = await request.json();
        const cleanTitle = title ? sanitizeString(title, 200) : undefined;
        const cleanAuthor = author !== undefined ? sanitizeString(author, 100) : undefined;
        const cleanDesc = description !== undefined ? sanitizeString(description, 2000) : undefined;
        let setClause = []; let params = [];
        if (cleanTitle !== undefined) { setClause.push('title=?'); params.push(cleanTitle); }
        if (cleanAuthor !== undefined) { setClause.push('author=?'); params.push(cleanAuthor); }
        if (cleanDesc !== undefined) { setClause.push('description=?'); params.push(cleanDesc); }
        if (cover_url !== undefined && (cover_url.startsWith('/cdn/') || cover_url.startsWith('/api/file/') || cover_url === '')) { setClause.push('cover_url=?'); params.push(cover_url.slice(0,500)); }
        if (file_url !== undefined && (file_url.startsWith('/api/file/') || file_url.startsWith('/cdn/') || file_url === '')) { setClause.push('file_url=?'); params.push(file_url.slice(0,500)); }
        if (!setClause.length) return await json({ error: 'لا يوجد تعديل' }, 400, env, request);
        params.push(id);
        await env.DB.prepare(`UPDATE books SET ${setClause.join(',')} WHERE id=?`).bind(...params).run();
        return await json({ success: true }, 200, env, request);
      } catch(e) { return await json({ error: 'خطأ' }, 400, env, request); }
    }

    if (url.pathname.startsWith('/api/books/') && method === 'DELETE') {
      const user = await getUserFromReq(request, env);
      if (!user) return await json({ error: 'Unauthorized' }, 401, env, request);
      const id = url.pathname.split('/').pop();
      if (!/^\d+$/.test(id)) return await json({ error: 'ID غير صالح' }, 400, env, request);
      const book = await env.DB.prepare('SELECT owner_id FROM books WHERE id=?').bind(id).first();
      if (!book) return await json({ error: 'Not found' }, 404, env, request);
      if (user.role !== 'admin' && book.owner_id !== user.id) return await json({ error: 'غير مصرح' }, 403, env, request);
      await env.DB.prepare('DELETE FROM books WHERE id=?').bind(id).run();
      return await json({ success: true }, 200, env, request);
    }

    // ===== ARTICLES - مرن: مقفول أو مفتوح لسلسلة =====
    if (url.pathname === '/api/articles' && method === 'GET') {
      const page=Math.max(1,parseInt(url.searchParams.get('page')||'1'));
      const limit=Math.min(50,Math.max(1,parseInt(url.searchParams.get('limit')||'20')));
      const offset=(page-1)*limit;
      const mine=url.searchParams.get('mine')==='1';
      const authorId = url.searchParams.get('author_id') || url.searchParams.get('owner_id');
      const parentFilter = url.searchParams.get('parent_id');
      let where="a.status='published'", params=[];
      if(mine){ const u=await getUserFromReq(request,env); if(!u||(u.role!=='publisher'&&u.role!=='admin')) return await json({error:'غير مصرح'},403,env,request); where=u.role==='admin'?'1=1':'a.author_id=?'; if(u.role!=='admin') params.push(u.id); }
      else if (authorId && /^\d+$/.test(authorId)) { where += ' AND a.author_id=?'; params.push(parseInt(authorId)); }
      if (parentFilter && /^\d+$/.test(parentFilter)) { where += ' AND a.parent_id=?'; params.push(parseInt(parentFilter)); }
      else if (url.searchParams.get('roots_only')==='1') { where += ' AND (a.parent_id IS NULL OR a.parent_id=0)'; }
      const arts=await env.DB.prepare(`SELECT a.*,u.name as author_name,u.display_name,u.avatar_url,c.name as category_name,sc.name as subcategory_name FROM articles a LEFT JOIN users u ON a.author_id=u.id LEFT JOIN categories c ON a.category_id=c.id LEFT JOIN subcategories sc ON a.subcategory_id=sc.id WHERE ${where} ORDER BY a.id DESC LIMIT ? OFFSET ?`).bind(...params,limit,offset).all();
      const totalRow=await env.DB.prepare(`SELECT COUNT(*) as total FROM articles a WHERE ${where}`).bind(...params).first();
      const hasPageParam = url.searchParams.has('page') || url.searchParams.has('limit') || url.searchParams.has('mine') || url.searchParams.has('author_id') || url.searchParams.has('owner_id');
      if (!hasPageParam) return await json(arts.results, 200, env, request);
      return await json({articles:arts.results,total:totalRow?.total||0,page,limit},200,env,request);
    }

    if (url.pathname.match(/^\/api\/articles\/\d+$/) && method === 'GET') {
      const id=url.pathname.split('/').pop();
      if(!/^\d+$/.test(id)) return await json({error:'ID غير صالح'},400,env,request);
      const article=await env.DB.prepare("SELECT a.*,u.name as author_name,c.name as category_name,sc.name as subcategory_name FROM articles a LEFT JOIN users u ON a.author_id=u.id LEFT JOIN categories c ON a.category_id=c.id LEFT JOIN subcategories sc ON a.subcategory_id=sc.id WHERE a.id=? AND a.status='published'").bind(id).first();
      if(!article) return await json({error:'Not found'},404,env,request);
      let chapters=[];
      if(article.is_open==1){
        const ch=await env.DB.prepare("SELECT a.*,u.display_name FROM articles a LEFT JOIN users u ON a.author_id=u.id WHERE a.parent_id=? AND a.status='published' ORDER BY a.chapter_order ASC, a.id ASC").bind(id).all();
        chapters=ch.results||[];
      }
      return await json({...article, chapters},200,env,request);
    }

    if (url.pathname.match(/^\/api\/articles\/\d+\/chapters$/) && method === 'GET') {
      const id=url.pathname.split('/')[3];
      if(!/^\d+$/.test(id)) return await json({error:'ID غير صالح'},400,env,request);
      const ch=await env.DB.prepare("SELECT a.*,u.display_name FROM articles a LEFT JOIN users u ON a.author_id=u.id WHERE a.parent_id=? ORDER BY a.chapter_order ASC, a.id ASC").bind(id).all();
      return await json(ch.results||[],200,env,request);
    }

    if (url.pathname === '/api/articles' && method === 'POST') {
      const user = await getUserFromReq(request, env);
      if (!user || (user.role !== 'publisher' && user.role !== 'admin')) return await json({ error: 'غير مصرح' }, 403, env, request);
      try {
        const { title, content, cover_url, category_id, subcategory_id, parent_id, is_open, chapter_order } = await request.json();
        if (!title || title.trim().length < 3) return await json({ error: 'العنوان قصير' }, 400, env, request);
        if (!cover_url || !cover_url.startsWith('/cdn/')) return await json({ error: 'غلاف المقال مطلوب' }, 400, env, request);
        if (!content || content.trim().length < 10) return await json({ error: 'المحتوى قصير' }, 400, env, request);
        const coverKey=cover_url.replace('/cdn/','');
        const coverOwned=await env.DB.prepare("SELECT id FROM files WHERE key=? AND owner_id=? AND mime_type LIKE 'image/%'").bind(coverKey,user.id).first();
        if(!coverOwned) return await json({error:'غلاف المقال غير صالح أو غير مملوك لحسابك'},400,env,request);
        if(!category_id||!subcategory_id) return await json({error:'التصنيف والتصنيف الفرعي مطلوبان'},400,env,request);
        const sub=await env.DB.prepare('SELECT id FROM subcategories WHERE id=? AND category_id=?').bind(subcategory_id,category_id).first();
        if(!sub) return await json({error:'التصنيف الفرعي لا يتبع التصنيف الرئيسي'},400,env,request);

        let cleanParent=null; let cleanIsOpen=0; let cleanOrder=null;
        if(parent_id && /^\d+$/.test(String(parent_id))){
          const parent=await env.DB.prepare('SELECT author_id,is_open FROM articles WHERE id=?').bind(parseInt(parent_id)).first();
          if(!parent) return await json({error:'المقال الأب غير موجود'},400,env,request);
          if(parent.is_open!=1) return await json({error:'المقال الأب مقفول ولا يقبل فصول'},400,env,request);
          if(parent.author_id!=user.id && user.role!='admin') return await json({error:'لا يمكنك إضافة فصل لمقال ليس لك'},403,env,request);
          cleanParent=parseInt(parent_id);
          const mx=await env.DB.prepare('SELECT MAX(chapter_order) as mx FROM articles WHERE parent_id=?').bind(cleanParent).first();
          cleanOrder=chapter_order ? parseInt(chapter_order) : ((mx?.mx||0)+1);
        } else {
          cleanIsOpen=is_open?1:0;
        }

        const cleanTitle = sanitizeString(title, 200);
        const cleanContent = sanitizeString(content, 50000);
        const res = await env.DB.prepare("INSERT INTO articles (title,content,cover_url,category_id,subcategory_id,author_id,parent_id,is_open,chapter_order,status) VALUES (?,?,?,?,?,?,?,?,?, 'pending')").bind(cleanTitle, cleanContent, cover_url, category_id, subcategory_id, user.id, cleanParent, cleanIsOpen, cleanOrder).run();
        return await json({ id: res.meta.last_row_id, success: true }, 200, env, request);
      } catch(e) { return await json({ error: 'بيانات غير صالحة: '+e.message }, 400, env, request); }
    }

    if (url.pathname.startsWith('/api/articles/') && method === 'PUT') {
      const user = await getUserFromReq(request, env);
      if (!user) return await json({ error: 'Unauthorized' }, 401, env, request);
      const id = url.pathname.split('/').pop();
      if (!/^\d+$/.test(id)) return await json({ error: 'ID غير صالح' }, 400, env, request);
      const art = await env.DB.prepare('SELECT author_id FROM articles WHERE id=?').bind(id).first();
      if (!art) return await json({ error: 'Not found' }, 404, env, request);
      if (user.role !== 'admin' && art.author_id !== user.id) return await json({ error: 'غير مصرح' }, 403, env, request);
      try {
        const { title, content, cover_url, is_open } = await request.json();
        let setClause = []; let params = [];
        if (title !== undefined) { setClause.push('title=?'); params.push(sanitizeString(title,200)); }
        if (content !== undefined) { setClause.push('content=?'); params.push(sanitizeString(content,50000)); }
        if (cover_url !== undefined && (cover_url.startsWith('/cdn/') || cover_url === '')) { setClause.push('cover_url=?'); params.push(cover_url.slice(0,500)); }
        if (is_open !== undefined) { setClause.push('is_open=?'); params.push(is_open?1:0); }
        if (!setClause.length) return await json({ error: 'لا يوجد تعديل' }, 400, env, request);
        params.push(id);
        await env.DB.prepare(`UPDATE articles SET ${setClause.join(',')} WHERE id=?`).bind(...params).run();
        return await json({ success: true }, 200, env, request);
      } catch(e) { return await json({ error: 'خطأ' }, 400, env, request); }
    }

    if (url.pathname.startsWith('/api/articles/') && method === 'DELETE') {
      const user = await getUserFromReq(request, env);
      if (!user) return await json({ error: 'Unauthorized' }, 401, env, request);
      const id = url.pathname.split('/').pop();
      if (!/^\d+$/.test(id)) return await json({ error: 'ID غير صالح' }, 400, env, request);
      const art = await env.DB.prepare('SELECT author_id FROM articles WHERE id=?').bind(id).first();
      if (!art) return await json({ error: 'Not found' }, 404, env, request);
      if (user.role !== 'admin' && art.author_id !== user.id) return await json({ error: 'غير مصرح' }, 403, env, request);
      await env.DB.prepare('DELETE FROM articles WHERE parent_id=?').bind(id).run();
      await env.DB.prepare('DELETE FROM articles WHERE id=?').bind(id).run();
      return await json({ success: true }, 200, env, request);
    }

    // ===== ADS - نفس كودك الأصلي بدون أي تغيير =====
    if (url.pathname === '/api/ads' && method === 'GET') {
      const placement = sanitizeString(url.searchParams.get('placement') || '', 50);
      const ownerId = url.searchParams.get('owner_id');
      let query, params;
      if (placement && ownerId && /^\d+$/.test(ownerId)) {
        query = 'SELECT * FROM ads WHERE placement=? AND owner_id=? AND is_active=1 ORDER BY id DESC LIMIT 20';
        params = [placement, ownerId];
      } else if (placement) {
        query = 'SELECT * FROM ads WHERE placement=? AND (owner_id IS NULL OR owner_id=0) AND is_active=1 ORDER BY id DESC LIMIT 20';
        params = [placement];
      } else if (ownerId && /^\d+$/.test(ownerId)) {
        query = 'SELECT * FROM ads WHERE owner_id=? AND is_active=1 ORDER BY id DESC LIMIT 20';
        params = [ownerId];
      } else {
        query = 'SELECT * FROM ads WHERE is_active=1 ORDER BY id DESC LIMIT 50';
        params = [];
      }
      const ads = await env.DB.prepare(query).bind(...params).all();
      const sanitized = ads.results.map(ad => ({ ...ad, custom_html: ad.custom_html ? sanitizeHTML(ad.custom_html) : '', title: sanitizeString(ad.title || '', 100) }));
      return await json(sanitized, 200, env, request);
    }

    if (url.pathname === '/api/ads' && method === 'POST') {
      const user = await getUserFromReq(request, env);
      if (!user || (user.role !== 'publisher' && user.role !== 'admin')) return await json({ error: 'غير مصرح' }, 403, env, request);
      try {
        const { title, placement, type, custom_html, image_url, link_url, owner_id } = await request.json();
        if (!title || !placement) return await json({ error: 'العنوان والمكان مطلوبان' }, 400, env, request);
        const cleanTitle = sanitizeString(title, 100);
        const cleanPlacement = sanitizeString(placement, 50);
        const allowedTypes = ['image_link', 'custom_html'];
        const cleanType = allowedTypes.includes(type) ? type : 'image_link';
        let cleanHTML = '';
        if (cleanType === 'custom_html' && custom_html) {
          cleanHTML = user.role === 'admin' ? sanitizeHTML(custom_html) : sanitizeAdHTML(custom_html);
        }
        const cleanImageUrl = image_url && (image_url.startsWith('/cdn/') || image_url.startsWith('https://')) ? image_url.slice(0,500) : '';
        const cleanLinkUrl = link_url && (link_url.startsWith('https://') || link_url.startsWith('/')) ? link_url.slice(0,500) : '';
        const finalOwner = user.role === 'admin' ? (owner_id && /^\d+$/.test(owner_id) ? owner_id : null) : user.id;
        const res = await env.DB.prepare('INSERT INTO ads (title,placement,type,custom_html,image_url,link_url,owner_id) VALUES (?,?,?,?,?,?,?)')
          .bind(cleanTitle, cleanPlacement, cleanType, cleanHTML, cleanImageUrl, cleanLinkUrl, finalOwner).run();
        return await json({ id: res.meta.last_row_id, success: true }, 200, env, request);
      } catch(e) { return await json({ error: 'بيانات غير صالحة' }, 400, env, request); }
    }

    if (url.pathname.startsWith('/api/ads/') && method === 'DELETE') {
      const user = await getUserFromReq(request, env);
      if (!user) return await json({ error: 'Unauthorized' }, 401, env, request);
      const id = url.pathname.split('/').pop();
      if (!/^\d+$/.test(id)) return await json({ error: 'ID غير صالح' }, 400, env, request);
      const ad = await env.DB.prepare('SELECT owner_id FROM ads WHERE id=?').bind(id).first();
      if (!ad) return await json({ error: 'Not found' }, 404, env, request);
      if (user.role !== 'admin' && ad.owner_id !== user.id) return await json({ error: 'غير مصرح' }, 403, env, request);
      await env.DB.prepare('DELETE FROM ads WHERE id=?').bind(id).run();
      return await json({ success: true }, 200, env, request);
    }

    // ===== PUBLISHER REQUESTS =====
    if (url.pathname === '/api/publisher-requests' && method === 'GET') {
      const user = await getUserFromReq(request, env);
      if (!user || user.role !== 'admin') return await json({ error: 'Admin only' }, 403, env, request);
      const reqs = await env.DB.prepare('SELECT pr.*, u.email FROM publisher_requests pr JOIN users u ON pr.user_id=u.id ORDER BY pr.id DESC LIMIT 100').all();
      return await json(reqs.results, 200, env, request);
    }

    if (url.pathname === '/api/publisher-requests' && method === 'POST') {
      const user = await getUserFromReq(request, env);
      if (!user) return await json({ error: 'Unauthorized' }, 401, env, request);
      try {
        const { name, reason, samples } = await request.json();
        if (!name || !reason) return await json({ error: 'الاسم والسبب مطلوبان' }, 400, env, request);
        const cleanName = sanitizeString(name, 100);
        const cleanReason = sanitizeString(reason, 500);
        const cleanSamples = sanitizeString(samples || '', 500);
        const existing = await env.DB.prepare('SELECT id FROM publisher_requests WHERE user_id=? AND status=?').bind(user.id, 'pending').first();
        if (existing) return await json({ error: 'لديك طلب معلق' }, 400, env, request);
        const res = await env.DB.prepare('INSERT INTO publisher_requests (user_id,name,reason,samples) VALUES (?,?,?,?)').bind(user.id, cleanName, cleanReason, cleanSamples).run();
        return await json({ id: res.meta.last_row_id, success: true }, 200, env, request);
      } catch(e) { return await json({ error: 'بيانات غير صالحة' }, 400, env, request); }
    }

    if (url.pathname.startsWith('/api/publisher-requests/') && method === 'PUT') {
      const authUser = await getUserFromReq(request, env);
      if (!authUser || authUser.role !== 'admin') return await json({ error: 'Admin only' }, 403, env, request);
      const id = url.pathname.split('/').pop();
      if (!/^\d+$/.test(id)) return await json({ error: 'ID غير صالح' }, 400, env, request);
      try {
        const { status } = await request.json();
        if (!['approved','rejected'].includes(status)) return await json({ error: 'Invalid status' }, 400, env, request);
        await env.DB.prepare('UPDATE publisher_requests SET status=? WHERE id=?').bind(status, id).run();
        if (status === 'approved') {
          await env.DB.prepare("UPDATE users SET role='publisher', is_publisher=1 WHERE id=(SELECT user_id FROM publisher_requests WHERE id=?)").bind(id).run();
        } else {
          await env.DB.prepare("UPDATE users SET is_publisher=0 WHERE id=(SELECT user_id FROM publisher_requests WHERE id=?) AND role!='admin'").bind(id).run();
        }
        return await json({ success: true, status }, 200, env, request);
      } catch(e) { return await json({ error: 'بيانات غير صالحة' }, 400, env, request); }
    }

    // ===== PROFILE =====
    if (url.pathname === '/api/profile' && method === 'GET') {
      const user = await getUserFromReq(request, env);
      if (!user) return await json({ error: 'Unauthorized' }, 401, env, request);
      const full = await env.DB.prepare('SELECT id,email,name,display_name,bio,avatar_url,website,role,is_publisher,verified FROM users WHERE id=?').bind(user.id).first();
      return await json(full || user, 200, env, request);
    }

    if (url.pathname === '/api/profile' && method === 'PUT') {
      const user = await getUserFromReq(request, env);
      if (!user) return await json({ error: 'Unauthorized' }, 401, env, request);
      try {
        const { display_name, bio, avatar_url, website } = await request.json();
        const cleanName = sanitizeString(display_name || '', 100);
        const cleanBio = sanitizeString(bio || '', 500);
        const cleanWebsite = (website && (website.startsWith('https://') || website.startsWith('http://')) ? website.slice(0,300) : '');
        let cleanAvatar = '';
        if (avatar_url && (avatar_url.startsWith('/cdn/') || avatar_url.startsWith('https://') || avatar_url.startsWith('/api/file/'))) cleanAvatar = avatar_url.slice(0,500);
        await env.DB.prepare('UPDATE users SET display_name=?, bio=?, avatar_url=?, website=?, name=? WHERE id=?')
          .bind(cleanName, cleanBio, cleanAvatar, cleanWebsite, cleanName, user.id).run();
        return await json({ success: true, display_name: cleanName, bio: cleanBio, avatar_url: cleanAvatar }, 200, env, request);
      } catch(e) { return await json({ error: 'خطأ في الحفظ' }, 400, env, request); }
    }

    if (url.pathname === '/api/upload/avatar' && method === 'POST') {
      const user = await getUserFromReq(request, env);
      if (!user) return await json({ error: 'Unauthorized' }, 401, env, request);
      try {
        const form = await request.formData();
        const file = form.get('file');
        if (!file || !file.size) return await json({ error: 'لا يوجد ملف' }, 400, env, request);
        if (file.size > 2*1024*1024) return await json({ error: 'الصورة كبيرة - حد أقصى 2MB' }, 400, env, request);
        if (!file.type.startsWith('image/')) return await json({ error: 'نوع الصورة غير مسموح' }, 400, env, request);
        const ext = file.name.split('.').pop() || 'jpg';
        const key = `avatars/${user.id}-${Date.now()}.${ext}`;
        await env.R2.put(key, file.stream(), { httpMetadata: { contentType: file.type } });
        const avatarUrl = `/cdn/${key}`;
        await env.DB.prepare('UPDATE users SET avatar_url=? WHERE id=?').bind(avatarUrl, user.id).run();
        return await json({ url: avatarUrl, success: true }, 200, env, request);
      } catch(e) { return await json({ error: 'فشل الرفع' }, 500, env, request); }
    }

    if (url.pathname.match(/^\/api\/users\/\d+\/public$/) && method === 'GET') {
      const id = url.pathname.split('/')[3];
      if (!/^\d+$/.test(id)) return await json({ error: 'ID غير صالح' }, 400, env, request);
      const u = await env.DB.prepare('SELECT id, display_name, name, bio, avatar_url, website, verified, role FROM users WHERE id=?').bind(id).first();
      if (!u) return await json({ error: 'Not found' }, 404, env, request);
      return await json(u, 200, env, request);
    }

    // ===== ADMIN =====
    if (url.pathname === '/api/admin/users' && method === 'GET') {
      const user = await getUserFromReq(request, env);
      if (!user || user.role !== 'admin') return await json({ error: 'Admin only' }, 403, env, request);
      const users = await env.DB.prepare(`
        SELECT u.id, u.email, u.name, u.display_name, u.bio, u.avatar_url, u.website, u.role, u.verified, u.is_publisher,
        (SELECT COUNT(*) FROM books WHERE owner_id=u.id) as books_count
        FROM users u ORDER BY u.id DESC LIMIT 200
      `).all();
      return await json(users.results, 200, env, request);
    }

    if (url.pathname === '/api/admin/settings' && (method === 'GET' || method === 'PUT')) {
      const user = await getUserFromReq(request, env);
      if (!user || user.role !== 'admin') return await json({error:'Admin only'},403,env,request);
      if (method === 'GET') {
        const rows = await env.DB.prepare("SELECT key,value,updated_at FROM app_settings ORDER BY key").all();
        const settings = Object.fromEntries((rows.results || []).map(r => [r.key, r.value]));
        return await json({allowed_origin: settings.allowed_origin || env.ALLOWED_ORIGIN || 'https://rufuf.pages.dev'},200,env,request);
      }
      try {
        const body = await request.json();
        const allowed_origin = validateAllowedOrigins(body.allowed_origin);
        if (!allowed_origin) return await json({error:'نطاق CORS غير صالح'},400,env,request);
        await env.DB.prepare("INSERT INTO app_settings (key,value,updated_at) VALUES ('allowed_origin',?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP").bind(allowed_origin).run();
        await invalidateSettingsCache();
        return await json({success:true,allowed_origin},200,env,request);
      } catch (e) { return await json({error:'تعذر تحديث الإعدادات'},400,env,request); }
    }

    if (url.pathname === '/api/admin/stats' && method === 'GET') {
      const user=await getUserFromReq(request,env);
      if(!user||user.role!=='admin') return await json({error:'Admin only'},403,env,request);
      const [books,articles,users,pendingBooks,pendingArticles]=await Promise.all([
        env.DB.prepare("SELECT COUNT(*) total FROM books").first(),
        env.DB.prepare("SELECT COUNT(*) total FROM articles").first(),
        env.DB.prepare("SELECT COUNT(*) total FROM users").first(),
        env.DB.prepare("SELECT COUNT(*) total FROM books WHERE status='pending'").first(),
        env.DB.prepare("SELECT COUNT(*) total FROM articles WHERE status='pending'").first()
      ]);
      return await json({books:books.total||0,articles:articles.total||0,users:users.total||0,pending_books:pendingBooks.total||0,pending_articles:pendingArticles.total||0},200,env,request);
    }

    if ((url.pathname.startsWith('/api/admin/books/') || url.pathname.startsWith('/api/admin/articles/')) && method === 'PUT') {
      const user=await getUserFromReq(request,env);
      if(!user||user.role!=='admin') return await json({error:'Admin only'},403,env,request);
      const parts=url.pathname.split('/');
      const type=parts[3]; const id=parts[4];
      if(!/^\d+$/.test(id)||!['books','articles'].includes(type)) return await json({error:'ID غير صالح'},400,env,request);
      const {status}=await request.json();
      if(!['pending','published','rejected'].includes(status)) return await json({error:'Invalid status'},400,env,request);
      await env.DB.prepare(`UPDATE ${type} SET status=? WHERE id=?`).bind(status,id).run();
      return await json({success:true,status},200,env,request);
    }

    // ===== FORUM (polling) =====
    if (url.pathname === '/api/forum' && method === 'GET') {
      const rows = await env.DB.prepare(`SELECT fm.id, fm.message, fm.created_at, u.name AS user_name FROM forum_messages fm LEFT JOIN users u ON u.id=fm.user_id ORDER BY fm.id DESC LIMIT 100`).all();
      return await json({messages: (rows.results || []).reverse()}, 200, env, request);
    }
    if (url.pathname === '/api/forum' && method === 'POST') {
      const user = await getUserFromReq(request, env);
      if (!user) return await json({error:'Unauthorized'},401,env,request);
      try {
        const body = await request.json();
        const message = sanitizeString(body.message || '', 1000);
        if (!message) return await json({error:'الرسالة فارغة'},400,env,request);
        await env.DB.prepare('INSERT INTO forum_messages (room,user_id,message) VALUES (?,?,?)').bind('general', user.id, message).run();
        return await json({success:true},201,env,request);
      } catch (_) { return await json({error:'تعذر إرسال الرسالة'},400,env,request); }
    }

    return await json({ error: 'Route not found' }, 404, env, request);
  }
};
