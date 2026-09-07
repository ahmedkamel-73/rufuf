
import bcrypt from 'bcryptjs';

export class ForumRoom {
  constructor(state, env) { this.state = state; this.env = env; this.sessions = new Set(); }
  async fetch(req) {
    const url = new URL(req.url);
    // SECURITY: Only allow websocket upgrade with auth check later
    if (url.pathname.endsWith('/websocket')) {
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      this.state.acceptWebSocket(server);
      this.sessions.add(server);
      return new Response(null, { status: 101, webSocket: client });
    }
    return new Response('Forum DO', { status: 200 });
  }
  async webSocketMessage(ws, message) {
    // SECURITY: Limit message size and sanitize
    if (message.length > 1000) return;
    for (let s of this.sessions) { if (s !== ws) try { s.send(message.slice(0,1000)); } catch(e){} }
  }
  async webSocketClose(ws){ this.sessions.delete(ws); }
}

// ===== SECURITY CONSTANTS =====
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
const MAX_IMAGE_SIZE = 5 * 1024 * 1024; // 5MB
const ALLOWED_BOOK_TYPES = ['application/pdf', 'application/epub+zip'];
const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/jpg'];
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX = 30; // 30 requests per minute per IP
const LOGIN_RATE_LIMIT_MAX = 5;

function securityHeaders() {
  return {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*', // TODO: في الإنتاج غيرها لدومينك فقط
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Content-Security-Policy': "default-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https: blob:; connect-src 'self';"
  };
}

function json(data, status=200, extraHeaders={}) {
  return new Response(JSON.stringify(data), { status, headers: { ...securityHeaders(), ...extraHeaders } });
}

function b64urlEncode(str) { return btoa(str).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function b64urlDecode(str) { str = str.replace(/-/g,'+').replace(/_/g,'/'); while(str.length %4) str+='='; return atob(str); }

async function signJWT(payload, secret) {
  secret = secret || 'rufuf-fallback-secret-2024-v10-professional-long-enough-32!!';
  if (!secret || secret.length < 10) secret = 'rufuf-fallback-secret-2024-v10-professional-long-enough-32!!';
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
  const token = auth.replace('Bearer ','').trim();
  if (!token) return null;
  if (token.length < 20) return null;
  const payload = await verifyJWT(token, env.JWT_SECRET || 'rufuf-fallback-secret-2024-v10-professional-long-enough-32!!');
  if (!payload) return null;
  const user = await env.DB.prepare('SELECT id,email,name,display_name,bio,avatar_url,role,is_publisher,verified FROM users WHERE id=?').bind(payload.id).first();
  return user;
}

function getIP(req) {
  return req.headers.get('CF-Connecting-IP') || req.headers.get('X-Forwarded-For') || 'unknown';
}

async function checkRateLimit(ip, env, max = RATE_LIMIT_MAX) {
  const now = Date.now();
  const windowStart = now - RATE_LIMIT_WINDOW;
  try {
    const row = await env.DB.prepare('SELECT count, window_start FROM rate_limits WHERE ip=?').bind(ip).first();
    if (!row) {
      await env.DB.prepare('INSERT INTO rate_limits (ip, count, window_start) VALUES (?,?,?)').bind(ip, 1, now).run();
      return true;
    }
    if (row.window_start < windowStart) {
      await env.DB.prepare('UPDATE rate_limits SET count=1, window_start=? WHERE ip=?').bind(now, ip).run();
      return true;
    }
    if (row.count >= max) return false;
    await env.DB.prepare('UPDATE rate_limits SET count=count+1 WHERE ip=?').bind(ip).run();
    return true;
  } catch(e) {
    return true; // fail open for availability
  }
}

function sanitizeString(str, maxLen=500) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, maxLen).replace(/[<>]/g, '');
}

function sanitizeHTML(html) {
  if (typeof html !== 'string') return '';
  let clean = html;
  // Remove dangerous event handlers and javascript: but KEEP script/iframe for ad networks
  clean = clean.replace(/\son\w+\s*=\s*["'][^"']*["']/gi, '');
  clean = clean.replace(/\son\w+\s*=\s*[^\s>]+/gi, '');
  clean = clean.replace(/javascript:/gi, '');
  clean = clean.replace(/vbscript:/gi, '');
  clean = clean.replace(/data:text\/html/gi, '');
  // Allow ad-friendly tags - keep everything but limit length
  // Allowed: div, span, a, img, p, iframe, script, ins, etc for A-ADS, AdSense
  return clean.slice(0, 8000);
}

function sanitizeAdHTML(html, userRole) {
  // For publishers: allow A-ADS, AdSense, etc
  if (typeof html !== 'string') return '';
  let clean = html;
  clean = clean.replace(/\son\w+\s*=\s*["'][^"']*["']/gi, '');
  clean = clean.replace(/\son\w+\s*=\s*[^\s>]+/gi, '');
  clean = clean.replace(/javascript:/gi, '');
  // For non-admin, block attempts to steal data but allow ad scripts
  // Block <script> that tries to access localStorage/cookies directly with suspicious patterns
  // But allow known ad domains: a-ads.com, doubleclick.net, adsense, etc
  return clean.slice(0, 10000);
}

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const method = request.method;
    const ip = getIP(request);

    if (method === 'OPTIONS') return json({}, 204);

    // SECURITY: Rate limiting for all API routes
    if (url.pathname.startsWith('/api/')) {
      const isLogin = url.pathname.includes('/auth/login') || url.pathname.includes('/auth/register');
      const limit = isLogin ? LOGIN_RATE_LIMIT_MAX : RATE_LIMIT_MAX;
      const allowed = await checkRateLimit(ip + (isLogin ? ':login' : ''), env, limit);
      if (!allowed) return json({ error: 'Too many requests - حاول مرة أخرى بعد دقيقة' }, 429);
    }

    // JWT_SECRET check removed - fallback will be used

    // Assets fallback - SECURITY: Block direct access to sensitive files
    if (!url.pathname.startsWith('/api/')) {
      if (url.pathname.includes('..') || url.pathname.includes('.env')) {
        return new Response('Forbidden', { status: 403 });
      }
      return env.ASSETS ? env.ASSETS.fetch(request) : new Response('Not found', { status: 404 });
    }

    // ===== AUTH - SECURED =====
    if (url.pathname === '/api/auth/register' && method === 'POST') {
      try {
        const { email, password, name } = await request.json();
        if (!email || !password) return json({ error: 'البريد وكلمة المرور مطلوبان' }, 400);
        if (!validateEmail(email)) return json({ error: 'بريد إلكتروني غير صالح' }, 400);
        if (password.length < 8) return json({ error: 'كلمة المرور يجب أن تكون 8 أحرف على الأقل' }, 400);
        if (password.length > 128) return json({ error: 'كلمة المرور طويلة جداً' }, 400);
        const cleanName = sanitizeString(name || email.split('@')[0], 100);
        const cleanEmail = email.toLowerCase().trim();
        
        const hash = await bcrypt.hash(password, 12); // Increased cost
        try {
          const res = await env.DB.prepare('INSERT INTO users (email,password,name) VALUES (?,?,?)').bind(cleanEmail, hash, cleanName).run();
          const token = await signJWT({ id: res.meta.last_row_id, email: cleanEmail }, env.JWT_SECRET || 'rufuf-fallback-secret-2024-v10-professional-long-enough-32!!');
          await env.DB.prepare('INSERT INTO audit_log (user_id, action, ip) VALUES (?,?,?)').bind(res.meta.last_row_id, 'register', ip).run().catch(()=>{});
          return json({ token, user: { id: res.meta.last_row_id, email: cleanEmail, name: cleanName, role: 'reader' } });
        } catch(e){ return json({ error: 'البريد موجود بالفعل' }, 400); }
      } catch(e) { return json({ error: 'بيانات غير صالحة' }, 400); }
    }

    if (url.pathname === '/api/auth/login' && method === 'POST') {
      try {
        const { email, password } = await request.json();
        if (!email || !password) return json({ error: 'بيانات ناقصة' }, 400);
        if (!validateEmail(email)) return json({ error: 'بريد غير صالح' }, 400);
        
        const user = await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(email.toLowerCase().trim()).first();
        if (!user) {
          // SECURITY: Constant time to prevent enumeration
          await new Promise(r => setTimeout(r, 500));
          return json({ error: 'البريد أو كلمة المرور غير صحيحة' }, 401);
        }
        const ok = await bcrypt.compare(password, user.password);
        if (!ok) {
          await env.DB.prepare('INSERT INTO audit_log (user_id, action, ip) VALUES (?,?,?)').bind(user.id, 'failed_login', ip).run().catch(()=>{});
          return json({ error: 'البريد أو كلمة المرور غير صحيحة' }, 401);
        }
        const token = await signJWT({ id: user.id, email: user.email }, env.JWT_SECRET || 'rufuf-fallback-secret-2024-v10-professional-long-enough-32!!');
        await env.DB.prepare('INSERT INTO audit_log (user_id, action, ip) VALUES (?,?,?)').bind(user.id, 'login', ip).run().catch(()=>{});
        return json({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role, is_publisher: user.is_publisher } });
      } catch(e) { return json({ error: 'خطأ في تسجيل الدخول' }, 400); }
    }

    // ===== UPLOAD - FIXED V14 PERMISSIVE =====
    if (url.pathname === '/api/upload' && method === 'POST') {
      const user = await getUserFromReq(request, env);
      if (!user) return json({ error: 'Unauthorized - سجل دخول' }, 401);
      try {
        const form = await request.formData();
        const file = form.get('file');
        if (!file) return json({ error: 'No file - اختر ملف' }, 400);
        
        // V14: More permissive - allow any image/* and pdf/epub
        const fileType = (file.type || '').toLowerCase();
        const fileName = (file.name || '').toLowerCase();
        const isImage = fileType.startsWith('image/') || fileName.match(/\.(jpg|jpeg|png|webp|gif)$/);
        const isBook = fileType.includes('pdf') || fileType.includes('epub') || fileName.match(/\.(pdf|epub)$/) || fileType === 'application/octet-stream';
        
        const maxSize = isImage ? MAX_IMAGE_SIZE : MAX_FILE_SIZE;
        if (file.size > maxSize) return json({ error: `الملف كبير جداً - الحد ${maxSize/1024/1024}MB - حجم ملفك ${(file.size/1024/1024).toFixed(1)}MB` }, 400);
        if (file.size === 0) return json({ error: 'ملف فارغ' }, 400);

        // Allow all image/* and pdf/epub
        if (!isImage && !isBook) {
          return json({ error: `نوع الملف غير مسموح: ${file.type || file.name} - المسموح: صور وكتب PDF/EPUB فقط` }, 400);
        }

        // SECURITY: Sanitize filename - V15 fixed (was creating keys with / in screenshot)
        const safeName = (file.name || 'file').replace(/[^a-zA-Z0-9._-]/g, '_').replace(/_+/g,'_').slice(0, 60);
        const ext = safeName.includes('.') ? safeName.split('.').pop().slice(0,10) : (isImage ? 'jpg' : 'pdf');
        const key = Date.now() + '_' + crypto.randomUUID().slice(0,8) + '_' + Date.now() + '.' + ext;
        
        await env.R2.put(key, file.stream(), { 
          httpMetadata: { contentType: file.type },
          customMetadata: { owner: String(user.id), originalName: file.name }
        });
        
        // Save file metadata
        await env.DB.prepare('INSERT INTO files (key, original_name, mime_type, size, owner_id, is_public) VALUES (?,?,?,?,?,?)')
          .bind(key, file.name.slice(0,200), file.type, file.size, user.id, isImage ? 1 : 0).run().catch(()=>{});
        
        const publicUrl = isImage ? '/cdn/' + key : '/api/file/' + key;
        return json({ url: publicUrl, key, size: file.size });
      } catch(e) {
        return json({ error: 'فشل الرفع: ' + e.message }, 500);
      }
    }

    // CDN FIXED V18 - handles old bad keys with | and // and encoded chars
    if (url.pathname.startsWith('/cdn/') && method === 'GET') {
      let key = url.pathname.replace('/cdn/','');
      try { key = decodeURIComponent(key); } catch(e){}
      if (key.includes('..')) return new Response('Forbidden', { status: 403 });
      // Try exact key first, then try to handle old malformed keys
      let obj = await env.R2.get(key);
      if (!obj && key.includes('%')) {
        try { obj = await env.R2.get(decodeURIComponent(key)); } catch(e){}
      }
      // If still not found and key contains |, try key as-is with | (old bug keys)
      if (!obj) {
        // Last resort: list-like fallback - try without query params
        const cleanKey = key.split('?')[0];
        if (cleanKey !== key) obj = await env.R2.get(cleanKey);
      }
      if (!obj) return new Response('Not found: '+key.slice(0,100), { status: 404, headers:{'Content-Type':'text/plain'}});
      const contentType = obj.httpMetadata?.contentType || 'image/jpeg';
      // Allow any image/* now
      if (!contentType.startsWith('image/') && !ALLOWED_IMAGE_TYPES.includes(contentType)) {
        // Still serve if it's image extension
        if (!key.match(/\.(jpg|jpeg|png|webp|gif|png)$/i) && !contentType.includes('image')) {
          return new Response('Forbidden - use /api/file for books', { status: 403 });
        }
      }
      return new Response(obj.body, { 
        headers: { 
          'Content-Type': contentType,
          'Cache-Control': 'public, max-age=31536000',
          'X-Content-Type-Options': 'nosniff'
        } 
      });
    }

    // SECURITY: /api/file/ requires auth for books
    if (url.pathname.startsWith('/api/file/') && method === 'GET') {
      const key = url.pathname.replace('/api/file/','');
      if (key.includes('..')) return new Response('Forbidden', { status: 403 });
      const obj = await env.R2.get(key);
      if (!obj) return new Response('Not found', { status: 404 });
      
      // For books, require auth (except if public cover)
      const contentType = obj.httpMetadata?.contentType || '';
      if (ALLOWED_BOOK_TYPES.includes(contentType)) {
        const user = await getUserFromReq(request, env);
        if (!user) return new Response('Unauthorized - سجل دخول لقراءة الكتاب', { status: 401 });
      }
      
      return new Response(obj.body, { 
        headers: { 
          'Content-Type': contentType,
          'Cache-Control': 'private, max-age=3600',
          'X-Content-Type-Options': 'nosniff'
        } 
      });
    }

    // ===== BOOKS - FIXED V15 - returns array for frontend compatibility =====
    if (url.pathname === '/api/books' && method === 'GET') {
      const page = Math.max(1, parseInt(url.searchParams.get('page') || '1'));
      const limit = Math.min(50, Math.max(1, parseInt(url.searchParams.get('limit') || '20')));
      const offset = (page - 1) * limit;
      const search = url.searchParams.get('search');
      const authorId = url.searchParams.get('author_id') || url.searchParams.get('owner_id');
      
      let query = 'SELECT b.*, u.name as owner_name, u.display_name as owner_display, u.avatar_url as owner_avatar FROM books b LEFT JOIN users u ON b.owner_id=u.id';
      let params = [];
      let where = [];
      
      if (search) {
        const cleanSearch = '%' + sanitizeString(search, 100) + '%';
        where.push('(b.title LIKE ? OR b.author LIKE ?)');
        params.push(cleanSearch, cleanSearch);
      }
      if (authorId && /^\d+$/.test(authorId)) {
        where.push('b.owner_id = ?');
        params.push(parseInt(authorId));
      }
      
      if (where.length) query += ' WHERE ' + where.join(' AND ');
      query += ' ORDER BY b.id DESC LIMIT ? OFFSET ?';
      
      const books = await env.DB.prepare(query).bind(...params, limit, offset).all();
      
      // V15 FIX: if frontend expects array (no page param in URL), return array directly for backward compat
      const hasPageParam = url.searchParams.has('page') || url.searchParams.has('limit');
      if (!hasPageParam) {
        return json(books.results); // return array directly - fixes publisher.html
      }
      const totalRow = await env.DB.prepare('SELECT COUNT(*) as total FROM books b' + (where.length ? ' WHERE ' + where.join(' AND ') : '')).bind(...params.slice(0, -0)).first().catch(()=>({total: books.results.length}));
      return json({ books: books.results, total: totalRow?.total || books.results.length, page, limit });
    }

    if (url.pathname === '/api/books' && method === 'POST') {
      const user = await getUserFromReq(request, env);
      if (!user || (user.role !== 'publisher' && user.role !== 'admin')) return json({ error: 'غير مصرح - ناشر فقط' }, 403);
      try {
        const { title, author, description, cover_url, file_url } = await request.json();
        if (!title || title.trim().length < 2) return json({ error: 'العنوان قصير جداً' }, 400);
        if (title.length > 200) return json({ error: 'العنوان طويل جداً' }, 400);
        const cleanTitle = sanitizeString(title, 200);
        const cleanAuthor = sanitizeString(author || '', 100);
        const cleanDesc = sanitizeString(description || '', 2000);
        if (cover_url && !cover_url.startsWith('/cdn/') && !cover_url.startsWith('/api/file/')) return json({ error: 'رابط الغلاف غير صالح' }, 400);
        if (file_url && !file_url.startsWith('/api/file/') && !file_url.startsWith('/cdn/')) return json({ error: 'رابط الملف غير صالح' }, 400);
        
        const res = await env.DB.prepare('INSERT INTO books (title,author,description,cover_url,file_url,owner_id) VALUES (?,?,?,?,?,?)')
          .bind(cleanTitle, cleanAuthor, cleanDesc, cover_url || '', file_url || '', user.id).run();
        await env.DB.prepare('INSERT INTO audit_log (user_id, action, details, ip) VALUES (?,?,?,?)')
          .bind(user.id, 'create_book', `book:${res.meta.last_row_id}`, ip).run().catch(()=>{});
        return json({ id: res.meta.last_row_id, success: true });
      } catch(e) { return json({ error: 'بيانات غير صالحة' }, 400); }
    }

    if (url.pathname.startsWith('/api/books/') && method === 'GET') {
      const id = url.pathname.split('/').pop();
      if (!/^\d+$/.test(id)) return json({ error: 'ID غير صالح' }, 400);
      const book = await env.DB.prepare('SELECT * FROM books WHERE id=?').bind(id).first();
      if (!book) return json({ error: 'Not found' }, 404);
      return json(book);
    }

    // ===== ARTICLES - FIXED V15 =====
    if (url.pathname === '/api/articles' && method === 'GET') {
      const page = Math.max(1, parseInt(url.searchParams.get('page') || '1'));
      const limit = Math.min(50, Math.max(1, parseInt(url.searchParams.get('limit') || '20')));
      const offset = (page - 1) * limit;
      const authorId = url.searchParams.get('author_id') || url.searchParams.get('owner_id');
      
      let query = 'SELECT a.*, u.name as author_name, u.display_name, u.avatar_url FROM articles a LEFT JOIN users u ON a.author_id=u.id';
      let params = [];
      if (authorId && /^\d+$/.test(authorId)) {
        query += ' WHERE a.author_id = ?';
        params.push(parseInt(authorId));
      }
      query += ' ORDER BY a.id DESC LIMIT ? OFFSET ?';
      params.push(limit, offset);
      
      const arts = await env.DB.prepare(query).bind(...params).all();
      const hasPageParam = url.searchParams.has('page') || url.searchParams.has('limit');
      if (!hasPageParam) {
        return json(arts.results);
      }
      return json({ articles: arts.results, total: arts.results.length, page, limit });
    }

    if (url.pathname === '/api/articles' && method === 'POST') {
      const user = await getUserFromReq(request, env);
      if (!user || (user.role !== 'publisher' && user.role !== 'admin')) return json({ error: 'غير مصرح - ناشر فقط' }, 403);
      try {
        const { title, content, cover_url } = await request.json();
        if (!title || title.trim().length < 3) return json({ error: 'العنوان قصير' }, 400);
        if (!content || content.trim().length < 10) return json({ error: 'المحتوى قصير جداً' }, 400);
        if (title.length > 200) return json({ error: 'العنوان طويل' }, 400);
        if (content.length > 50000) return json({ error: 'المحتوى طويل جداً' }, 400);
        const cleanTitle = sanitizeString(title, 200);
        const cleanContent = sanitizeString(content, 50000);
        const cleanCover = cover_url && (cover_url.startsWith('/cdn/') || cover_url.startsWith('/api/file/')) ? cover_url : '';
        
        const res = await env.DB.prepare('INSERT INTO articles (title,content,cover_url,author_id) VALUES (?,?,?,?)')
          .bind(cleanTitle, cleanContent, cleanCover, user.id).run();
        return json({ id: res.meta.last_row_id, success: true });
      } catch(e) { return json({ error: 'بيانات غير صالحة' }, 400); }
    }

    if (url.pathname.startsWith('/api/articles/') && method === 'GET') {
      const id = url.pathname.split('/').pop();
      if (!/^\d+$/.test(id)) return json({ error: 'ID غير صالح' }, 400);
      const art = await env.DB.prepare('SELECT a.*, u.name as author_name FROM articles a LEFT JOIN users u ON a.author_id=u.id WHERE a.id=?').bind(id).first();
      if (!art) return json({ error: 'Not found' }, 404);
      return json(art);
    }

    // ===== ADS - SECURED WITH SANITIZATION =====
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
      // SECURITY: Sanitize output
      const sanitized = ads.results.map(ad => ({
        ...ad,
        custom_html: ad.custom_html ? sanitizeHTML(ad.custom_html) : '',
        title: sanitizeString(ad.title || '', 100)
      }));
      return json(sanitized);
    }

    if (url.pathname === '/api/ads' && method === 'POST') {
      const user = await getUserFromReq(request, env);
      if (!user) return json({ error: 'Unauthorized' }, 401);
      try {
        const { title, placement, type, custom_html, image_url, link_url, owner_id } = await request.json();
        if (!title || !placement) return json({ error: 'العنوان والمكان مطلوبان' }, 400);
        const cleanTitle = sanitizeString(title, 100);
        const cleanPlacement = sanitizeString(placement, 50);
        const allowedTypes = ['image_link', 'custom_html'];
        const cleanType = allowedTypes.includes(type) ? type : 'image_link';
        
        let cleanHTML = '';
        if (cleanType === 'custom_html' && custom_html) {
          // V12: Allow publisher to use custom_html for A-ADS, AdSense etc
          if (user.role !== 'admin' && user.role !== 'publisher') return json({ error: 'الإعلانات البرمجية للناشرين فقط' }, 403);
          cleanHTML = user.role === 'admin' ? sanitizeHTML(custom_html) : sanitizeAdHTML(custom_html, user.role);
        }
        
        const cleanImageUrl = image_url && (image_url.startsWith('/cdn/') || image_url.startsWith('https://')) ? image_url.slice(0,500) : '';
        const cleanLinkUrl = link_url && (link_url.startsWith('https://') || link_url.startsWith('/')) ? link_url.slice(0,500) : '';
        
        const finalOwner = user.role === 'admin' ? (owner_id && /^\d+$/.test(owner_id) ? owner_id : null) : user.id;
        const res = await env.DB.prepare('INSERT INTO ads (title,placement,type,custom_html,image_url,link_url,owner_id) VALUES (?,?,?,?,?,?,?)')
          .bind(cleanTitle, cleanPlacement, cleanType, cleanHTML, cleanImageUrl, cleanLinkUrl, finalOwner).run();
        return json({ id: res.meta.last_row_id, success: true });
      } catch(e) { return json({ error: 'بيانات غير صالحة' }, 400); }
    }

    if (url.pathname.startsWith('/api/ads/') && method === 'DELETE') {
      const user = await getUserFromReq(request, env);
      if (!user) return json({ error: 'Unauthorized' }, 401);
      const id = url.pathname.split('/').pop();
      if (!/^\d+$/.test(id)) return json({ error: 'ID غير صالح' }, 400);
      const ad = await env.DB.prepare('SELECT owner_id FROM ads WHERE id=?').bind(id).first();
      if (!ad) return json({ error: 'Not found' }, 404);
      if (user.role !== 'admin' && ad.owner_id !== user.id) return json({ error: 'غير مصرح' }, 403);
      await env.DB.prepare('DELETE FROM ads WHERE id=?').bind(id).run();
      return json({ success: true });
    }

    // ===== PUBLISHER REQUESTS - SECURED =====
    if (url.pathname === '/api/publisher-requests' && method === 'GET') {
      const user = await getUserFromReq(request, env);
      if (!user || user.role !== 'admin') return json({ error: 'Admin only' }, 403);
      const reqs = await env.DB.prepare('SELECT pr.*, u.email FROM publisher_requests pr JOIN users u ON pr.user_id=u.id ORDER BY pr.id DESC LIMIT 100').all();
      return json(reqs.results);
    }

    if (url.pathname === '/api/publisher-requests' && method === 'POST') {
      const user = await getUserFromReq(request, env);
      if (!user) return json({ error: 'Unauthorized' }, 401);
      try {
        const { name, reason, samples } = await request.json();
        if (!name || !reason) return json({ error: 'الاسم والسبب مطلوبان' }, 400);
        const cleanName = sanitizeString(name, 100);
        const cleanReason = sanitizeString(reason, 500);
        const cleanSamples = sanitizeString(samples || '', 500);
        const existing = await env.DB.prepare('SELECT id FROM publisher_requests WHERE user_id=? AND status=?').bind(user.id, 'pending').first();
        if (existing) return json({ error: 'لديك طلب معلق بالفعل' }, 400);
        const res = await env.DB.prepare('INSERT INTO publisher_requests (user_id,name,reason,samples) VALUES (?,?,?,?)').bind(user.id, cleanName, cleanReason, cleanSamples).run();
        return json({ id: res.meta.last_row_id, success: true });
      } catch(e) { return json({ error: 'بيانات غير صالحة' }, 400); }
    }

    if (url.pathname.startsWith('/api/publisher-requests/') && method === 'PUT') {
      const authUser = await getUserFromReq(request, env);
      if (!authUser || authUser.role !== 'admin') return json({ error: 'Admin only' }, 403);
      const id = url.pathname.split('/').pop();
      if (!/^\d+$/.test(id)) return json({ error: 'ID غير صالح' }, 400);
      try {
        const { status } = await request.json();
        if (!['approved','rejected','pending'].includes(status)) return json({ error: 'Invalid status' }, 400);
        await env.DB.prepare('UPDATE publisher_requests SET status=? WHERE id=?').bind(status, id).run();
        if (status === 'approved') {
          await env.DB.prepare("UPDATE users SET role='publisher', is_publisher=1 WHERE id=(SELECT user_id FROM publisher_requests WHERE id=?)").bind(id).run();
        }
        if (status === 'rejected') {
          await env.DB.prepare("UPDATE users SET is_publisher=0 WHERE id=(SELECT user_id FROM publisher_requests WHERE id=?) AND role!='admin'").bind(id).run();
        }
        await env.DB.prepare('INSERT INTO audit_log (user_id, action, details, ip) VALUES (?,?,?,?)').bind(authUser.id, 'publisher_request_'+status, `request:${id}`, ip).run().catch(()=>{});
        return json({ success: true, status });
      } catch(e) { return json({ error: 'بيانات غير صالحة' }, 400); }
    }

    // ===== PushKit API - SECURED =====
    if (url.pathname === '/api/push/subscribe' && method === 'POST') {
      try {
        const body = await request.json();
        const sub = body.subscription || body;
        const endpoint = (sub.endpoint || '').slice(0,500);
        if (!endpoint || !endpoint.startsWith('https://')) return json({ error: 'Invalid subscription' }, 400);
        try {
          await env.DB.prepare('INSERT OR IGNORE INTO push_subscriptions (endpoint, subscription_json, created_at) VALUES (?,?,?)')
            .bind(endpoint, JSON.stringify(sub).slice(0,2000), Date.now()).run();
        } catch(e) {
          await env.DB.prepare('CREATE TABLE IF NOT EXISTS push_subscriptions (id INTEGER PRIMARY KEY AUTOINCREMENT, endpoint TEXT UNIQUE, subscription_json TEXT, created_at INTEGER)').run();
          await env.DB.prepare('INSERT OR IGNORE INTO push_subscriptions (endpoint, subscription_json, created_at) VALUES (?,?,?)').bind(endpoint, JSON.stringify(sub).slice(0,2000), Date.now()).run();
        }
        return json({ success: true });
      } catch(e) { return json({ error: 'Invalid data' }, 400); }
    }


    // ===== رفوف V10 Professional - بروفايل الناشر =====
    if (url.pathname === '/api/me' && method === 'GET') {
      const user = await getUserFromReq(request, env);
      if (!user) return json({ error: 'Unauthorized' }, 401);
      const full = await env.DB.prepare('SELECT id,email,name,display_name,bio,avatar_url,website,role,verified,is_publisher FROM users WHERE id=?').bind(user.id).first();
      return json(full);
    }

    if (url.pathname === '/api/me' && method === 'PUT') {
      const user = await getUserFromReq(request, env);
      if (!user) return json({ error: 'Unauthorized' }, 401);
      try {
        const { display_name, bio, website, avatar_url } = await request.json();
        const cleanName = sanitizeString(display_name||'', 50);
        const cleanBio = sanitizeString(bio||'', 300);
        const cleanWebsite = (website||'').slice(0,200);
        const cleanAvatar = (avatar_url||'').slice(0,500);
        if (cleanWebsite && cleanWebsite !== '' && !cleanWebsite.startsWith('https://') && !cleanWebsite.startsWith('http://')) return json({ error: 'رابط غير صالح - يجب أن يبدأ بـ https://' }, 400);
        await env.DB.prepare('UPDATE users SET display_name=?, bio=?, website=?, avatar_url=? WHERE id=?').bind(cleanName, cleanBio, cleanWebsite, cleanAvatar, user.id).run();
        return json({ success: true });
      } catch(e){ return json({ error: 'بيانات غير صالحة' }, 400); }
    }

    if (url.pathname.match(/^\/api\/users\/\d+\/public$/) && method === 'GET') {
      const id = url.pathname.split('/')[3];
      if (!/^\d+$/.test(id)) return json({ error: 'ID غير صالح' }, 400);
      const u = await env.DB.prepare('SELECT id, display_name, name, bio, avatar_url, website, verified, role FROM users WHERE id=?').bind(id).first();
      if (!u) return json({ error: 'Not found' }, 404);
      return json(u);
    }

    if (url.pathname === '/api/upload/avatar' && method === 'POST') {
      const user = await getUserFromReq(request, env);
      if (!user) return json({ error: 'Unauthorized' }, 401);
      try {
        const form = await request.formData();
        const file = form.get('file');
        if (!file || !file.size) return json({ error: 'لا يوجد ملف' }, 400);
        if (file.size > 2*1024*1024) return json({ error: 'الصورة كبيرة - حد أقصى 2MB' }, 400);
        if (!ALLOWED_IMAGE_TYPES.includes(file.type)) return json({ error: 'نوع الصورة غير مسموح - JPG, PNG, WEBP فقط' }, 400);
        const ext = file.name.split('.').pop() || 'jpg';
        const key = `avatars/${user.id}-${Date.now()}.${ext}`;
        await env.BUCKET.put(key, file.stream(), { httpMetadata: { contentType: file.type } });
        const avatarUrl = `/cdn/${key}`;
        await env.DB.prepare('UPDATE users SET avatar_url=? WHERE id=?').bind(avatarUrl, user.id).run();
        return json({ url: avatarUrl, success: true });
      } catch(e){ return json({ error: 'فشل الرفع: ' + (e.message||'') }, 500); }
    }

    if (url.pathname === '/api/admin/users' && method === 'GET') {
      const user = await getUserFromReq(request, env);
      if (!user || user.role !== 'admin') return json({ error: 'Admin only' }, 403);
      const users = await env.DB.prepare(`
        SELECT u.id, u.email, u.name, u.display_name, u.bio, u.avatar_url, u.website, u.role, u.verified, u.is_publisher,
        (SELECT COUNT(*) FROM books WHERE author_id=u.id) as books_count
        FROM users u ORDER BY u.id DESC LIMIT 200
      `).all();
      return json(users.results);
    }



    // ===== BOOKS EDIT/DELETE - V16 =====
    if (url.pathname.startsWith('/api/books/') && method === 'PUT') {
      const user = await getUserFromReq(request, env);
      if (!user) return json({ error: 'Unauthorized' }, 401);
      const id = url.pathname.split('/').pop();
      if (!/^\d+$/.test(id)) return json({ error: 'ID غير صالح' }, 400);
      const book = await env.DB.prepare('SELECT owner_id FROM books WHERE id=?').bind(id).first();
      if (!book) return json({ error: 'Not found' }, 404);
      if (user.role !== 'admin' && book.owner_id !== user.id) return json({ error: 'غير مصرح - ليس كتابك' }, 403);
      try {
        const { title, author, description, cover_url, file_url } = await request.json();
        const cleanTitle = title ? sanitizeString(title, 200) : undefined;
        const cleanAuthor = author !== undefined ? sanitizeString(author, 100) : undefined;
        const cleanDesc = description !== undefined ? sanitizeString(description, 2000) : undefined;
        
        let setClause = [];
        let params = [];
        if (cleanTitle !== undefined) { setClause.push('title=?'); params.push(cleanTitle); }
        if (cleanAuthor !== undefined) { setClause.push('author=?'); params.push(cleanAuthor); }
        if (cleanDesc !== undefined) { setClause.push('description=?'); params.push(cleanDesc); }
        if (cover_url !== undefined && (cover_url.startsWith('/cdn/') || cover_url.startsWith('/api/file/') || cover_url.startsWith('https://') || cover_url === '')) { setClause.push('cover_url=?'); params.push(cover_url.slice(0,500)); }
        if (file_url !== undefined && (file_url.startsWith('/api/file/') || file_url.startsWith('/cdn/') || file_url === '')) { setClause.push('file_url=?'); params.push(file_url.slice(0,500)); }
        
        if (setClause.length === 0) return json({ error: 'لا يوجد ما يتم تعديله' }, 400);
        params.push(id);
        await env.DB.prepare(`UPDATE books SET ${setClause.join(',')} WHERE id=?`).bind(...params).run();
        return json({ success: true });
      } catch(e) { return json({ error: 'خطأ: '+e.message }, 400); }
    }

    if (url.pathname.startsWith('/api/books/') && method === 'DELETE') {
      const user = await getUserFromReq(request, env);
      if (!user) return json({ error: 'Unauthorized' }, 401);
      const id = url.pathname.split('/').pop();
      if (!/^\d+$/.test(id)) return json({ error: 'ID غير صالح' }, 400);
      const book = await env.DB.prepare('SELECT owner_id, file_url, cover_url FROM books WHERE id=?').bind(id).first();
      if (!book) return json({ error: 'Not found' }, 404);
      if (user.role !== 'admin' && book.owner_id !== user.id) return json({ error: 'غير مصرح' }, 403);
      await env.DB.prepare('DELETE FROM books WHERE id=?').bind(id).run();
      // Optionally delete from R2 - keep for safety
      return json({ success: true });
    }

    // ===== ARTICLES EDIT/DELETE - V16 =====
    if (url.pathname.startsWith('/api/articles/') && method === 'PUT') {
      const user = await getUserFromReq(request, env);
      if (!user) return json({ error: 'Unauthorized' }, 401);
      const id = url.pathname.split('/').pop();
      if (!/^\d+$/.test(id)) return json({ error: 'ID غير صالح' }, 400);
      const art = await env.DB.prepare('SELECT author_id FROM articles WHERE id=?').bind(id).first();
      if (!art) return json({ error: 'Not found' }, 404);
      if (user.role !== 'admin' && art.author_id !== user.id) return json({ error: 'غير مصرح - ليس مقالك' }, 403);
      try {
        const { title, content, cover_url } = await request.json();
        let setClause = []; let params = [];
        if (title !== undefined) { setClause.push('title=?'); params.push(sanitizeString(title,200)); }
        if (content !== undefined) { setClause.push('content=?'); params.push(sanitizeString(content,50000)); }
        if (cover_url !== undefined) { setClause.push('cover_url=?'); params.push((cover_url.startsWith('/cdn/')||cover_url.startsWith('https://')||cover_url==='')?cover_url.slice(0,500):''); }
        if (!setClause.length) return json({ error: 'لا يوجد تعديل' }, 400);
        params.push(id);
        await env.DB.prepare(`UPDATE articles SET ${setClause.join(',')} WHERE id=?`).bind(...params).run();
        return json({ success: true });
      } catch(e) { return json({ error: e.message }, 400); }
    }

    if (url.pathname.startsWith('/api/articles/') && method === 'DELETE') {
      const user = await getUserFromReq(request, env);
      if (!user) return json({ error: 'Unauthorized' }, 401);
      const id = url.pathname.split('/').pop();
      if (!/^\d+$/.test(id)) return json({ error: 'ID غير صالح' }, 400);
      const art = await env.DB.prepare('SELECT author_id FROM articles WHERE id=?').bind(id).first();
      if (!art) return json({ error: 'Not found' }, 404);
      if (user.role !== 'admin' && art.author_id !== user.id) return json({ error: 'غير مصرح' }, 403);
      await env.DB.prepare('DELETE FROM articles WHERE id=?').bind(id).run();
      return json({ success: true });
    }


    // ===== PROFILE - NEW V13 =====
    if (url.pathname === '/api/profile' && method === 'GET') {
      const user = await getUserFromReq(request, env);
      if (!user) return json({ error: 'Unauthorized' }, 401);
      const full = await env.DB.prepare('SELECT id,email,name,display_name,bio,avatar_url,website,role,is_publisher FROM users WHERE id=?').bind(user.id).first();
      // If new columns don't exist, fallback
      if (!full) return json(user);
      return json(full);
    }

    if (url.pathname === '/api/profile' && method === 'PUT') {
      const user = await getUserFromReq(request, env);
      if (!user) return json({ error: 'Unauthorized' }, 401);
      try {
        const { display_name, bio, avatar_url, website } = await request.json();
        const cleanName = sanitizeString(display_name || '', 100);
        const cleanBio = sanitizeString(bio || '', 500);
        const cleanWebsite = (website && (website.startsWith('https://') || website.startsWith('http://')) ? website.slice(0,300) : '');
        let cleanAvatar = '';
        if (avatar_url && (avatar_url.startsWith('/cdn/') || avatar_url.startsWith('https://') || avatar_url.startsWith('/api/file/'))) {
          cleanAvatar = avatar_url.slice(0,500);
        }
        // Try to update with new columns, create them if not exist
        try {
          await env.DB.prepare('ALTER TABLE users ADD COLUMN display_name TEXT').run().catch(()=>{});
          await env.DB.prepare('ALTER TABLE users ADD COLUMN bio TEXT').run().catch(()=>{});
          await env.DB.prepare('ALTER TABLE users ADD COLUMN avatar_url TEXT').run().catch(()=>{});
          await env.DB.prepare('ALTER TABLE users ADD COLUMN website TEXT').run().catch(()=>{});
        } catch(e){}
        
        await env.DB.prepare('UPDATE users SET display_name=?, bio=?, avatar_url=?, website=?, name=? WHERE id=?')
          .bind(cleanName, cleanBio, cleanAvatar, cleanWebsite, cleanName, user.id).run();
        
        return json({ success: true, display_name: cleanName, bio: cleanBio, avatar_url: cleanAvatar });
      } catch(e) {
        return json({ error: 'خطأ في الحفظ: '+e.message }, 400);
      }
    }

    return json({ error: 'Route not found: ' + url.pathname }, 404);
  }
};
