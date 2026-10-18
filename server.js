'use strict';
/**
 * NumVirtual — servidor sem dependências externas (somente módulos nativos do Node >= 18).
 * Autenticação JWT (HS256), senhas com scrypt, tempo real via Server-Sent Events,
 * persistência em arquivo JSON, rate limiting e cabeçalhos de segurança.
 */
const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');

/* ---- mini loader de .env ---- */
try {
  const envFile = path.join(__dirname, '.env');
  if (fs.existsSync(envFile)) {
    for (const line of fs.readFileSync(envFile, 'utf8').split(/\r?\n/)) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/i);
      if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
    }
  }
} catch (e) { console.warn('[env] falha ao ler .env:', e.message); }

const { COUNTRIES, PLATFORMS, getProvider } = require('./providers');

/* ------------------------------ Config ------------------------------ */
const PORT = Number(process.env.PORT) || 3000;
const TTL_MIN = Number(process.env.SESSION_TTL_MIN) || 20;
const MAX_ACTIVE = Number(process.env.MAX_ACTIVE_NUMBERS) || 3;
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  JWT_SECRET = crypto.randomBytes(48).toString('hex');
  console.warn('[security] JWT_SECRET ausente/curto: usando segredo temporário (logins caem ao reiniciar). Defina JWT_SECRET no .env.');
}
const provider = getProvider();
const PUBLIC_DIR = path.join(__dirname, 'public');

/* ------------------------------ Banco (JSON) ------------------------------ */
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
fs.mkdirSync(DATA_DIR, { recursive: true });
let db = { users: [], sessions: [], nextUserId: 1, nextSessionId: 1 };
if (fs.existsSync(DB_FILE)) {
  try {
    db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch (e) {
    const bak = DB_FILE + '.corrompido-' + Date.now();
    fs.copyFileSync(DB_FILE, bak);
    console.error('[db] arquivo ilegível, backup em', bak, '— iniciando banco vazio.');
  }
}
function writeNow() {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DB_FILE);
}
let saveTimer = null;
function save() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => { saveTimer = null; try { writeNow(); } catch (e) { console.error('[db] falha ao salvar:', e.message); } }, 150);
}
function flush() { if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; } try { writeNow(); } catch { /* ignore */ } }

/* ---------------------------- Utilidades ---------------------------- */
const stats = { rateLimited: 0, failedLogins: 0, invalidInputs: 0, startedAt: Date.now() };

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

const publicSession = (s) => ({
  id: s.id, platform: s.platform, country: s.country, phone: s.phone,
  status: s.status, code: s.code, createdAt: s.createdAt, expiresAt: s.expiresAt,
});
const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email });
const totalsFor = (userId) => {
  const mine = db.sessions.filter((s) => s.userId === userId);
  return { generated: mine.length, received: mine.filter((s) => s.status === 'received').length };
};

const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;
function validatePassword(pw) {
  if (typeof pw !== 'string' || pw.length < 8 || pw.length > 72) return 'A senha deve ter entre 8 e 72 caracteres.';
  if (!/[a-z]/.test(pw) || !/[A-Z]/.test(pw) || !/\d/.test(pw)) return 'A senha precisa de letra minúscula, maiúscula e número.';
  return null;
}

/* --- senhas (scrypt) --- */
const hashPw = (pw) => new Promise((resolve, reject) => {
  const salt = crypto.randomBytes(16);
  crypto.scrypt(pw, salt, 64, (err, key) => (err ? reject(err) : resolve(salt.toString('hex') + ':' + key.toString('hex'))));
});
const verifyPw = (pw, stored) => new Promise((resolve) => {
  const [saltHex, keyHex] = String(stored).split(':');
  if (!saltHex || !keyHex) return resolve(false);
  crypto.scrypt(pw, Buffer.from(saltHex, 'hex'), 64, (err, key) => {
    if (err) return resolve(false);
    const expected = Buffer.from(keyHex, 'hex');
    resolve(expected.length === key.length && crypto.timingSafeEqual(expected, key));
  });
});
const DUMMY_HASH = hashPw('senha-falsa-para-igualar-tempo');

/* --- JWT HS256 --- */
const b64u = (v) => Buffer.from(v).toString('base64url');
const hmac = (data) => crypto.createHmac('sha256', JWT_SECRET).update(data).digest();
function signJwt(payload, ttlSec) {
  const h = b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const p = b64u(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + ttlSec }));
  return `${h}.${p}.${hmac(h + '.' + p).toString('base64url')}`;
}
function verifyJwt(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('formato');
  const [h, p, s] = parts;
  const header = JSON.parse(Buffer.from(h, 'base64url').toString());
  if (header.alg !== 'HS256') throw new Error('alg');
  const given = Buffer.from(s, 'base64url');
  const expected = hmac(h + '.' + p);
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) throw new Error('assinatura');
  const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
  if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) throw new Error('expirado');
  return payload;
}

/* --- rate limit --- */
const buckets = new Map();
function limited(key, max, windowMs) {
  const now = Date.now();
  let b = buckets.get(key);
  if (!b || b.reset <= now) { b = { count: 0, reset: now + windowMs }; buckets.set(key, b); }
  b.count++;
  return b.count > max;
}
setInterval(() => { const now = Date.now(); for (const [k, b] of buckets) if (b.reset <= now) buckets.delete(k); }, 60000).unref();
function clientIp(req) {
  if (TRUST_PROXY) {
    const xf = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    if (xf) return xf;
  }
  return req.socket.remoteAddress || 'unknown';
}
function rateGuard(ip, name, max, windowMs, message) {
  if (limited(name + ':' + ip, max, windowMs)) { stats.rateLimited++; throw new HttpError(429, message); }
}

/* --- HTTP helpers --- */
function sendJson(res, status, body) {
  const data = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(data), 'Cache-Control': 'no-store' });
  res.end(data);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; let tooBig = false; const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > 10240) { tooBig = true; return; }
      if (!tooBig) chunks.push(c);
    });
    req.on('end', () => {
      if (tooBig) return reject(new HttpError(413, 'Corpo da requisição muito grande.'));
      if (!chunks.length) return resolve({});
      try {
        const v = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        resolve(v && typeof v === 'object' && !Array.isArray(v) ? v : {});
      } catch { reject(new HttpError(400, 'JSON inválido.')); }
    });
    req.on('error', reject);
  });
}
function authUser(req) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) throw new HttpError(401, 'Não autenticado.');
  try {
    const payload = verifyJwt(token);
    if (payload.typ === 'stream') throw new Error('tipo');
    const user = db.users.find((u) => u.id === payload.sub);
    if (!user || user.status !== 'active') throw new Error('inativo');
    return user;
  } catch {
    throw new HttpError(401, 'Sessão inválida ou expirada.');
  }
}

/* --- tempo real (SSE) --- */
const streams = new Map(); // userId -> Set<res>
const tickets = new Map(); // ticket -> { userId, exp }
function pushTo(userId, event, data) {
  const set = streams.get(userId);
  if (!set) return;
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const r of set) { try { r.write(msg); } catch { /* conexão caída */ } }
}
setInterval(() => {
  for (const set of streams.values()) for (const r of set) { try { r.write(': ping\n\n'); } catch { /* ignore */ } }
  const now = Date.now();
  for (const [k, t] of tickets) if (t.exp <= now) tickets.delete(k);
}, 20000).unref();
const liveConnections = () => { let n = 0; for (const s of streams.values()) n += s.size; return n; };

/* ------------------------------ Rotas API ------------------------------ */
async function settle(session, newStatus) {
  if (session.status !== 'waiting') return false;
  session.status = newStatus;
  save();
  try { await provider.cancel(session); } catch (e) { console.warn('[provider.cancel]', e.message); }
  return true;
}

async function pollOne(s) {
  try {
    if (s.status !== 'waiting') return;
    if (Date.now() >= s.expiresAt) {
      if (await settle(s, 'expired')) pushTo(s.userId, 'session', publicSession(s));
      return;
    }
    const { code } = await provider.check(s);
    if (code && s.status === 'waiting') {
      s.status = 'received'; s.code = code; save();
      pushTo(s.userId, 'session', publicSession(s));
    }
  } catch (e) {
    console.warn('[poll]', s.id, e.message);
  }
}

function ownedSession(user, idStr) {
  const id = Number(idStr);
  const s = db.sessions.find((x) => x.id === id && x.userId === user.id);
  if (!s) throw new HttpError(404, 'Número não encontrado.');
  return s;
}

async function handleApi(req, res, url) {
  const ip = clientIp(req);
  rateGuard(ip, 'api', 300, 60 * 1000, 'Muitas requisições. Aguarde um instante.');
  const route = req.method + ' ' + url.pathname;

  if (route === 'POST /api/auth/register') {
    rateGuard(ip, 'register', 5, 60 * 60 * 1000, 'Limite de cadastros atingido. Tente mais tarde.');
    const { name, email, password } = await readBody(req);
    const cleanName = typeof name === 'string' ? name.trim() : '';
    const cleanEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';
    if (cleanName.length < 2 || cleanName.length > 80) { stats.invalidInputs++; throw new HttpError(400, 'Informe um nome válido (2 a 80 caracteres).'); }
    if (!EMAIL_RE.test(cleanEmail)) { stats.invalidInputs++; throw new HttpError(400, 'E-mail inválido.'); }
    const pwErr = validatePassword(password);
    if (pwErr) { stats.invalidInputs++; throw new HttpError(400, pwErr); }
    if (db.users.some((u) => u.email === cleanEmail)) throw new HttpError(409, 'Este e-mail já está cadastrado.');
    const user = { id: db.nextUserId++, name: cleanName, email: cleanEmail, passwordHash: await hashPw(password), status: 'active', createdAt: Date.now() };
    db.users.push(user); save();
    return sendJson(res, 201, { token: signJwt({ sub: user.id }, 12 * 3600), user: publicUser(user) });
  }

  if (route === 'POST /api/auth/login') {
    rateGuard(ip, 'login', 10, 15 * 60 * 1000, 'Muitas tentativas de login. Tente novamente em 15 minutos.');
    const { email, password } = await readBody(req);
    if (typeof email !== 'string' || typeof password !== 'string' || password.length > 72) { stats.invalidInputs++; throw new HttpError(400, 'Credenciais inválidas.'); }
    const user = db.users.find((u) => u.email === email.trim().toLowerCase());
    const ok = await verifyPw(password, user ? user.passwordHash : await DUMMY_HASH);
    if (!user || !ok || user.status !== 'active') { stats.failedLogins++; throw new HttpError(401, 'E-mail ou senha incorretos.'); }
    return sendJson(res, 200, { token: signJwt({ sub: user.id }, 12 * 3600), user: publicUser(user) });
  }

  // A partir daqui, tudo exige login.
  if (route === 'GET /api/stream') {
    const t = tickets.get(url.searchParams.get('ticket') || '');
    if (!t || t.exp <= Date.now()) throw new HttpError(401, 'Ticket inválido ou expirado.');
    tickets.delete(url.searchParams.get('ticket'));
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
    res.write('retry: 3000\n\n');
    if (!streams.has(t.userId)) streams.set(t.userId, new Set());
    streams.get(t.userId).add(res);
    req.on('close', () => { const set = streams.get(t.userId); if (set) { set.delete(res); if (!set.size) streams.delete(t.userId); } });
    return undefined;
  }

  const user = authUser(req);

  if (route === 'POST /api/stream-ticket') {
    const ticket = crypto.randomBytes(24).toString('hex');
    tickets.set(ticket, { userId: user.id, exp: Date.now() + 30000 });
    return sendJson(res, 200, { ticket });
  }
  if (route === 'GET /api/me') {
    return sendJson(res, 200, { user: publicUser(user), unlimited: true, provider: provider.name, ttlMin: TTL_MIN, totals: totalsFor(user.id) });
  }
  if (route === 'GET /api/countries') {
    return sendJson(res, 200, { platforms: PLATFORMS, countries: COUNTRIES.map(({ id, name, dial }) => ({ id, name, dial })) });
  }
  if (route === 'GET /api/numbers') {
    const mine = db.sessions.filter((s) => s.userId === user.id).sort((a, b) => b.id - a.id).slice(0, 100);
    return sendJson(res, 200, { sessions: mine.map(publicSession), totals: totalsFor(user.id) });
  }
  if (route === 'POST /api/numbers') {
    rateGuard(ip, 'generate', 30, 10 * 60 * 1000, 'Limite de geração de números atingido. Aguarde alguns minutos.');
    const { platform, country } = await readBody(req);
    if (!PLATFORMS.includes(platform)) { stats.invalidInputs++; throw new HttpError(400, 'Plataforma inválida.'); }
    const c = COUNTRIES.find((x) => x.id === country);
    if (!c) { stats.invalidInputs++; throw new HttpError(400, 'País inválido.'); }
    const active = db.sessions.filter((s) => s.userId === user.id && s.status === 'waiting').length;
    if (active >= MAX_ACTIVE) throw new HttpError(429, `Você já tem ${MAX_ACTIVE} números aguardando SMS. Cancele ou aguarde um deles.`);
    let bought;
    try {
      bought = await provider.buy({ country: c, platform });
    } catch (e) {
      console.error('[provider.buy]', e.message);
      throw new HttpError(502, 'Não foi possível alocar um número agora. Tente novamente em instantes.');
    }
    const now = Date.now();
    const session = {
      id: db.nextSessionId++, userId: user.id, platform, country: c.id, phone: bought.phone,
      provider: provider.name, providerId: bought.providerId, status: 'waiting', code: null,
      simulateAt: bought.simulateAt || null, createdAt: now, expiresAt: now + TTL_MIN * 60 * 1000,
    };
    db.sessions.push(session); save();
    return sendJson(res, 201, { session: publicSession(session), totals: totalsFor(user.id) });
  }

  const m = url.pathname.match(/^\/api\/numbers\/(\d+)\/(refresh|cancel)$/);
  if (m && req.method === 'POST') {
    const s = ownedSession(user, m[1]);
    if (m[2] === 'refresh') {
      await pollOne(s);
      return sendJson(res, 200, { session: publicSession(s) });
    }
    if (s.status !== 'waiting') throw new HttpError(409, 'Este número não está mais aguardando SMS.');
    await settle(s, 'cancelled');
    pushTo(user.id, 'session', publicSession(s));
    return sendJson(res, 200, { session: publicSession(s), totals: totalsFor(user.id) });
  }
  if (route === 'GET /api/security/stats') {
    return sendJson(res, 200, {
      uptimeSec: Math.floor((Date.now() - stats.startedAt) / 1000),
      rateLimited: stats.rateLimited, failedLogins: stats.failedLogins,
      invalidInputs: stats.invalidInputs, liveConnections: liveConnections(),
    });
  }
  throw new HttpError(404, 'Rota não encontrada.');
}

/* ------------------------------ Estáticos ------------------------------ */
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon',
};
function serveStatic(req, res, url) {
  if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'Método não permitido.');
  let p;
  try { p = decodeURIComponent(url.pathname); } catch { throw new HttpError(400, 'URL inválida.'); }
  if (p.includes('\0')) throw new HttpError(400, 'URL inválida.');
  if (p === '/') p = '/index.html';
  const full = path.normalize(path.join(PUBLIC_DIR, p));
  if (full !== PUBLIC_DIR && !full.startsWith(PUBLIC_DIR + path.sep)) throw new HttpError(403, 'Acesso negado.');
  fs.readFile(full, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Não encontrado.'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(full)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    return res.end(req.method === 'HEAD' ? undefined : data);
  });
}

/* ------------------------------ Servidor ------------------------------ */
const CSP = [
  "default-src 'self'",
  "script-src 'self' https://cdn.tailwindcss.com 'unsafe-eval'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join('; ');

const server = http.createServer(async (req, res) => {
  res.setHeader('Content-Security-Policy', CSP);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  try {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/api/')) await handleApi(req, res, url);
    else serveStatic(req, res, url);
  } catch (err) {
    const status = err.status || 500;
    if (status >= 500) console.error('[error]', err);
    if (!res.headersSent) sendJson(res, status, { error: status >= 500 ? 'Erro interno do servidor.' : err.message });
    else res.end();
  }
});

/* ------------------------ Poller de SMS/expiração ------------------- */
let polling = false;
setInterval(async () => {
  if (polling) return;
  polling = true;
  try {
    for (const s of db.sessions.filter((x) => x.status === 'waiting')) await pollOne(s);
  } finally { polling = false; }
}, 3000).unref();

server.listen(PORT, () => {
  console.log(`\n  Plataforma no ar: http://localhost:${PORT}`);
  console.log(`  Provedor: ${provider.name}${provider.name === 'simulated' ? ' (números/códigos FICTÍCIOS — apenas demonstração)' : ''}\n`);
});
server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') console.error(`Porta ${PORT} em uso. Use outra: PORT=3001 node server.js`);
  else console.error(e);
  process.exit(1);
});
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { flush(); process.exit(0); });
