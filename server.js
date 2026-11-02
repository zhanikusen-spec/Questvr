'use strict';
/* VR Box · Quest — сервер для Render.
   HTTP:  раздаёт public/index.html + API (/api/register, /api/login, /api/me, /api/save)
   WS:    комнаты 1..4, позиции игроков, голос (только тем, кто ближе VOICE_R) */
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data', 'users.json');
const MAX_ROOM = 4;          // server #1..#4
const MAX_PER_ROOM = 50;
const VOICE_R = 12;          // как VOICE.R в клиенте
const TICK_MS = 100;
const NICK_RE = /^[A-Za-z0-9_\-А-Яа-яЁё]{3,16}$/;

/* ---------- хранилище аккаунтов (JSON-файл) ---------- */
let users = {};   // key(lowercase nick) -> {nick, salt, hash, token, data}
try { users = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch (e) { users = {}; }
const byToken = new Map();
for (const k in users) if (users[k].token) byToken.set(users[k].token, k);

let saveT = null;
function persist() {
  if (saveT) return;
  saveT = setTimeout(() => {
    saveT = null;
    try {
      fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
      const tmp = DATA_FILE + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(users));
      fs.renameSync(tmp, DATA_FILE);
    } catch (e) { console.error('save error', e.message); }
  }, 1000);
}
function hashPass(pass, salt) { return crypto.scryptSync(pass, salt, 32).toString('hex'); }
function newToken() { return crypto.randomBytes(24).toString('hex'); }
function cleanData(d) {
  if (!d || typeof d !== 'object' || Array.isArray(d)) return {};
  if (JSON.stringify(d).length > 200000) return null;
  return d;
}
function issueToken(k) {
  const u = users[k];
  if (u.token) byToken.delete(u.token);
  u.token = newToken(); byToken.set(u.token, k);
}

/* ---------- HTTP (чистый Node, без express) ---------- */
const zlib = require('zlib');
const PUBLIC = path.join(__dirname, 'public');
const ROOT = __dirname;
// Ищем index.html сначала в public/, потом в корне (если папку public не создали)
function resolveStatic(p) {
  const candidates = [
    path.normalize(path.join(PUBLIC, p)),
    path.normalize(path.join(ROOT, p === '/index.html' || p === 'index.html' ? 'index.html' : p))
  ];
  return candidates;
}
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
  '.glb': 'model/gltf-binary', '.mp3': 'audio/mpeg', '.wav': 'audio/wav', '.woff2': 'font/woff2' };
const gzCache = new Map();   // путь -> {mtime, buf}

const hits = new Map();      // лимит попыток на IP
setInterval(() => hits.clear(), 60000).unref();
function limited(ip, max) { const n = (hits.get(ip) || 0) + 1; hits.set(ip, n); return n > max; }

function json(res, code, obj) {
  const b = Buffer.from(JSON.stringify(obj));
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': b.length });
  res.end(b);
}
const fail = (res, code, error) => json(res, code, { error });

function readBody(req, res, cb) {
  let size = 0; const chunks = [];
  req.on('data', c => {
    size += c.length;
    if (size > 300 * 1024) { fail(res, 413, 'Слишком большие данные'); req.destroy(); return; }
    chunks.push(c);
  });
  req.on('end', () => {
    if (res.writableEnded) return;
    let body = {};
    try { body = JSON.parse(Buffer.concat(chunks).toString() || '{}'); } catch (e) { return fail(res, 400, 'Плохой запрос'); }
    if (!body || typeof body !== 'object') body = {};
    cb(body);
  });
}

function authBody(body, res) {
  const k = byToken.get(body.token);
  if (!k || !users[k]) { fail(res, 401, 'Сессия устарела, войди заново'); return null; }
  return users[k];
}

const API = {
  // Занять ник (без пароля). Если уже занят другим — 409.
  '/api/register': (body, res, ip) => {
    if (limited(ip, 30)) return fail(res, 429, 'Слишком много попыток, подожди минуту');
    const { nick, data, token } = body;
    if (typeof nick !== 'string' || !NICK_RE.test(nick)) return fail(res, 400, 'Ник: 3–16 символов — буквы, цифры, _ и -');
    const k = nick.toLowerCase();
    // Уже есть такой ник
    if (users[k]) {
      // Если прислали свой старый token — это тот же игрок, пускаем
      if (token && users[k].token && token === users[k].token) {
        json(res, 200, { nick: users[k].nick, token: users[k].token, data: users[k].data });
        return;
      }
      return fail(res, 409, 'Это имя уже занято');
    }
    const d = cleanData(data); if (d === null) return fail(res, 413, 'Слишком большие данные');
    users[k] = { nick, salt: '', hash: '', token: '', data: d || {} };
    issueToken(k); persist();
    json(res, 200, { nick, token: users[k].token, data: users[k].data });
  },
  // Старый login больше не нужен, но оставляем заглушку
  '/api/login': (body, res) => {
    fail(res, 400, 'Пароль отключён. Просто введи ник.');
  },
  '/api/me': (body, res) => {
    const u = authBody(body, res); if (!u) return;
    json(res, 200, { nick: u.nick, data: u.data });
  },
  '/api/save': (body, res) => {
    const u = authBody(body, res); if (!u) return;
    const d = cleanData(body.data); if (d === null) return fail(res, 413, 'Слишком большие данные');
    u.data = d; persist();
    json(res, 200, { ok: true });
  }
};

function serveStatic(req, res) {
  let p = decodeURIComponent((req.url || '/').split('?')[0]);
  if (p === '/' || p === '') p = '/index.html';
  if (p.endsWith('/')) p += 'index.html';

  // Пробуем: 1) public/...  2) корень проекта (если папку public не создали)
  const candidates = [
    path.normalize(path.join(PUBLIC, p)),
    path.normalize(path.join(__dirname, p.replace(/^\//, '')))
  ];

  const tryNext = (i) => {
    if (i >= candidates.length) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Not found\n\nПоложи index.html либо в папку public/, либо прямо в корень рядом с server.js и сделай Redeploy.');
    }
    const file = candidates[i];
    // защита от выхода за пределы проекта
    if (!file.startsWith(PUBLIC) && !file.startsWith(__dirname)) {
      return tryNext(i + 1);
    }
    fs.stat(file, (err, st) => {
      if (err || !st.isFile()) return tryNext(i + 1);
      const ext = path.extname(file).toLowerCase();
      const head = { 'Content-Type': MIME[ext] || 'application/octet-stream', 'Cache-Control': 'public, max-age=60' };
      const gz = /\bgzip\b/.test(req.headers['accept-encoding'] || '') && /\.(html|js|css|json|svg)$/.test(ext);
      if (!gz) {
        head['Content-Length'] = st.size;
        res.writeHead(200, head);
        return req.method === 'HEAD' ? res.end() : fs.createReadStream(file).pipe(res);
      }
      const c = gzCache.get(file);
      const send = buf => {
        head['Content-Encoding'] = 'gzip';
        head['Vary'] = 'Accept-Encoding';
        head['Content-Length'] = buf.length;
        res.writeHead(200, head);
        res.end(req.method === 'HEAD' ? undefined : buf);
      };
      if (c && c.mtime === st.mtimeMs) return send(c.buf);
      fs.readFile(file, (e, raw) => {
        if (e) { res.writeHead(500); return res.end(); }
        zlib.gzip(raw, { level: 9 }, (e2, buf) => {
          if (e2) { res.writeHead(500); return res.end(); }
          gzCache.set(file, { mtime: st.mtimeMs, buf });
          send(buf);
        });
      });
    });
  };
  tryNext(0);
}

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');          // клиент можно открыть и с другого домена (?server=...)
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  const url = (req.url || '/').split('?')[0];
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  if (url === '/health') { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('ok'); }
  if (API[url]) {
    if (req.method !== 'POST') return fail(res, 405, 'Только POST');
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'x').toString().split(',')[0].trim();
    return readBody(req, res, body => API[url](body, res, ip));
  }
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
  serveStatic(req, res);
});

/* ---------- WebSocket ---------- */
const wss = new WebSocketServer({ server, maxPayload: 16384 });
const rooms = {};                 // n -> Map(id -> client)
for (let i = 1; i <= MAX_ROOM; i++) rooms[i] = new Map();
const online = new Map();         // nick key -> client

function send(c, o) { if (c.ws.readyState === 1) c.ws.send(JSON.stringify(o)); }
function leave(c) {
  if (c.room) { rooms[c.room].delete(c.id); c.room = 0; }
  if (c.key && online.get(c.key) === c) online.delete(c.key);
}

wss.on('connection', (ws) => {
  const c = { ws, id: 0, room: 0, key: '', nick: '', x: 0, y: 0, z: 0, r: 0, h: '', m: 0, alive: true, vt: 0, vn: 0 };
  ws.on('pong', () => { ws.dead = false; });

  ws.on('message', (buf, isBinary) => {
    if (isBinary) {                                   // голос: Int16 PCM 8кГц
      if (!c.room || buf.length < 2 || buf.length > 8192) return;
      const now = Date.now();
      if (now - c.vt > 1000) { c.vt = now; c.vn = 0; }
      if (++c.vn > 40) return;
      const out = Buffer.allocUnsafe(buf.length + 1);
      out[0] = c.id; buf.copy(out, 1);
      for (const p of rooms[c.room].values()) {
        if (p === c) continue;
        if (Math.hypot(p.x - c.x, p.y - c.y, p.z - c.z) <= VOICE_R && p.ws.readyState === 1) p.ws.send(out, { binary: true });
      }
      return;
    }
    let m; try { m = JSON.parse(buf.toString()); } catch (e) { return; }
    if (!m || typeof m !== 'object') return;

    if (m.t === 'join') {
      if (c.room) return;
      const room = m.room | 0;
      const k = byToken.get(m.token);
      if (!k || !users[k]) { send(c, { t: 'auth' }); return ws.close(); }
      if (room < 1 || room > MAX_ROOM) return ws.close();
      const R = rooms[room];
      if (R.size >= MAX_PER_ROOM) { send(c, { t: 'full' }); return ws.close(); }
      const old = online.get(k);
      if (old) { send(old, { t: 'kick' }); leave(old); old.ws.close(); }
      let id = 1; while (R.has(id)) id++;
      c.id = id; c.room = room; c.key = k; c.nick = users[k].nick;
      R.set(id, c); online.set(k, c);
      send(c, { t: 'hello', id });
    } else if (m.t === 'pos' && c.room) {
      const f = v => (typeof v === 'number' && isFinite(v) ? Math.max(-1000, Math.min(1000, v)) : 0);
      c.x = f(m.x); c.y = f(m.y); c.z = f(m.z); c.r = f(m.r);
      c.h = typeof m.h === 'string' ? m.h.slice(0, 24) : '';
      c.m = m.m ? 1 : 0;
    }
  });
  ws.on('close', () => leave(c));
  ws.on('error', () => leave(c));
});

// рассылка состояния комнаты
setInterval(() => {
  for (const n in rooms) {
    const R = rooms[n]; if (!R.size) continue;
    const all = [...R.values()].map(p => ({ i: p.id, u: p.nick, x: p.x, y: p.y, z: p.z, r: p.r, h: p.h, m: p.m }));
    for (const c of R.values()) {
      send(c, { t: 'state', n: R.size, p: all.filter(o => o.i !== c.id) });
    }
  }
}, TICK_MS);

// ping каждые 25 с: Render режет молчащие соединения; не ответившие на ping — закрываем
setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.dead) return ws.terminate();
    ws.dead = true; try { ws.ping(); } catch (e) {}
  });
}, 25000).unref();

server.listen(PORT, () => console.log('VR Box server on :' + PORT));
