#!/usr/bin/env node
/*
 * StudyQuest server with "Sign in with Google" + built-in Google Classroom.
 * No npm packages. Requires Node.js 18 or newer.
 *
 *   node server.js            then open http://localhost:3000/setup  (one time, ~5 minutes)
 *
 * After that, anyone you allow just taps "Continue with Google". Nothing to paste, ever.
 *
 * Optional settings (environment variables, or the same names in config.json):
 *   PORT=3000                       GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET
 *   PUBLIC_URL=https://study.example.com   (the address people use; Google needs https unless it's localhost)
 *   ALLOWED_EMAILS=me@gmail.com,friend@school.org   (leave empty to allow any Google account)
 *   MAX_USERS=100     TLS_KEY=key.pem TLS_CERT=cert.pem (serve https directly)
 */
if (typeof fetch !== 'function') { console.error('StudyQuest needs Node.js 18 or newer (nodejs.org).'); process.exit(1); }
const http = require('http'), https = require('https'), fs = require('fs'), path = require('path'), crypto = require('crypto'), os = require('os');
const env = process.env, PORT = +env.PORT || 3000, MAX_USERS = +env.MAX_USERS || 100;
const DB_FILE = path.join(__dirname, 'studyquest-data.json'), CFG_FILE = path.join(__dirname, 'config.json'), PAGE = path.join(__dirname, 'index.html');
const G = { // overridable only so the server can be tested against a fake Google
  auth: env.G_AUTH || 'https://accounts.google.com/o/oauth2/v2/auth', token: env.G_TOKEN || 'https://oauth2.googleapis.com/token',
  revoke: env.G_REVOKE || 'https://oauth2.googleapis.com/revoke', classroom: env.G_CLASSROOM || 'https://classroom.googleapis.com/v1', calendar: env.G_CALENDAR || 'https://www.googleapis.com/calendar/v3' };
const CLASSROOM_SCOPES = ['https://www.googleapis.com/auth/classroom.courses.readonly', 'https://www.googleapis.com/auth/classroom.coursework.me.readonly', 'https://www.googleapis.com/auth/classroom.student-submissions.me.readonly'];

// Each permission counts as granted if Google reports it OR a broader/equivalent Classroom scope that allows the same reads.
const SCOPE_BASE = 'https://www.googleapis.com/auth/';
const NEED = [
  ['classroom.courses.readonly', 'classroom.courses'],
  ['classroom.coursework.me.readonly', 'classroom.coursework.me', 'classroom.coursework.students.readonly', 'classroom.coursework.students'],
  ['classroom.student-submissions.me.readonly', 'classroom.student-submissions.students.readonly', 'classroom.coursework.me.readonly', 'classroom.coursework.me', 'classroom.coursework.students.readonly', 'classroom.coursework.students']];
const missingScopes = granted => NEED.filter(g => !g.some(x => granted.includes(SCOPE_BASE + x))).map(g => g[0]);

// ---------- config + database ----------
let cfg = {}; try { cfg = JSON.parse(fs.readFileSync(CFG_FILE, 'utf8')); } catch (e) {}
function saveCfg() { fs.writeFileSync(CFG_FILE, JSON.stringify(cfg, null, 2), { mode: 0o600 }); }
if (!cfg.secretKey && !env.SECRET_KEY) { cfg.secretKey = crypto.randomBytes(32).toString('hex'); saveCfg(); }
const conf = () => ({
  clientId: env.GOOGLE_CLIENT_ID || cfg.clientId || '', clientSecret: env.GOOGLE_CLIENT_SECRET || cfg.clientSecret || '',
  publicUrl: (env.PUBLIC_URL || cfg.publicUrl || 'http://localhost:' + PORT).replace(/\/+$/, ''),
  allowed: String(env.ALLOWED_EMAILS || (cfg.allowedEmails || []).join(',')).split(',').map(s => s.trim().toLowerCase()).filter(Boolean),
  passwords: env.PASSWORD_LOGIN !== 'off' && cfg.passwords !== false,
  courseworkScope: env.COURSEWORK_SCOPE || cfg.courseworkScope || '' });
const configured = () => { const c = conf(); return !!(c.clientId && c.clientSecret); };
const redirectUri = () => conf().publicUrl + '/auth/google/callback';

let db = { users: {}, sessions: {} };
try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) {}
db.users = db.users || {}; db.sessions = db.sessions || {};
function save() { const t = DB_FILE + '.tmp'; fs.writeFileSync(t, JSON.stringify(db), { mode: 0o600 }); fs.renameSync(t, DB_FILE); }

// Google refresh tokens are encrypted at rest with a key kept in config.json.
const aesKey = () => crypto.createHash('sha256').update(env.SECRET_KEY || cfg.secretKey).digest();
function enc(t) { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', aesKey(), iv), ct = Buffer.concat([c.update(t, 'utf8'), c.final()]); return [iv, c.getAuthTag(), ct].map(b => b.toString('base64')).join('.'); }
function dec(s) { try { const [iv, tag, ct] = s.split('.').map(x => Buffer.from(x, 'base64')), d = crypto.createDecipheriv('aes-256-gcm', aesKey(), iv); d.setAuthTag(tag); return Buffer.concat([d.update(ct), d.final()]).toString('utf8'); } catch (e) { return null; } }
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
// ---------- username + password accounts (optional, alongside Google) ----------
const scrypt = (pw, salt) => new Promise((res, rej) => crypto.scrypt(pw, salt, 64, (e, k) => e ? rej(e) : res(k.toString('hex'))));
async function makeHash(pw) { const salt = crypto.randomBytes(16).toString('hex'); return { salt, hash: await scrypt(pw, salt) }; }
async function checkPw(u, pw) {
  const h = await scrypt(pw, u && u.salt ? u.salt : 'x'.repeat(32)); // always do the work, so timing doesn't reveal which usernames exist
  return !!(u && u.hash) && crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(u.hash, 'hex'));
}
const fails = {}; // 5 wrong tries per username+IP -> 5 minute pause
const locked = k => fails[k] && fails[k].n >= 5 && Date.now() < fails[k].until;
function noteFail(k) { const f = fails[k] = fails[k] || { n: 0, until: 0 }; if (++f.n >= 5) f.until = Date.now() + 5 * 60000; }
function newSession(sub) {
  const token = crypto.randomBytes(32).toString('hex'); db.sessions[sha(token)] = { user: sub, exp: Date.now() + 90 * 864e5 };
  for (const k in db.sessions) if (db.sessions[k].exp < Date.now()) delete db.sessions[k];
  save(); return token;
}
// The coursework permission can be swapped if Google's console won't accept the default (set COURSEWORK_SCOPE or "courseworkScope" in config.json).
const COURSEWORK_CHOICES = ['classroom.coursework.me.readonly', 'classroom.coursework.students.readonly', 'classroom.coursework.me'];
const requestScopes = () => ['openid', 'email', 'profile', SCOPE_BASE + 'classroom.courses.readonly',
  SCOPE_BASE + (COURSEWORK_CHOICES.includes(conf().courseworkScope) ? conf().courseworkScope : COURSEWORK_CHOICES[0]), SCOPE_BASE + 'classroom.student-submissions.me.readonly',
  SCOPE_BASE + 'classroom.announcements.readonly', SCOPE_BASE + 'classroom.courseworkmaterials.readonly', SCOPE_BASE + 'calendar.readonly'];
const googleUrl = (state, prompt) => G.auth + '?' + new URLSearchParams({ client_id: conf().clientId, redirect_uri: redirectUri(), response_type: 'code',
  scope: requestScopes().join(' '), access_type: 'offline', include_granted_scopes: 'true', state, prompt });
const states = new Map(), logins = new Map(), atCache = new Map();
setInterval(() => { const n = Date.now(); for (const m of [states, logins]) for (const [k, v] of m) if (v.exp < n) m.delete(k); }, 60000).unref();

// ---------- Google helpers ----------
async function gjson(url, opts) {
  const r = await fetch(url, opts), j = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error((j.error && (j.error.message || j.error)) || j.error_description || 'HTTP ' + r.status); e.status = r.status; e.body = j; throw e; }
  return j;
}
const form = o => ({ method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(o) });
async function accessToken(user) {
  const hit = atCache.get(user.sub); if (hit && hit.exp > Date.now() + 60000) return hit.token;
  const rt = user.rt && dec(user.rt), c = conf();
  const relink = () => { user.rt = null; user.classroom = false; atCache.delete(user.sub); save(); const e = new Error('relink'); e.relink = true; return e; };
  if (!rt) throw relink();
  try {
    const j = await gjson(G.token, form({ client_id: c.clientId, client_secret: c.clientSecret, refresh_token: rt, grant_type: 'refresh_token' }));
    atCache.set(user.sub, { token: j.access_token, exp: Date.now() + (j.expires_in || 3600) * 1000 }); return j.access_token;
  } catch (e) { if (e.body && e.body.error === 'invalid_grant') throw relink(); throw e; }
}
// Google's list of "granted scopes" can leave out a scope whose wording matches another one. So when it looks incomplete,
// we test for real: ask Google for one class's assignments. Only a "scope" error means the permission is truly missing.
async function probeScopes(user) {
  try {
    atCache.delete(user.sub); const tok = await accessToken(user), B = G.classroom, h = { headers: { Authorization: 'Bearer ' + tok } };
    const cs = (await gjson(B + '/courses?' + new URLSearchParams({ studentId: 'me', courseStates: 'ACTIVE', pageSize: '1' }), h)).courses || [];
    if (!cs.length) return true; // nothing to test against; a real problem would show up on the first sync
    try { await gjson(B + '/courses/' + cs[0].id + '/courseWork?pageSize=1', h); return true; }
    catch (e) { return !/SCOPE_INSUFFICIENT|insufficient authentication scopes/i.test(JSON.stringify(e.body || '') + e.message); }
  } catch (e) { return false; }
}
async function pages(url, params, key, token) {
  let out = [], pt;
  do { const q = new URLSearchParams(Object.assign({ pageSize: '100' }, params)); if (pt) q.set('pageToken', pt);
    const j = await gjson(url + '?' + q, { headers: { Authorization: 'Bearer ' + token } }); out = out.concat(j[key] || []); pt = j.nextPageToken; } while (pt);
  return out;
}
const isScope = e => /SCOPE_INSUFFICIENT|insufficient authentication scopes|insufficientPermissions/i.test(JSON.stringify(e.body || '') + e.message);
const attach = ms => (ms || []).map(m => m.driveFile ? { k: 'drive', title: m.driveFile.driveFile.title, url: m.driveFile.driveFile.alternateLink }
  : m.youTubeVideo ? { k: 'video', title: m.youTubeVideo.title, url: m.youTubeVideo.alternateLink }
  : m.link ? { k: 'link', title: m.link.title || m.link.url, url: m.link.url }
  : m.form ? { k: 'form', title: m.form.title, url: m.form.formUrl } : null).filter(x => x && /^https:\/\//.test(x.url || ''));
const firstPage = async (url, params, key, token) => (await gjson(url + '?' + new URLSearchParams(params), { headers: { Authorization: 'Bearer ' + token } }))[key] || [];
async function classroomData(user) {
  const tok = await accessToken(user), B = G.classroom;
  const courses = await pages(B + '/courses', { studentId: 'me', courseStates: 'ACTIVE' }, 'courses', tok);
  const items = [], skipped = [], announcements = [], materials = [], missing = new Set();
  await Promise.all(courses.map(async c => {
    try {
      const state = {};
      try { (await pages(`${B}/courses/${c.id}/courseWork/-/studentSubmissions`, { userId: 'me' }, 'studentSubmissions', tok)).forEach(s => { state[s.courseWorkId] = s.state; }); } catch (e) { /* turned-in status is optional */ }
      (await pages(`${B}/courses/${c.id}/courseWork`, { courseWorkStates: 'PUBLISHED' }, 'courseWork', tok)).forEach(w =>
        items.push({ id: c.id + '_' + w.id, course: c.name, title: w.title, dueDate: w.dueDate || null, dueTime: w.dueTime || null, state: state[w.id] || '', link: w.alternateLink, pts: w.maxPoints || 0, materials: attach(w.materials) }));
    } catch (e) { skipped.push({ course: c.name, error: String(e.message).slice(0, 160) }); }
    try {
      (await firstPage(`${B}/courses/${c.id}/announcements`, { announcementStates: 'PUBLISHED', orderBy: 'updateTime desc', pageSize: '8' }, 'announcements', tok))
        .forEach(a => announcements.push({ id: c.id + '_' + a.id, course: c.name, text: String(a.text || '').slice(0, 1500), time: a.updateTime || a.creationTime, link: a.alternateLink, materials: attach(a.materials) }));
    } catch (e) { if (isScope(e)) missing.add('announcements'); }
    try {
      (await firstPage(`${B}/courses/${c.id}/courseWorkMaterials`, { courseWorkMaterialStates: 'PUBLISHED', orderBy: 'updateTime desc', pageSize: '10' }, 'courseWorkMaterial', tok))
        .forEach(m => materials.push({ id: c.id + '_' + m.id, course: c.name, title: m.title || '(Untitled)', text: String(m.description || '').slice(0, 800), time: m.updateTime || m.creationTime, link: m.alternateLink, materials: attach(m.materials) }));
    } catch (e) { if (isScope(e)) missing.add('materials'); }
  }));
  const newest = (a, b) => String(b.time || '').localeCompare(String(a.time || ''));
  return { ok: true, courses: courses.length, items, skipped, announcements: announcements.sort(newest).slice(0, 60), materials: materials.sort(newest).slice(0, 60), missing: [...missing] };
}
// All the user's visible Google calendars, for one date range.
async function calendarData(user, from, to) {
  const tok = await accessToken(user), B = G.calendar, h = { headers: { Authorization: 'Bearer ' + tok } };
  const cals = ((await gjson(B + '/users/me/calendarList?' + new URLSearchParams({ minAccessRole: 'reader', maxResults: '50' }), h)).items || []).filter(c => c.selected !== false).slice(0, 8);
  const events = [];
  await Promise.all(cals.map(async c => {
    try {
      const j = await gjson(B + '/calendars/' + encodeURIComponent(c.id) + '/events?' + new URLSearchParams({ timeMin: from, timeMax: to, singleEvents: 'true', orderBy: 'startTime', maxResults: '250' }), h);
      (j.items || []).filter(e => e.status !== 'cancelled' && e.start).forEach(e => events.push({ id: c.id + '|' + e.id, title: e.summary || '(No title)', start: e.start.dateTime || e.start.date, end: (e.end || {}).dateTime || (e.end || {}).date,
        allDay: !!e.start.date, link: e.htmlLink, where: e.location || '', cal: c.summaryOverride || c.summary, color: c.backgroundColor }));
    } catch (e) { if (isScope(e)) throw e; } // one broken calendar shouldn't hide the rest
  }));
  return { ok: true, events };
}

// ---------- HTTP ----------
const isLocal = req => ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.socket.remoteAddress) && !req.headers['x-forwarded-for'] && /^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/.test(req.headers.host || '');
function readBody(req) {
  return new Promise((res, rej) => { let b = '', n = 0;
    req.on('data', c => { n += c.length; if (n > 2e6) { rej(new Error('That is too much data.')); req.destroy(); } else b += c; });
    req.on('end', () => { try { res(b ? JSON.parse(b) : {}); } catch (e) { rej(new Error('Bad request.')); } }); });
}
const bearer = req => (req.headers.authorization || '').replace(/^Bearer /, '');
function authed(req) { const s = db.sessions[sha(bearer(req))]; return s && s.exp > Date.now() && db.users[s.user] ? db.users[s.user] : null; }
const has = (u, x) => (u.granted || []).includes(x);
const pub = u => ({ sub: u.sub, name: u.name, email: u.email || '', classroom: !!u.classroom, password: !!u.hash,
  perms: { announcements: has(u, 'classroom.announcements.readonly'), materials: has(u, 'classroom.courseworkmaterials.readonly'), calendar: has(u, 'calendar.readonly') || has(u, 'calendar') } });

async function handle(req, res) {
  const u = new URL(req.url, 'http://x'), p = u.pathname, q = u.searchParams, M = req.method;
  const headers = (t, extra) => Object.assign({ 'Content-Type': t, 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store' }, extra);
  const html = (code, b) => { res.writeHead(code, headers('text/html; charset=utf-8')); res.end(b); };
  const redirect = loc => { res.writeHead(302, { Location: loc, 'Cache-Control': 'no-store' }); res.end(); };
  const send = (code, o) => { res.writeHead(code, headers('application/json')); res.end(JSON.stringify(o)); };
  const fail = msg => redirect('/?autherror=' + encodeURIComponent(msg));
  try {
    if (M === 'GET' && (p === '/' || p === '/index.html')) { res.writeHead(200, headers('text/html; charset=utf-8', { 'Cache-Control': 'no-cache' })); return res.end(fs.readFileSync(PAGE)); }

    // ----- one-time setup, only from the computer running the server -----
    if (p === '/setup' || p === '/setup/save') {
      if (!isLocal(req)) return html(403, 'Setup is only available on the computer running the server: open http://localhost:' + PORT + '/setup there.');
      if (p === '/setup') return html(200, setupPage());
      const b = await readBody(req), id = String(b.clientId || '').trim(), sec = String(b.clientSecret || '').trim(), url = String(b.publicUrl || '').trim().replace(/\/+$/, '');
      if (!/\.apps\.googleusercontent\.com$/.test(id)) return send(400, { error: 'The Client ID should end in .apps.googleusercontent.com' });
      if (sec.length < 8) return send(400, { error: 'Paste the Client secret too.' });
      if (!/^https?:\/\/[^\s/]+$/.test(url)) return send(400, { error: 'The address should look like https://study.example.com or http://localhost:' + PORT });
      cfg.clientId = id; cfg.clientSecret = sec; cfg.publicUrl = url;
      cfg.passwords = b.passwords !== false;
      cfg.allowedEmails = String(b.allowedEmails || '').split(/[\s,]+/).map(s => s.trim().toLowerCase()).filter(Boolean);
      saveCfg(); return send(200, { ok: true, url });
    }

    // ----- Sign in with Google, or link Classroom to an account you already have -----
    if (p === '/auth/google') {
      if (!configured()) return fail('Google sign-in is not set up yet.');
      const state = crypto.randomBytes(16).toString('hex'); states.set(state, { exp: Date.now() + 600000 });
      return redirect(googleUrl(state, 'select_account'));
    }
    if (p === '/auth/google/callback') {
      const st = states.get(q.get('state')); states.delete(q.get('state'));
      const bad = msg => redirect((st && st.linkUser ? '/?linkerror=' : '/?autherror=') + encodeURIComponent(msg));
      if (q.get('error')) return bad('Google sign-in was cancelled.');
      if (!st || st.exp < Date.now() || !q.get('code')) return bad('That sign-in expired. Please try again.');
      const c = conf();
      const tok = await gjson(G.token, form({ code: q.get('code'), client_id: c.clientId, client_secret: c.clientSecret, redirect_uri: redirectUri(), grant_type: 'authorization_code' }));
      const granted = String(tok.scope || '').split(' '), all = missingScopes(granted).length === 0;
      if (st.linkUser) { // signed-in user (any kind) connecting Classroom
        const target = db.users[st.linkUser]; if (!target) return bad('Your account was not found.');
        if (tok.refresh_token) target.rt = enc(tok.refresh_token);
        target.granted = granted.map(x => x.replace(SCOPE_BASE, ''));
        const basics = granted.includes(SCOPE_BASE + 'classroom.courses.readonly');
        target.classroom = !!target.rt && (all || (basics && await probeScopes(target))); atCache.delete(target.sub); save();
        if (target.classroom) return redirect('/?linked=1');
        const missing = missingScopes(granted);
        console.log('[Classroom link] Google granted:', granted.join(' ') || '(nothing)');
        const short = x => x.replace(SCOPE_BASE, ''), asked = requestScopes().filter(x => x.startsWith(SCOPE_BASE)).map(short);
        return bad(missing.length
          ? 'Google did not grant: ' + missing.join(', ') + '. This server asked for: ' + asked.join(', ') + '. Google approved: ' + (granted.map(short).join(', ') || 'nothing') + '. Every scope in "asked" must be listed under Data access in Google Cloud (Google Auth Platform), your account must be a test user, and you should remove the app at myaccount.google.com/permissions before tapping Connect again.'
          : 'Google did not return a long-lived key. Remove this app at myaccount.google.com/permissions and tap Connect again.');
      }
      const claims = JSON.parse(Buffer.from(String(tok.id_token).split('.')[1], 'base64url').toString()); // received straight from Google over TLS
      const email = String(claims.email || '').toLowerCase();
      if (!claims.sub) return bad('Google did not return an account.');
      if (c.allowed.length && !c.allowed.includes(email)) return bad('This StudyQuest server is private. Ask the owner to add ' + email + '.');
      if (!db.users[claims.sub] && Object.keys(db.users).length >= MAX_USERS) return bad('This server is full.');
      const user = db.users[claims.sub] = db.users[claims.sub] || { sub: claims.sub, created: Date.now(), data: null };
      user.email = email; user.name = claims.name || email;
      if (tok.refresh_token) user.rt = enc(tok.refresh_token);
      user.granted = granted.map(x => x.replace(SCOPE_BASE, ''));
      user.classroom = !!user.rt && (all || (granted.includes(SCOPE_BASE + 'classroom.courses.readonly') && await probeScopes(user))); atCache.delete(user.sub); save();
      const code = crypto.randomBytes(24).toString('hex'); logins.set(code, { sub: user.sub, exp: Date.now() + 60000 });
      return redirect('/?login=' + code); // one-time code, swapped for a session by the page
    }

    // ----- API -----
    if (p === '/api/ping') return send(200, { server: true, google: configured(), passwords: conf().passwords, local: isLocal(req) });
    const body = M === 'GET' ? {} : await readBody(req);
    if (p === '/api/signup' || p === '/api/login') {
      if (!conf().passwords) return send(403, { error: 'Username accounts are turned off on this server.' });
      const name = String(body.username || '').trim().toLowerCase(), pw = String(body.password || ''), sub = 'pw:' + name;
      if (!/^[a-z0-9_.-]{3,24}$/.test(name)) return send(400, { error: 'Username: 3–24 letters, numbers, . _ or -' });
      if (p === '/api/signup') {
        if (pw.length < 8 || pw.length > 200) return send(400, { error: 'Pick a password with at least 8 characters.' });
        if (db.users[sub]) return send(409, { error: 'That username is taken.' });
        if (Object.keys(db.users).length >= MAX_USERS) return send(403, { error: 'This server is full.' });
        db.users[sub] = Object.assign({ sub, name, email: '', created: Date.now(), data: null, classroom: false }, await makeHash(pw));
      } else {
        const key = req.socket.remoteAddress + ':' + name;
        if (locked(key)) return send(429, { error: 'Too many wrong tries. Please wait a few minutes.' });
        if (!(await checkPw(db.users[sub], pw))) { noteFail(key); return send(401, { error: 'Wrong username or password.' }); }
        delete fails[key];
      }
      return send(200, { token: newSession(sub), user: pub(db.users[sub]) });
    }
    if (p === '/api/exchange') {
      const l = logins.get(String(body.code)); logins.delete(String(body.code));
      if (!l || l.exp < Date.now() || !db.users[l.sub]) return send(400, { error: 'That sign-in expired. Please try again.' });
      return send(200, { token: newSession(l.sub), user: pub(db.users[l.sub]) });
    }
    const user = authed(req);
    if (!user) return send(401, { error: 'Please sign in again.' });
    if (p === '/api/me') return send(200, pub(user));
    if (p === '/api/classroom/link') { // returns the Google consent address, tied to the signed-in account
      if (!configured()) return send(409, { error: 'Google is not set up on this server yet. Ask the owner to finish the setup.' });
      const state = crypto.randomBytes(16).toString('hex'); states.set(state, { exp: Date.now() + 600000, linkUser: user.sub });
      return send(200, { url: googleUrl(state, 'consent') });
    }
    if (p === '/api/password') {
      if (!user.hash) return send(400, { error: 'This account signs in with Google, so it has no password.' });
      if (!(await checkPw(user, String(body.old || '')))) return send(401, { error: 'Your current password is wrong.' });
      const np = String(body.new || ''); if (np.length < 8 || np.length > 200) return send(400, { error: 'New password needs at least 8 characters.' });
      Object.assign(user, await makeHash(np));
      const keep = sha(bearer(req)); for (const k in db.sessions) if (db.sessions[k].user === user.sub && k !== keep) delete db.sessions[k]; // sign out other devices
      save(); return send(200, { ok: true });
    }
    if (p === '/api/data' && M === 'GET') return send(200, { data: user.data });
    if (p === '/api/data' && M === 'PUT') {
      if (!Array.isArray(body.tasks) || typeof body.u !== 'number') return send(400, { error: 'Bad data.' });
      user.data = { u: body.u, tasks: body.tasks, stats: body.stats }; save(); return send(200, { ok: true });
    }
    if (p === '/api/classroom' && M === 'GET') {
      if (!user.classroom) return send(409, { error: 'relink' });
      try { return send(200, await classroomData(user)); } catch (e) { return e.relink ? send(409, { error: 'relink' }) : send(502, { error: 'Google said: ' + e.message }); }
    }
    if (p === '/api/calendar' && M === 'GET') {
      const from = Date.parse(q.get('from')), to = Date.parse(q.get('to'));
      if (!(from < to) || to - from > 100 * 864e5) return send(400, { error: 'Bad dates.' });
      if (!user.rt) return send(409, { error: 'relink' });
      try { return send(200, await calendarData(user, new Date(from).toISOString(), new Date(to).toISOString())); }
      catch (e) { return e.relink ? send(409, { error: 'relink' }) : isScope(e) ? send(409, { error: 'scope' }) : send(502, { error: 'Google said: ' + e.message }); }
    }
    const revoke = () => { const rt = user.rt && dec(user.rt); if (rt) fetch(G.revoke, form({ token: rt })).catch(() => {}); };
    if (p === '/api/classroom/unlink') { revoke(); user.rt = null; user.classroom = false; atCache.delete(user.sub); save(); return send(200, { ok: true }); }
    if (p === '/api/logout') { delete db.sessions[sha(bearer(req))]; save(); return send(200, { ok: true }); }
    if (p === '/api/delete') { revoke(); delete db.users[user.sub]; for (const k in db.sessions) if (db.sessions[k].user === user.sub) delete db.sessions[k]; save(); return send(200, { ok: true }); }
    send(404, { error: 'Not found' });
  } catch (e) { if (p.startsWith('/auth/')) return fail('Google sign-in failed: ' + e.message); send(400, { error: e.message || 'Something went wrong.' }); }
}

function setupPage() {
  const c = conf(), esc = s => String(s).replace(/[&<>"]/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[ch]));
  const link = (u, t) => `<a href="${u}" target="_blank" rel="noopener">${t} ↗</a>`;
  return `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>StudyQuest setup</title>
<style>body{font:15px/1.5 system-ui,sans-serif;max-width:640px;margin:2rem auto;padding:0 1rem;color:#1e293b}h1{margin-bottom:0}li{margin:.7rem 0}a{color:#4f46e5;font-weight:600}
input{width:100%;box-sizing:border-box;padding:.6rem;border:1px solid #cbd5e1;border-radius:.6rem;font:inherit;margin:.2rem 0 .6rem}code{background:#f1f5f9;padding:.1rem .35rem;border-radius:.3rem;word-break:break-all}
button{background:#4f46e5;color:#fff;border:0;border-radius:.7rem;padding:.7rem 1.2rem;font:inherit;font-weight:700;cursor:pointer}#msg{font-weight:600;margin-top:.8rem}</style>
<h1>StudyQuest setup</h1><p style="color:#64748b;margin-top:.2rem">Do this once. After that, everyone just taps “Continue with Google”.</p>
<ol><li>Create a Google Cloud project. ${link('https://console.cloud.google.com/projectcreate', 'Open')}</li>
<li>Turn on <b>two</b> APIs: the <b>Google Classroom API</b> ${link('https://console.cloud.google.com/apis/library/classroom.googleapis.com', 'Enable')} and the <b>Google Calendar API</b> ${link('https://console.cloud.google.com/apis/library/calendar-json.googleapis.com', 'Enable')}. Nothing else is needed.</li>
<li>Set up the consent screen: choose <b>External</b>. Under <b>Data access</b> choose <b>Add or remove scopes</b> and paste these into <b>Manually add scopes</b> (one per line), then <b>Update</b> and <b>Save</b>:
<pre style="background:#f1f5f9;padding:.6rem;border-radius:.5rem;overflow:auto;font-size:12px">https://www.googleapis.com/auth/classroom.courses.readonly
https://www.googleapis.com/auth/classroom.coursework.me.readonly
https://www.googleapis.com/auth/classroom.student-submissions.me.readonly
https://www.googleapis.com/auth/classroom.announcements.readonly
https://www.googleapis.com/auth/classroom.courseworkmaterials.readonly
https://www.googleapis.com/auth/calendar.readonly</pre>
Under <b>Audience</b> add everyone who will sign in as a <b>test user</b> (up to 100). ${link('https://console.cloud.google.com/auth/overview', 'Open')}</li>
<li>Create an <b>OAuth client</b> of type <b>Web application</b> and add this <b>Authorized redirect URI</b>: <code id="ru"></code> ${link('https://console.cloud.google.com/auth/clients/create', 'Create')}</li>
<li>Paste what Google shows you:
<label>Client ID<input id="cid" autocomplete="off" placeholder="123…apps.googleusercontent.com"></label>
<label>Client secret<input id="sec" type="password" autocomplete="off"></label>
<label>Address people will use <small>(http://localhost:${PORT} for testing; an https address to use it on phones)</small><input id="url" value="${esc(c.publicUrl)}"></label>
<label>Only allow these Google emails <small>(optional, comma separated; empty = any test user)</small><input id="em" value="${esc(c.allowed.join(', '))}"></label>
<label style="display:flex;gap:.5rem;align-items:center"><input id="pwon" type="checkbox" style="width:auto;margin:0" ${c.passwords ? 'checked' : ''}> Also let people make a username + password account <small>(turn off if you listed allowed emails above)</small></label><br>
<button onclick="go()">Save and finish</button><div id="msg"></div></li></ol>
<script>const $=i=>document.getElementById(i);function ru(){$('ru').textContent=$('url').value.replace(/\\/+$/,'')+'/auth/google/callback'}$('url').oninput=ru;ru();
async function go(){const r=await fetch('/setup/save',{method:'POST',body:JSON.stringify({clientId:$('cid').value,clientSecret:$('sec').value,publicUrl:$('url').value,allowedEmails:$('em').value,passwords:$('pwon').checked})});const j=await r.json();
$('msg').style.color=r.ok?'#059669':'#dc2626';$('msg').innerHTML=r.ok?'Saved! <a href="'+j.url+'">Open StudyQuest</a> and tap Continue with Google.':j.error}</script>`;
}

const useTls = env.TLS_KEY && env.TLS_CERT;
const server = useTls ? https.createServer({ key: fs.readFileSync(env.TLS_KEY), cert: fs.readFileSync(env.TLS_CERT) }, handle) : http.createServer(handle);
server.on('error', e => {
  if (e.code === 'EADDRINUSE') console.error('\nPort ' + PORT + ' is already in use. StudyQuest is probably already running in another window.\nClose that window (or press Ctrl+C in it), then try again.\nTo find what is using it on Windows: netstat -ano | findstr :' + PORT + '\n');
  else console.error(e);
  process.exit(1);
});
server.listen(PORT, '0.0.0.0', () => {
  const proto = useTls ? 'https' : 'http';
  console.log('\nStudyQuest is running.\n  On this computer:  ' + proto + '://localhost:' + PORT);
  for (const l of Object.values(os.networkInterfaces())) for (const i of l || []) if (i.family === 'IPv4' && !i.internal) console.log('  On your network:  ' + proto + '://' + i.address + ':' + PORT);
  if (!configured()) console.log('\nFirst time? Finish the one-time Google setup at http://localhost:' + PORT + '/setup');
  else if (!/^https:|^http:\/\/localhost/.test(conf().publicUrl)) console.log('\nNote: Google only allows https addresses (or localhost) for sign-in. PUBLIC_URL is ' + conf().publicUrl);
  console.log('\nData: ' + DB_FILE + '  (back it up; config.json holds your Google secret, keep it private)\n');
});
