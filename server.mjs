import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.PORT || 4173);
const publicOrigin = process.env.PUBLIC_ORIGIN || process.env.RENDER_EXTERNAL_URL || "";
const secret = process.env.SESSION_SECRET || (process.env.NODE_ENV === "production" ? "" : "local-development-secret-change-before-production");
if (process.env.NODE_ENV === "production" && (Buffer.byteLength(secret) < 32 || secret === "change-this-to-a-long-random-secret" || secret === "local-development-secret-change-before-production")) throw new Error("Set a unique SESSION_SECRET of at least 32 characters in production");
if (process.env.NODE_ENV === "production" && (!process.env.ADMIN_SETUP_KEY || process.env.ADMIN_SETUP_KEY.length < 8 || process.env.ADMIN_SETUP_KEY === "Dozett808")) throw new Error("Set a unique ADMIN_SETUP_KEY of at least 8 characters in production");
const turnUrls = (process.env.TURN_URLS || "").split(",").map(value => value.trim()).filter(Boolean);
const turnSharedSecret = process.env.TURN_SHARED_SECRET || "";
if (process.env.NODE_ENV === "production" && Boolean(turnUrls.length) !== Boolean(turnSharedSecret)) throw new Error("Set both TURN_URLS and TURN_SHARED_SECRET, or leave both unset");
const dataDir = path.resolve(process.env.DATA_DIR || path.join(__dirname, "data"));
const storeFile = path.join(dataDir, "store.json");
fs.mkdirSync(dataDir, { recursive: true });

const defaultStore = { users: [], beats: [], messages: [], contactRequests: [], nextUser: 1, nextBeat: 1 };
let store = fs.existsSync(storeFile) ? JSON.parse(fs.readFileSync(storeFile, "utf8")) : defaultStore;
store.users ||= [];
store.beats ||= [];
store.messages ||= [];
store.contactRequests ||= [];
const save = () => fs.writeFileSync(storeFile, JSON.stringify(store, null, 2));
const sessions = new Map();
const eventClients = new Map();
const rateLimits = new Map();
const callRooms = new Map();
const audioDir = path.join(dataDir, "audio");
fs.mkdirSync(audioDir, { recursive: true });
function removeAudioFile(file) {
  if (!file) return;
  try { fs.unlinkSync(path.join(audioDir, path.basename(file))); }
  catch (error) { if (error.code !== "ENOENT") throw error; }
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}
function verifyPassword(password, encoded) {
  const [salt, expected] = encoded.split(":");
  const actual = crypto.scryptSync(password, salt, 64).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(actual, "hex"));
}
function uid(prefix) {
  return `${prefix}_${crypto.randomBytes(12).toString("hex")}`;
}
function signSession(id) {
  const payload = Buffer.from(id).toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}
function sessionCookie(token, req) {
  const secure = req.socket.encrypted || process.env.COOKIE_SECURE === "true" ? "; Secure" : "";
  return `ts_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${60 * 60 * 24 * 30}${secure}`;
}
function verifySession(token) {
  if (!token) return null;
  const [payload, sig] = token.split(".");
  if (!payload || !sig) return null;
  const expected = crypto.createHmac("sha256", secret).update(payload).digest("base64url");
  try { if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null; } catch { return null; }
  return Buffer.from(payload, "base64url").toString("utf8");
}
function cookies(req) {
  return Object.fromEntries((req.headers.cookie || "").split(";").map(v => v.trim().split("=")).filter(v => v.length === 2).map(([k, v]) => [k, decodeURIComponent(v)]));
}
function currentUser(req) {
  const id = verifySession(cookies(req).ts_session);
  return id ? store.users.find(u => u.id === id) : null;
}
function setJson(res, status, value) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(JSON.stringify(value));
}
function readJson(req, maxBytes = 2_000_000) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let tooLarge = false;
    req.on("data", chunk => {
      size += chunk.length;
      if (size > maxBytes) { tooLarge = true; chunks.length = 0; return; }
      if (!tooLarge) chunks.push(chunk);
    });
    req.on("end", () => {
      if (tooLarge) { reject(new Error("Request too large")); return; }
      try { const body = Buffer.concat(chunks).toString("utf8"); resolve(body ? JSON.parse(body) : {}); } catch { reject(new Error("Invalid JSON")); }
    });
    req.on("error", reject);
  });
}
function readRaw(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let tooLarge = false;
    req.on("data", chunk => {
      size += chunk.length;
      if (size > maxBytes) { tooLarge = true; chunks.length = 0; return; }
      if (!tooLarge) chunks.push(chunk);
    });
    req.on("end", () => tooLarge ? reject(new Error("Audio file is too large")) : resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}
function rateLimit(req, action, max, windowMs) {
  const now = Date.now();
  if (rateLimits.size > 1000) {
    for (const [key, value] of rateLimits) if (value.expiresAt <= now) rateLimits.delete(key);
    while (rateLimits.size > 5000) rateLimits.delete(rateLimits.keys().next().value);
  }
  const ip = req.socket.remoteAddress || "unknown";
  const key = `${action}:${ip}`;
  const entry = rateLimits.get(key);
  if (!entry || entry.expiresAt <= now) {
    rateLimits.set(key, { count: 1, expiresAt: now + windowMs });
    return false;
  }
  entry.count += 1;
  return entry.count > max;
}
function isHoneypotFilled(body) {
  return String(body.website || "").trim().length > 0;
}
async function verifyCaptcha(token, req) {
  const siteKey = process.env.TURNSTILE_SITE_KEY || "";
  const secretKey = process.env.TURNSTILE_SECRET_KEY || "";
  if (!siteKey && !secretKey) return { ok: true };
  if (!siteKey || !secretKey) return { ok: false, status: 503, error: "Turnstile ist unvollständig konfiguriert" };
  if (!token) return { ok: false, status: 400, error: "Bitte die Sicherheitsprüfung abschließen" };
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ secret: secretKey, response: token, remoteip: req.socket.remoteAddress || "" }),
      signal: controller.signal
    });
    const result = await response.json();
    const expectedHost = publicOrigin ? new URL(publicOrigin).hostname : "";
    return response.ok && result.success === true && (!expectedHost || result.hostname === expectedHost)
      ? { ok: true }
      : { ok: false, status: 400, error: "Sicherheitsprüfung fehlgeschlagen" };
  } catch {
    return { ok: false, status: 503, error: "Sicherheitsprüfung ist vorübergehend nicht erreichbar" };
  } finally {
    clearTimeout(timeout);
  }
}
function safeBeat(beat) {
  const { audioFile, ...publicData } = beat;
  return publicData;
}
function audioInfo(mime) {
  const types = {
    "audio/mpeg": "mp3", "audio/mp3": "mp3", "audio/wav": "wav", "audio/x-wav": "wav",
    "audio/wave": "wav", "audio/ogg": "ogg", "audio/webm": "webm", "audio/mp4": "m4a", "audio/x-m4a": "m4a", "audio/x-flac": "flac",
    "audio/aac": "aac", "audio/flac": "flac"
  };
  return types[mime.toLowerCase()] || null;
}
function hasAudioSignature(buffer, mime) {
  if (mime === "audio/mpeg" || mime === "audio/mp3") return buffer.subarray(0, 3).toString() === "ID3" || (buffer[0] === 0xff && (buffer[1] & 0xe0) === 0xe0);
  if (mime === "audio/wav" || mime === "audio/x-wav" || mime === "audio/wave") return buffer.subarray(0, 4).toString() === "RIFF" && buffer.subarray(8, 12).toString() === "WAVE";
  if (mime === "audio/ogg") return buffer.subarray(0, 4).toString() === "OggS";
  if (mime === "audio/webm") return buffer.subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3]));
  if (mime === "audio/mp4" || mime === "audio/x-m4a") return buffer.subarray(4, 8).toString() === "ftyp";
  if (mime === "audio/aac") return buffer.subarray(0, 4).toString() === "ADIF" || (buffer[0] === 0xff && (buffer[1] & 0xf6) === 0xf0);
  if (mime === "audio/flac" || mime === "audio/x-flac") return buffer.subarray(0, 4).toString() === "fLaC";
  return false;
}
function publish(userId, payload) {
  for (const client of eventClients.get(userId) || []) client(payload);
}
function activeCallFor(userId) {
  for (const [callId, room] of callRooms) {
    if (room.participants.has(userId) || room.invited.has(userId)) return callId;
  }
  return "";
}
function hashCallToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}
function disconnectCallUser(userId) {
  for (const [callId, room] of callRooms) {
    if (room.hostId === userId) {
      for (const participantId of new Set([...room.participants, ...room.invited])) {
        if (participantId !== userId) publish(participantId, { type: "call", from: userId, payload: { type: "ended", callId } });
      }
      callRooms.delete(callId);
    } else if (room.participants.delete(userId)) {
      for (const participantId of room.participants) publish(participantId, { type: "call", from: userId, payload: { type: "left", callId, userId } });
    } else if (room.invited.delete(userId)) {
      for (const participantId of room.participants) publish(participantId, { type: "call", from: userId, payload: { type: "declined", callId, userId } });
    }
  }
}
function requireUser(req, res) {
  const user = currentUser(req);
  if (!user) { setJson(res, 401, { error: "Nicht angemeldet" }); return null; }
  return user;
}
function requireAdmin(req, res) {
  const user = requireUser(req, res);
  if (!user) return null;
  if (user.role !== "admin") { setJson(res, 403, { error: "Keine Administratorrechte" }); return null; }
  return user;
}
function publicUser(user, includeEmail = false) {
  return { id: user.id, artist: user.artist, role: user.role, avatar: user.avatar || "", ...(includeEmail ? { email: user.email || "" } : {}) };
}

async function api(req, res, url) {
  if (url.pathname === "/api/public-config" && req.method === "GET") {
    const iceServers = [{ urls: "stun:stun.l.google.com:19302" }];
    if (turnUrls.length && turnSharedSecret) {
      const username = `${Math.floor(Date.now() / 1000) + 3600}:twin-signal`;
      const credential = crypto.createHmac("sha1", turnSharedSecret).update(username).digest("base64");
      iceServers.push({ urls: turnUrls, username, credential });
    }
    setJson(res, 200, { turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || "", captchaRequired: Boolean(process.env.TURNSTILE_SITE_KEY && process.env.TURNSTILE_SECRET_KEY), iceServers });
    return true;
  }
  if (url.pathname === "/api/me" && req.method === "GET") {
    const user = requireUser(req, res);
    if (user) setJson(res, 200, { user: publicUser(user) });
    return true;
  }
  if (url.pathname === "/api/auth/register" && req.method === "POST") {
    if (rateLimit(req, "register", 5, 60 * 60 * 1000)) return setJson(res, 429, { error: "Zu viele Registrierungsversuche. Bitte später erneut versuchen." });
    const body = await readJson(req);
    if (isHoneypotFilled(body)) return setJson(res, 400, { error: "Anfrage konnte nicht verarbeitet werden" });
    const captcha = await verifyCaptcha(body.captchaToken, req);
    if (!captcha.ok) return setJson(res, captcha.status, { error: captcha.error });
    const artist = String(body.username || "").trim();
    const email = String(body.email || "").trim().toLowerCase();
    if (!artist || artist.length > 80 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 || String(body.password || "").length < 8 || String(body.password || "").length > 128) return setJson(res, 400, { error: "Benutzername, gültige E-Mail und ein Passwort mit 8 bis 128 Zeichen erforderlich" });
    if (store.users.some(u => u.artist.toLowerCase() === artist.toLowerCase())) return setJson(res, 409, { error: "Benutzername ist bereits registriert" });
    if (store.users.some(u => u.email && u.email.toLowerCase() === email)) return setJson(res, 409, { error: "E-Mail ist bereits registriert" });
    const user = { id: uid("member"), artist, email, role: "member", avatar: "", password: hashPassword(body.password), createdAt: new Date().toISOString() };
    store.users.push(user); save();
    const token = signSession(user.id);
    res.writeHead(200, { "Set-Cookie": sessionCookie(token, req), "Content-Type": "application/json" });
    res.end(JSON.stringify({ user: publicUser(user) }));
    return true;
  }
  if (url.pathname === "/api/auth/login" && req.method === "POST") {
    if (rateLimit(req, "login", 8, 15 * 60 * 1000)) return setJson(res, 429, { error: "Zu viele Anmeldeversuche. Bitte in 15 Minuten erneut versuchen." });
    const body = await readJson(req);
    if (isHoneypotFilled(body)) return setJson(res, 400, { error: "Anfrage konnte nicht verarbeitet werden" });
    const username = String(body.username || "").trim().toLowerCase();
    if (username.length > 254 || String(body.password || "").length > 128) return setJson(res, 401, { error: "Anmeldung fehlgeschlagen" });
    const user = store.users.find(u => u.artist.toLowerCase() === username || (u.email && u.email.toLowerCase() === username));
    if (!user) return setJson(res, 401, { error: "Anmeldung fehlgeschlagen" });
    try { if (!verifyPassword(body.password || "", user.password)) return setJson(res, 401, { error: "Anmeldung fehlgeschlagen" }); }
    catch { return setJson(res, 401, { error: "Anmeldung fehlgeschlagen" }); }
    if (user.role === "admin") {
      const adminCode = String(body.setupKey || "");
      if (adminCode.length > 128) return setJson(res, 401, { error: "Admin-Code ist nicht korrekt" });
      let validCode = false;
      if (store.adminCodeHash) {
        try { validCode = verifyPassword(adminCode, store.adminCodeHash); } catch { validCode = false; }
      } else {
        validCode = Boolean(process.env.ADMIN_SETUP_KEY) && adminCode === process.env.ADMIN_SETUP_KEY;
        if (validCode) { store.adminCodeHash = hashPassword(adminCode); save(); }
      }
      if (!validCode) return setJson(res, 401, { error: "Admin-Code ist nicht korrekt" });
    }
    const token = signSession(user.id);
    res.writeHead(200, { "Set-Cookie": sessionCookie(token, req), "Content-Type": "application/json" });
    res.end(JSON.stringify({ user: publicUser(user) }));
    return true;
  }
  if (url.pathname === "/api/admin/setup" && req.method === "POST") {
    if (rateLimit(req, "admin-setup", 3, 60 * 60 * 1000)) return setJson(res, 429, { error: "Zu viele Admin-Einrichtungsversuche" });
    const body = await readJson(req);
    if (store.users.some(u => u.role === "admin")) return setJson(res, 409, { error: "Ein Admin-Konto existiert bereits" });
    const username = String(body.username || "").trim();
    const email = String(body.email || "").trim().toLowerCase();
    const setupKey = String(body.setupKey || "");
    if (!username || username.length > 80 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 || String(body.password || "").length < 12 || String(body.password || "").length > 128 || setupKey.length > 128 || setupKey !== (process.env.ADMIN_SETUP_KEY || "")) return setJson(res, 400, { error: "Admin-Einrichtung: gültiger Setup-Key, Benutzername, gültige E-Mail und Passwort mit 12 bis 128 Zeichen erforderlich" });
    const admin = { id: uid("admin"), artist: username, email, role: "admin", avatar: "", password: hashPassword(body.password), createdAt: new Date().toISOString() };
    store.adminCodeHash = hashPassword(setupKey);
    store.users.push(admin); save();
    const token = signSession(admin.id);
    res.writeHead(200, { "Set-Cookie": sessionCookie(token, req), "Content-Type": "application/json" });
    res.end(JSON.stringify({ user: publicUser(admin), setupComplete: true }));
    return true;
  }
  if (url.pathname === "/api/admin/status" && req.method === "GET") {
    setJson(res, 200, { configured: store.users.some(u => u.role === "admin"), setupKeyRequired: true });
    return true;
  }
  if (url.pathname === "/api/admin/setup-code" && req.method === "POST") {
    const admin = requireAdmin(req, res); if (!admin) return true;
    const body = await readJson(req);
    const newCode = String(body.newCode || "");
    if (newCode.length < 8 || newCode.length > 128) return setJson(res, 400, { error: "Der Admin-Code muss 8 bis 128 Zeichen lang sein" });
    if (String(body.currentPassword || "").length > 128) return setJson(res, 401, { error: "Aktuelles Passwort ist nicht korrekt" });
    try { if (!verifyPassword(body.currentPassword || "", admin.password)) return setJson(res, 401, { error: "Aktuelles Passwort ist nicht korrekt" }); }
    catch { return setJson(res, 401, { error: "Aktuelles Passwort ist nicht korrekt" }); }
    store.adminCodeHash = hashPassword(newCode);
    save();
    setJson(res, 200, { ok: true });
    return true;
  }
  if (url.pathname === "/api/call-links" && req.method === "POST") {
    const user = requireUser(req, res); if (!user) return true;
    const body = await readJson(req);
    const callId = String(body.callId || "");
    const room = callRooms.get(callId);
    if (!/^[\w-]{16,80}$/.test(callId) || !room || !room.participants.has(user.id)) return setJson(res, 404, { error: "Aktiver Anruf nicht gefunden" });
    room.linkTokenHashes ||= new Set();
    if (room.linkTokenHashes.size >= 16) return setJson(res, 429, { error: "Für diesen Anruf wurden bereits zu viele Freigabelinks erstellt" });
    const token = crypto.randomBytes(32).toString("hex");
    room.linkTokenHashes.add(hashCallToken(token));
    setJson(res, 201, { token });
    return true;
  }
  if ((url.pathname === "/api/call-links/preview" || url.pathname === "/api/call-links/join") && req.method === "POST") {
    const user = requireUser(req, res); if (!user) return true;
    const body = await readJson(req);
    const callId = String(body.callId || "");
    const token = String(body.token || "");
    const room = callRooms.get(callId);
    if (!/^[\w-]{16,80}$/.test(callId) || !/^[a-f0-9]{64}$/.test(token) || !room?.linkTokenHashes?.has(hashCallToken(token))) {
      return setJson(res, 404, { error: "Anruf-Link ist ungültig oder abgelaufen" });
    }
    if (url.pathname.endsWith("/preview")) {
      if (room.participants.has(user.id)) return setJson(res, 409, { error: "Du bist bereits in diesem Anruf" });
      const activeCall = activeCallFor(user.id);
      if (activeCall && activeCall !== callId) return setJson(res, 409, { error: "Du bist bereits in einem anderen Anruf" });
      if (room.participants.size + room.invited.size >= 4 && !room.invited.has(user.id)) return setJson(res, 409, { error: "Dieser Anruf ist bereits voll" });
      setJson(res, 200, { hostId: room.hostId, video: room.video });
      return true;
    }
    if (room.participants.has(user.id)) return setJson(res, 409, { error: "Du bist bereits in diesem Anruf" });
    const activeCall = activeCallFor(user.id);
    if (activeCall && activeCall !== callId) return setJson(res, 409, { error: "Du bist bereits in einem anderen Anruf" });
    if (room.participants.size + room.invited.size >= 4 && !room.invited.has(user.id)) return setJson(res, 409, { error: "Dieser Anruf ist bereits voll" });
    room.invited.delete(user.id);
    room.participants.add(user.id);
    const participants = [...room.participants];
    for (const participantId of participants) {
      publish(participantId, { type: "call", from: user.id, payload: { type: "joined", callId, hostId: room.hostId, video: room.video, participants } });
    }
    setJson(res, 200, { hostId: room.hostId, video: room.video, participants });
    return true;
  }
  if (url.pathname === "/api/auth/logout" && req.method === "POST") {
    res.writeHead(200, { "Set-Cookie": `ts_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${req.socket.encrypted || process.env.COOKIE_SECURE === "true" ? "; Secure" : ""}`, "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
    return true;
  }
  if (url.pathname === "/api/contact" && req.method === "POST") {
    if (rateLimit(req, "contact", 5, 60 * 60 * 1000)) return setJson(res, 429, { error: "Zu viele Anfragen. Bitte später erneut versuchen." });
    const body = await readJson(req);
    if (isHoneypotFilled(body)) return setJson(res, 400, { error: "Anfrage konnte nicht verarbeitet werden" });
    const captcha = await verifyCaptcha(body.captchaToken, req);
    if (!captcha.ok) return setJson(res, captcha.status, { error: captcha.error });
    const name = String(body.name || "").trim();
    const subject = String(body.subject || "").trim();
    const project = String(body.project || "").trim();
    const message = String(body.message || "").trim();
    if (!name || name.length > 120 || !subject || subject.length > 200 || project.length > 100 || !message || message.length > 5000) return setJson(res, 400, { error: "Name, Betreff oder Nachricht fehlen oder sind zu lang" });
    const request = { id: uid("contact"), type: body.type === "exclusive-beat" ? "exclusive-beat" : "contact", name, subject, project, message, createdAt: new Date().toISOString(), read: false };
    store.contactRequests.push(request); save();
    for (const admin of store.users.filter(u => u.role === "admin")) publish(admin.id, { type: "contact-request", request });
    setJson(res, 201, { ok: true, request: { id: request.id } });
    return true;
  }
  const contactMatch = url.pathname.match(/^\/api\/contact\/([^/]+)$/);
  if (contactMatch && req.method === "DELETE") {
    const admin = requireAdmin(req, res); if (!admin) return true;
    const before = store.contactRequests.length;
    store.contactRequests = store.contactRequests.filter(request => request.id !== contactMatch[1]);
    if (store.contactRequests.length === before) return setJson(res, 404, { error: "Anfrage nicht gefunden" });
    save();
    for (const recipient of store.users.filter(user => user.role === "admin")) publish(recipient.id, { type: "contact-request-deleted", requestId: contactMatch[1] });
    setJson(res, 200, { ok: true });
    return true;
  }
  if (url.pathname === "/api/contact" && req.method === "GET") {
    const admin = requireAdmin(req, res); if (!admin) return true;
    setJson(res, 200, { requests: [...store.contactRequests].sort((a, b) => b.createdAt.localeCompare(a.createdAt)) });
    return true;
  }
  if (url.pathname === "/api/users" && req.method === "GET") {
    const user = requireUser(req, res); if (!user) return true;
    const users = user.role === "admin" ? store.users.filter(u => u.role === "member") : store.users.filter(u => u.id !== user.id);
    setJson(res, 200, { users: users.map(u => publicUser(u, user.role === "admin")) });
    return true;
  }
  if (url.pathname === "/api/profile" && req.method === "POST") {
    const user = requireUser(req, res); if (!user) return true;
    const body = await readJson(req);
    if (typeof body.avatar === "string") {
      if (body.avatar && (body.avatar.length > 1_400_000 || !/^data:image\/(?:png|jpeg|webp);base64,[A-Za-z0-9+/]+={0,2}$/.test(body.avatar))) return setJson(res, 400, { error: "Profilbild muss eine PNG-, JPG- oder WebP-Datei unter 1 MB sein" });
    }
    if (String(body.artist || "").trim()) user.artist = String(body.artist).trim().slice(0, 80);
    if (typeof body.avatar === "string") user.avatar = body.avatar;
    save(); setJson(res, 200, { user: publicUser(user) }); return true;
  }
  if (url.pathname === "/api/beats" && req.method === "GET") {
    setJson(res, 200, { beats: store.beats.map(safeBeat) }); return true;
  }
  if (url.pathname === "/api/beats" && req.method === "POST") {
    const admin = requireAdmin(req, res); if (!admin) return true;
    const body = await readJson(req);
    const name = String(body.name || "").trim();
    const cover = String(body.cover || "").trim();
    if (cover.length > 2000) return setJson(res, 400, { error: "Cover-URL ist zu lang" });
    if (!name || name.length > 120 || String(body.bpm || "").length > 3 || String(body.key || "").length > 20 || String(body.genre || "").length > 40) return setJson(res, 400, { error: "Beatdaten sind ungültig oder zu lang" });
    let coverUrl = "";
    if (cover) {
      try {
        const siteOrigin = process.env.PUBLIC_ORIGIN || `http://${req.headers.host || "localhost"}`;
        const parsedCover = new URL(cover, siteOrigin);
        const sameSite = parsedCover.origin === new URL(siteOrigin).origin;
        const approvedHost = parsedCover.origin === "https://images.unsplash.com";
        if (!sameSite && !approvedHost) throw new Error();
        coverUrl = parsedCover.href;
      } catch {
        return setJson(res, 400, { error: "Cover muss von dieser Website oder images.unsplash.com stammen" });
      }
    }
    const beat = { id: uid("beat"), name, bpm: String(body.bpm || "—"), key: String(body.key || "—"), genre: String(body.genre || "Other"), producer: "Twin Signal", cover: coverUrl, hasAudio: false, createdAt: new Date().toISOString() };
    store.beats.push(beat); save(); publish(admin.id, { type: "beat-update" }); setJson(res, 201, { beat: safeBeat(beat) }); return true;
  }
  const beatAudioMatch = url.pathname.match(/^\/api\/beats\/([^/]+)\/audio$/);
  if (beatAudioMatch && req.method === "POST") {
    const admin = requireAdmin(req, res); if (!admin) return true;
    const beat = store.beats.find(b => b.id === beatAudioMatch[1]);
    if (!beat) return setJson(res, 404, { error: "Beat nicht gefunden" });
    const mime = String(req.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
    const ext = audioInfo(mime);
    if (!ext) return setJson(res, 415, { error: "Nicht unterstütztes Audioformat" });
    const audio = await readRaw(req, 12 * 1024 * 1024);
    if (!audio.length || !hasAudioSignature(audio, mime)) return setJson(res, 400, { error: "Die Datei sieht nicht wie eine gültige Audiodatei aus" });
    const audioFile = `${beat.id}-${uid("audio")}.${ext}`;
    fs.writeFileSync(path.join(audioDir, audioFile), audio, { flag: "wx" });
    const previousAudioFile = beat.audioFile;
    const previousAudioMime = beat.audioMime;
    const previousHasAudio = beat.hasAudio;
    beat.audioFile = audioFile;
    beat.audioMime = mime;
    beat.hasAudio = true;
    try { save(); }
    catch (error) {
      beat.audioFile = previousAudioFile;
      if (previousAudioMime === undefined) delete beat.audioMime;
      else beat.audioMime = previousAudioMime;
      beat.hasAudio = previousHasAudio;
      removeAudioFile(audioFile);
      throw error;
    }
    if (previousAudioFile) {
      try { removeAudioFile(previousAudioFile); } catch (error) { console.error("Could not remove replaced audio file:", error); }
    }
    publish(admin.id, { type: "beat-update" });
    setJson(res, 201, { beat: safeBeat(beat) });
    return true;
  }
  if (beatAudioMatch && req.method === "GET") {
    if (rateLimit(req, "beat-audio", 30, 60 * 1000)) return setJson(res, 429, { error: "Zu viele Audiowiedergaben" });
    const beat = store.beats.find(b => b.id === beatAudioMatch[1]);
    if (!beat || !beat.audioFile) return setJson(res, 404, { error: "Keine Audiodatei für diesen Beat vorhanden" });
    const audioPath = path.join(audioDir, path.basename(beat.audioFile));
    fs.stat(audioPath, (error, stats) => {
      if (error || !stats.isFile()) { setJson(res, 404, { error: "Audiodatei nicht gefunden" }); return; }
      const range = req.headers.range;
      if (range) {
        const match = range.match(/^bytes=(\d*)-(\d*)$/);
        if (!match) { res.writeHead(416, { "Content-Range": `bytes */${stats.size}` }).end(); return; }
        let start = match[1] ? Number(match[1]) : 0;
        let end = match[2] ? Number(match[2]) : stats.size - 1;
        if (!match[1] && match[2]) {
          const suffixLength = Number(match[2]);
          if (!Number.isSafeInteger(suffixLength) || suffixLength <= 0) { res.writeHead(416, { "Content-Range": `bytes */${stats.size}` }).end(); return; }
          start = Math.max(0, stats.size - suffixLength);
          end = stats.size - 1;
        } else {
          end = Math.min(end, stats.size - 1);
        }
        if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || start > end || start >= stats.size) { res.writeHead(416, { "Content-Range": `bytes */${stats.size}` }).end(); return; }
        res.writeHead(206, { "Content-Type": beat.audioMime, "Content-Length": end - start + 1, "Content-Range": `bytes ${start}-${end}/${stats.size}`, "Accept-Ranges": "bytes", "Content-Disposition": "inline", "Cache-Control": "private, no-store" });
        fs.createReadStream(audioPath, { start, end }).pipe(res);
        return;
      }
      res.writeHead(200, { "Content-Type": beat.audioMime, "Content-Length": stats.size, "Accept-Ranges": "bytes", "Content-Disposition": "inline", "Cache-Control": "private, no-store" });
      fs.createReadStream(audioPath).pipe(res);
    });
    return true;
  }
  const beatMatch = url.pathname.match(/^\/api\/beats\/([^/]+)$/);
  if (beatMatch && req.method === "DELETE") {
    const admin = requireAdmin(req, res); if (!admin) return true;
    const removed = store.beats.find(b => b.id === beatMatch[1]);
    if (!removed) return setJson(res, 404, { error: "Beat nicht gefunden" });
    store.beats = store.beats.filter(b => b.id !== beatMatch[1]);
    save();
    try { removeAudioFile(removed.audioFile); } catch (error) { console.error("Could not remove deleted beat audio:", error); }
    setJson(res, 200, { ok: true }); return true;
  }
  if (url.pathname === "/api/messages" && req.method === "GET") {
    const user = requireUser(req, res); if (!user) return true;
    const withId = url.searchParams.get("with");
    if (!withId) return setJson(res, 400, { error: "Empfänger erforderlich" });
    const messages = store.messages.filter(m => (m.from === user.id && m.to === withId) || (m.from === withId && m.to === user.id)).sort((a, b) => a.createdAt.localeCompare(b.createdAt));
    setJson(res, 200, { messages }); return true;
  }
  if (url.pathname === "/api/messages" && req.method === "POST") {
    const user = requireUser(req, res); if (!user) return true;
    const body = await readJson(req);
    const text = String(body.text || "").trim();
    const to = String(body.to || "");
    if (!text || !to || text.length > 5000) return setJson(res, 400, { error: "Nachricht oder Empfänger ungültig" });
    if (!store.users.some(u => u.id === to)) return setJson(res, 404, { error: "Empfänger nicht gefunden" });
    const message = { id: uid("message"), from: user.id, to, text, createdAt: new Date().toISOString() };
    store.messages.push(message); save();
    publish(to, { type: "message", message }); publish(user.id, { type: "message", message });
    setJson(res, 201, { message }); return true;
  }
  if (url.pathname === "/api/messages" && req.method === "DELETE") {
    const admin = requireAdmin(req, res); if (!admin) return true;
    const memberId = url.searchParams.get("with");
    const member = store.users.find(user => user.id === memberId && user.role === "member");
    if (!member) return setJson(res, 404, { error: "Mitglied nicht gefunden" });
    const before = store.messages.length;
    store.messages = store.messages.filter(message => !(
      (message.from === admin.id && message.to === member.id) ||
      (message.from === member.id && message.to === admin.id)
    ));
    const deleted = before - store.messages.length;
    save();
    publish(admin.id, { type: "chat-deleted", withId: member.id });
    publish(member.id, { type: "chat-deleted", withId: admin.id });
    setJson(res, 200, { ok: true, deleted });
    return true;
  }
  if (url.pathname === "/api/signaling" && req.method === "POST") {
    const user = requireUser(req, res); if (!user) return true;
    const body = await readJson(req);
    const targetId = String(body.to || "");
    const payload = body.payload;
    const target = store.users.find(member => member.id === targetId);
    if (!target || !payload || typeof payload !== "object" || Array.isArray(payload) || JSON.stringify(payload).length > 100_000) return setJson(res, 400, { error: "Ungültiges Call-Signal" });
    const callId = String(payload.callId || "");
    if (!/^[\w-]{16,80}$/.test(callId)) return setJson(res, 400, { error: "Ungültige Anruf-ID" });
    const room = callRooms.get(callId);
    const sendCall = (recipient, signal) => publish(recipient, { type: "call", payload: signal, from: user.id });

    if (payload.type === "start") {
      if (targetId === user.id || ![true, false].includes(payload.video)) return setJson(res, 400, { error: "Anruf kann nicht gestartet werden" });
      if (room || activeCallFor(user.id) || activeCallFor(targetId)) return setJson(res, 409, { error: "Ein Teilnehmer ist bereits in einem Anruf" });
      callRooms.set(callId, { hostId: user.id, video: payload.video, participants: new Set([user.id]), invited: new Set([targetId]), linkTokenHashes: new Set() });
      sendCall(targetId, { type: "invite", callId, hostId: user.id, video: payload.video });
      return setJson(res, 200, { ok: true });
    }

    if (payload.type === "invite") {
      if (!room) return setJson(res, 404, { error: "Anruf nicht gefunden" });
      if (!room.participants.has(user.id)) return setJson(res, 403, { error: "Du bist nicht Teil dieses Anrufs" });
      if (room.participants.has(targetId) || room.invited.has(targetId)) return setJson(res, 409, { error: "Dieses Mitglied ist bereits im Anruf oder eingeladen" });
      if (activeCallFor(targetId)) return setJson(res, 409, { error: "Dieses Mitglied ist bereits in einem Anruf" });
      if (room.participants.size + room.invited.size >= 4) return setJson(res, 409, { error: "Ein Anruf ist auf vier Personen begrenzt" });
      room.invited.add(targetId);
      sendCall(targetId, { type: "invite", callId, hostId: room.hostId, video: room.video });
      return setJson(res, 200, { ok: true });
    }

    if (payload.type === "join") {
      if (!room) return setJson(res, 404, { error: "Anruf nicht gefunden" });
      if (targetId !== room.hostId || !room.invited.has(user.id)) return setJson(res, 403, { error: "Keine Einladung für diesen Anruf" });
      if ([...callRooms].some(([otherCallId, otherRoom]) => otherCallId !== callId && (otherRoom.participants.has(user.id) || otherRoom.invited.has(user.id)))) return setJson(res, 409, { error: "Du bist bereits in einem anderen Anruf" });
      if (room.participants.size >= 4) return setJson(res, 409, { error: "Ein Anruf ist auf vier Personen begrenzt" });
      room.invited.delete(user.id);
      room.participants.add(user.id);
      const participants = [...room.participants];
      for (const participantId of participants) sendCall(participantId, { type: "joined", callId, hostId: room.hostId, video: room.video, participants });
      return setJson(res, 200, { ok: true, hostId: room.hostId, video: room.video, participants });
    }

    if (payload.type === "decline") {
      if (!room || targetId !== room.hostId || !room.invited.delete(user.id)) return setJson(res, 404, { error: "Einladung nicht gefunden" });
      for (const participantId of room.participants) sendCall(participantId, { type: "declined", callId, userId: user.id });
      return setJson(res, 200, { ok: true });
    }

    if (payload.type === "offer" || payload.type === "answer" || payload.type === "ice") {
      if (!room || payload.callId !== callId || !room.participants.has(user.id) || !room.participants.has(targetId) || targetId === user.id) return setJson(res, 403, { error: "Keine Berechtigung für dieses Anrufsignal" });
      if (payload.type === "offer" || payload.type === "answer") {
        if (!payload.sdp || typeof payload.sdp !== "object") return setJson(res, 400, { error: "Ungültige Anrufbeschreibung" });
      } else if (!payload.candidate || typeof payload.candidate !== "object") return setJson(res, 400, { error: "Ungültiger ICE-Kandidat" });
      sendCall(targetId, payload);
      return setJson(res, 200, { ok: true });
    }

    if (payload.type === "kick") {
      if (!room || user.id !== room.hostId || targetId === room.hostId || !room.participants.has(targetId)) return setJson(res, 403, { error: "Teilnehmer kann nicht entfernt werden" });
      room.participants.delete(targetId);
      room.linkTokenHashes?.clear();
      publish(targetId, { type: "call", from: user.id, payload: { type: "removed", callId, hostId: room.hostId } });
      for (const participantId of room.participants) sendCall(participantId, { type: "left", callId, userId: targetId });
      for (const participantId of room.participants) sendCall(participantId, { type: "links-revoked", callId });
      return setJson(res, 200, { ok: true });
    }

    if (payload.type === "leave" || payload.type === "end") {
      if (!room || !room.participants.has(user.id)) return setJson(res, 404, { error: "Anruf nicht gefunden" });
      if (payload.type === "end" && user.id !== room.hostId) return setJson(res, 403, { error: "Nur der Anruf-Host kann den Anruf beenden" });
      if (payload.type === "end" || user.id === room.hostId) {
        for (const participantId of new Set([...room.participants, ...room.invited])) {
          if (participantId !== user.id) publish(participantId, { type: "call", from: user.id, payload: { type: "ended", callId } });
        }
        callRooms.delete(callId);
      } else {
        room.participants.delete(user.id);
        for (const participantId of room.participants) sendCall(participantId, { type: "left", callId, userId: user.id });
      }
      return setJson(res, 200, { ok: true });
    }

    return setJson(res, 400, { error: "Unbekannter Anrufvorgang" });
  }
  if (url.pathname === "/api/events" && req.method === "GET") {
    const user = currentUser(req);
    if (!user) { res.writeHead(401).end(); return true; }
    res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", "Connection": "keep-alive" });
    res.write(": connected\n\n");
    const send = payload => res.write(`data: ${JSON.stringify(payload)}\n\n`);
    const set = eventClients.get(user.id) || new Set(); set.add(send); eventClients.set(user.id, set);
    for (const [callId, room] of callRooms) {
      if (room.invited.has(user.id)) send({ type: "call", from: room.hostId, payload: { type: "invite", callId, hostId: room.hostId, video: room.video } });
    }
    req.on("close", () => {
      set.delete(send);
      if (!set.size) {
        eventClients.delete(user.id);
        disconnectCallUser(user.id);
      }
    });
    return true;
  }
  return false;
}

const mime = { ".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp" };
const server = http.createServer(async (req, res) => {
  try {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    res.setHeader("Permissions-Policy", "camera=(self), microphone=(self), geolocation=()");
    res.setHeader("Content-Security-Policy", "default-src 'self'; base-uri 'self'; object-src 'none'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: https://images.unsplash.com; connect-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; media-src 'self' blob:; frame-ancestors 'none'; form-action 'self' https://buy.stripe.com");
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method) && req.headers.origin) {
      try {
        const requestOrigin = new URL(req.headers.origin);
        const expectedOrigin = publicOrigin ? new URL(publicOrigin).origin : "";
        const matchesOrigin = expectedOrigin ? requestOrigin.origin === expectedOrigin : requestOrigin.host === req.headers.host;
        if (!matchesOrigin) return setJson(res, 403, { error: "Cross-origin request rejected" });
      } catch {
        return setJson(res, 403, { error: "Invalid request origin" });
      }
    }
    if (await api(req, res, url)) return;
    let pathname = decodeURIComponent(url.pathname);
    if (pathname === "/") pathname = "/index.html";
    if (pathname !== "/index.html" && pathname !== "/favicon.svg" && !(pathname.startsWith("/IMG/") && !pathname.slice(5).includes("/") && [".jpg", ".jpeg", ".png", ".webp"].includes(path.extname(pathname).toLowerCase()))) return setJson(res, 404, { error: "Not found" });
    const file = path.resolve(__dirname, `.${pathname}`);
    const relative = path.relative(__dirname, file);
    if (relative.startsWith("..") || path.isAbsolute(relative)) return setJson(res, 403, { error: "Forbidden" });
    fs.readFile(file, (error, content) => {
      if (res.headersSent) return;
      if (error) { res.writeHead(404); res.end("Not found"); return; }
      res.writeHead(200, { "Content-Type": mime[path.extname(file)] || "application/octet-stream" });
      res.end(content);
    });
  } catch (error) {
    console.error(error);
    if (!res.headersSent) setJson(res, error.message === "Request too large" || error.message === "Audio file is too large" ? 413 : error.message === "Invalid JSON" ? 400 : 500, { error: error.message === "Request too large" || error.message === "Audio file is too large" ? "Anfrage ist zu groß" : error.message === "Invalid JSON" ? "Ungültige JSON-Anfrage" : "Serverfehler" });
  }
});
server.listen(port, "0.0.0.0", () => console.log(`Twin Signal running at http://localhost:${port}`));
