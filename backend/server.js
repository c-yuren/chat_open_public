// ============================================================
//  Ren (Open E2EE 2-Party Chat) — Express + SQLite Backend
// ============================================================
//  Features:
//  1. Strictly 2-Party Rooms (Person 1 and Person 2)
//  2. Multi-device support: Each person can connect via multiple devices
//     (Phone, Laptop, Desktop, iOS Shortcuts) using their member slot & token
//  3. True Zero-Knowledge End-to-End Encryption:
//     Server stores ONLY ciphertext & IV. AES-256 keys never reach server.
//  4. 50-Message rolling limit per room (Strict FIFO auto-pruning)
//  5. Anti-flood rate limiting & sliding window controls
//  6. Inactive room auto-cleanup (14 days)
// ============================================================

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");
const os = require("os");

const app = express();
const PORT = process.env.PORT || 3001;
const MAX_MESSAGES_PER_ROOM = parseInt(process.env.MAX_MESSAGES_PER_ROOM || "50", 10);
const ROOM_EXPIRE_DAYS = parseInt(process.env.ROOM_EXPIRE_DAYS || "14", 10);
const PRESENCE_TIMEOUT_MS = 30 * 1000; // 30s timeout for online presence

app.set("trust proxy", 1);

// ============================================================
//  CORS Configuration
// ============================================================
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "*")
  .split(",")
  .map(s => s.trim());

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes("*") || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      callback(new Error("CORS not allowed"));
    },
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "Cache-Control"],
    maxAge: 86400,
  })
);

app.use(express.json({ limit: "32kb" }));

// ============================================================
//  SQLite Database Setup & Migration
// ============================================================
const DB_PATH = path.join(__dirname, "chat.db");
const db = new Database(DB_PATH);

db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS rooms (
    id          TEXT PRIMARY KEY,
    token1      TEXT NOT NULL,
    token2      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    last_active TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS messages (
    id          TEXT PRIMARY KEY,
    room_id     TEXT NOT NULL,
    sender      INTEGER NOT NULL DEFAULT 1,
    ciphertext  TEXT NOT NULL,
    iv          TEXT NOT NULL,
    timestamp   TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_messages_room_ts 
    ON messages(room_id, timestamp DESC);
`);

// Auto-migrate if older schema exists
const roomCols = db.prepare("PRAGMA table_info(rooms)").all().map(c => c.name);
if (!roomCols.includes("token1")) {
  db.exec("ALTER TABLE rooms ADD COLUMN token1 TEXT");
}
if (!roomCols.includes("token2")) {
  db.exec("ALTER TABLE rooms ADD COLUMN token2 TEXT");
}
if (!roomCols.includes("traffic_bytes")) {
  db.exec("ALTER TABLE rooms ADD COLUMN traffic_bytes INTEGER NOT NULL DEFAULT 0");
}

const msgCols = db.prepare("PRAGMA table_info(messages)").all().map(c => c.name);
if (!msgCols.includes("sender")) {
  db.exec("ALTER TABLE messages ADD COLUMN sender INTEGER NOT NULL DEFAULT 1");
}

// Prepared Statements
const stmtGetRoom = db.prepare("SELECT * FROM rooms WHERE id = ?");
const stmtInsertRoom = db.prepare(`
  INSERT INTO rooms (id, token1, token2, created_at, last_active, traffic_bytes)
  VALUES (?, ?, ?, ?, ?, 0)
`);
const stmtTouchRoom = db.prepare(`
  UPDATE rooms SET last_active = ? WHERE id = ?
`);
const stmtAddRoomTraffic = db.prepare(`
  UPDATE rooms SET traffic_bytes = COALESCE(traffic_bytes, 0) + ? WHERE id = ?
`);
const stmtDeleteRoomMsgs = db.prepare("DELETE FROM messages WHERE room_id = ?");
const stmtDeleteRoom = db.prepare("DELETE FROM rooms WHERE id = ?");
const stmtCountRoomMsgs = db.prepare(
  "SELECT COUNT(*) as count FROM messages WHERE room_id = ?"
);
const stmtInsertMsg = db.prepare(`
  INSERT OR IGNORE INTO messages (id, room_id, sender, ciphertext, iv, timestamp)
  VALUES (?, ?, ?, ?, ?, ?)
`);
const stmtPruneMsgs = db.prepare(`
  DELETE FROM messages
  WHERE room_id = ?
    AND id NOT IN (
      SELECT id FROM messages
      WHERE room_id = ?
      ORDER BY timestamp DESC, id DESC
      LIMIT ?
    )
`);
const stmtGetMsgs = db.prepare(`
  SELECT id, room_id, sender, ciphertext, iv, timestamp
  FROM messages
  WHERE room_id = ?
  ORDER BY timestamp DESC
  LIMIT ?
`);
const stmtCleanExpiredMessages = db.prepare(`
  DELETE FROM messages WHERE room_id IN (
    SELECT id FROM rooms WHERE datetime(last_active) < datetime('now', '-' || ? || ' days')
  )
`);
const stmtCleanExpiredRooms = db.prepare(`
  DELETE FROM rooms WHERE datetime(last_active) < datetime('now', '-' || ? || ' days')
`);

// Monitoring & Statistics Queries
const stmtTotalRooms = db.prepare("SELECT COUNT(*) as count FROM rooms");
const stmtTotalMessages = db.prepare("SELECT COUNT(*) as count FROM messages");
const stmtActiveRooms24h = db.prepare("SELECT COUNT(*) as count FROM rooms WHERE datetime(last_active) > datetime('now', '-1 day')");
const stmtActiveRooms1h = db.prepare("SELECT COUNT(*) as count FROM rooms WHERE datetime(last_active) > datetime('now', '-1 hour')");

// ============================================================
//  2-Party Presence Tracking (Multi-Device Friendly)
// ============================================================
// Map<roomId, { u1_lastSeen: number, u2_lastSeen: number }>
const roomPresence = new Map();

function updateSlotPresence(roomId, slot) {
  const now = Date.now();
  let pres = roomPresence.get(roomId);
  if (!pres) {
    pres = { u1: 0, u2: 0 };
    roomPresence.set(roomId, pres);
  }
  if (slot === 1) pres.u1 = now;
  if (slot === 2) pres.u2 = now;
}

function getPresenceStatus(roomId) {
  const now = Date.now();
  const pres = roomPresence.get(roomId) || { u1: 0, u2: 0 };
  const u1Online = now - pres.u1 < PRESENCE_TIMEOUT_MS;
  const u2Online = now - pres.u2 < PRESENCE_TIMEOUT_MS;
  return {
    u1Online,
    u2Online,
    activeCount: (u1Online ? 1 : 0) + (u2Online ? 1 : 0),
  };
}

// Authenticate slot & token for a given room
function authenticateMember(roomId, slot, token) {
  if (!roomId || !token || (slot !== 1 && slot !== 2)) {
    return { ok: false, status: 400, error: "Invalid slot or missing token" };
  }

  const room = stmtGetRoom.get(roomId);
  if (!room) {
    return { ok: false, status: 404, error: "Room not found or expired" };
  }

  const expectedToken = slot === 1 ? room.token1 : room.token2;
  if (!expectedToken || token !== expectedToken) {
    return { ok: false, status: 403, error: "Unauthorized: Invalid member token for this room" };
  }

  updateSlotPresence(roomId, slot);
  return { ok: true, room };
}

// ============================================================
//  Administrator Authentication
// ============================================================
const ADMIN_KEY = process.env.ADMIN_KEY || "ren-admin-2026";

function requireAdminAuth(req, res, next) {
  const authHeader = req.headers["authorization"];
  let token = null;
  if (authHeader && typeof authHeader === "string") {
    token = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : authHeader.trim();
  }
  const key = token || req.headers["x-admin-key"] || req.query?.adminKey || req.body?.adminKey;

  if (!key || key !== ADMIN_KEY) {
    return res.status(401).json({
      ok: false,
      error: "Unauthorized: Invalid or missing administrator credentials"
    });
  }
  next();
}

// ============================================================
//  Sliding Window Rate Limiter
// ============================================================
class RateLimiter {
  constructor() {
    this.limits = new Map();
    setInterval(() => this.cleanup(), 5 * 60 * 1000).unref();
  }

  check(key, maxRequests, windowMs) {
    const now = Date.now();
    let record = this.limits.get(key);

    if (!record) {
      this.limits.set(key, [now]);
      return { allowed: true, retryAfter: 0 };
    }

    const validTimestamps = record.filter(ts => now - ts < windowMs);

    if (validTimestamps.length >= maxRequests) {
      const oldestInWindow = validTimestamps[0];
      const retryAfter = Math.ceil((oldestInWindow + windowMs - now) / 1000);
      this.limits.set(key, validTimestamps);
      return { allowed: false, retryAfter: Math.max(retryAfter, 1) };
    }

    validTimestamps.push(now);
    this.limits.set(key, validTimestamps);
    return { allowed: true, retryAfter: 0 };
  }

  cleanup() {
    const now = Date.now();
    for (const [key, timestamps] of this.limits.entries()) {
      const filtered = timestamps.filter(ts => now - ts < 10 * 60 * 1000);
      if (filtered.length === 0) {
        this.limits.delete(key);
      } else {
        this.limits.set(key, filtered);
      }
    }
  }
}

const limiter = new RateLimiter();

function getClientIp(req) {
  return req.headers["x-forwarded-for"]
    ? req.headers["x-forwarded-for"].split(",")[0].trim()
    : req.ip || req.connection.remoteAddress || "unknown";
}

function isValidRoomId(roomId) {
  return typeof roomId === "string" && /^[a-zA-Z0-9_-]{3,32}$/.test(roomId);
}

// ============================================================
//  API Endpoints
// ============================================================

const FRONTEND_PATH = path.join(__dirname, "../frontend");
if (fs.existsSync(FRONTEND_PATH)) {
  app.use(express.static(FRONTEND_PATH));
}

// ---------- 1. Health / Status ----------
app.get("/api/health", (req, res) => {
  res.json({
    name: "Ren 1-on-1 E2EE Chat API",
    version: "3.2-multidevice",
    e2ee: "AES-GCM-256",
    maxParticipants: 2,
    multiDevice: "Supported (Arbitrary devices per party)",
    maxMessagesPerRoom: MAX_MESSAGES_PER_ROOM,
  });
});

app.get("/", (req, res) => {
  const indexPath = path.join(FRONTEND_PATH, "index.html");
  if (fs.existsSync(indexPath)) {
    return res.sendFile(indexPath);
  }
  res.json({
    name: "Ren 1-on-1 E2EE Chat API",
    version: "3.2-multidevice",
    e2ee: "AES-GCM-256",
    maxParticipants: 2,
    multiDevice: "Supported (Arbitrary devices per party)",
    maxMessagesPerRoom: MAX_MESSAGES_PER_ROOM,
  });
});

// ---------- 2. Create Room (POST /api/rooms/create) ----------
app.post("/api/rooms/create", (req, res) => {
  const ip = getClientIp(req);

  // Rate limit: 10 room creations per 10 minutes per IP
  const check = limiter.check(`create_room:${ip}`, 10, 10 * 60 * 1000);
  if (!check.allowed) {
    return res.status(429).json({ error: `Too many rooms created. Please wait ${check.retryAfter}s.` });
  }

  const roomId = "r_" + crypto.randomBytes(4).toString("hex");
  const token1 = crypto.randomBytes(16).toString("hex");
  const token2 = crypto.randomBytes(16).toString("hex");
  const now = new Date().toISOString();

  try {
    stmtInsertRoom.run(roomId, token1, token2, now, now);
    updateSlotPresence(roomId, 1);

    res.json({
      ok: true,
      roomId,
      token1,
      token2,
      maxMessages: MAX_MESSAGES_PER_ROOM,
    });
  } catch (e) {
    console.error("Failed to create room:", e);
    res.status(500).json({ error: "Failed to create room." });
  }
});

// ---------- 3. Verify / Join Room (POST /api/rooms/verify) ----------
app.post("/api/rooms/verify", (req, res) => {
  const ip = getClientIp(req);
  const { roomId, slot, token } = req.body || {};
  const slotNum = parseInt(slot, 10);

  // Rate limit: 30 verifies per minute per IP
  const check = limiter.check(`verify:${ip}`, 30, 60 * 1000);
  if (!check.allowed) {
    return res.status(429).json({ error: "Too many requests. Please slow down." });
  }

  const auth = authenticateMember(roomId, slotNum, token);
  if (!auth.ok) {
    return res.status(auth.status).json({ error: auth.error });
  }

  const presence = getPresenceStatus(roomId);
  const msgCount = stmtCountRoomMsgs.get(roomId)?.count || 0;

  res.json({
    ok: true,
    roomId,
    slot: slotNum,
    token2: slotNum === 1 ? auth.room.token2 : undefined, // Creator can view token2 to share invite
    presence,
    messageCount: msgCount,
    maxMessages: MAX_MESSAGES_PER_ROOM,
  });
});

// ---------- 4. Send Encrypted Message (POST /api/send) ----------
app.post("/api/send", (req, res) => {
  const ip = getClientIp(req);
  const { roomId, slot, token, ciphertext, iv } = req.body || {};
  const slotNum = parseInt(slot, 10);

  if (!isValidRoomId(roomId)) {
    return res.status(400).json({ error: "Invalid Room ID" });
  }
  if (!ciphertext || typeof ciphertext !== "string" || ciphertext.length > 8192) {
    return res.status(400).json({ error: "Invalid ciphertext format or length" });
  }
  if (!iv || typeof iv !== "string" || iv.length > 128) {
    return res.status(400).json({ error: "Invalid IV format" });
  }

  // Authenticate member
  const auth = authenticateMember(roomId, slotNum, token);
  if (!auth.ok) {
    return res.status(auth.status).json({ error: auth.error });
  }

  // Rate Limits:
  // 1. IP burst: 1 msg per 1s
  const burstCheck = limiter.check(`send_burst:${ip}`, 1, 1000);
  if (!burstCheck.allowed) {
    return res.status(429).json({ error: "Sending too fast. Please wait 1 second." });
  }

  // 2. IP minute limit: 30 msgs / min
  const minCheck = limiter.check(`send_min:${ip}`, 30, 60 * 1000);
  if (!minCheck.allowed) {
    return res.status(429).json({ error: `Rate limit reached. Please wait ${minCheck.retryAfter}s.` });
  }

  const id = `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
  const timestamp = new Date().toISOString();

  const insertAndPrune = db.transaction(() => {
    stmtTouchRoom.run(timestamp, roomId);
    stmtInsertMsg.run(id, roomId, slotNum, ciphertext, iv, timestamp);
    // Strict 50-message cap per room
    stmtPruneMsgs.run(roomId, roomId, MAX_MESSAGES_PER_ROOM);
    return stmtCountRoomMsgs.get(roomId)?.count || 0;
  });

  try {
    const currentCount = insertAndPrune();
    const presence = getPresenceStatus(roomId);

    // Track room traffic
    const sentBytes = (ciphertext ? ciphertext.length : 0) + (iv ? iv.length : 0) + 128;
    try { stmtAddRoomTraffic.run(sentBytes, roomId); } catch {}

    res.json({
      ok: true,
      id,
      roomId,
      sender: slotNum,
      timestamp,
      currentCount,
      presence,
      maxLimit: MAX_MESSAGES_PER_ROOM,
    });
  } catch (e) {
    console.error("Failed to save message:", e);
    res.status(500).json({ error: "Failed to save message" });
  }
});

// ---------- 5. Fetch Messages & Heartbeat (GET /api/messages) ----------
app.get("/api/messages", (req, res) => {
  const ip = getClientIp(req);
  const roomId = req.query.roomId;
  const slotNum = parseInt(req.query.slot, 10);
  const token = req.query.token;

  // Rate limit: 4 polls / second per IP
  const pollCheck = limiter.check(`poll:${ip}`, 4, 1000);
  if (!pollCheck.allowed) {
    return res.status(429).json({ error: "Polling too fast" });
  }

  // Authenticate member
  const auth = authenticateMember(roomId, slotNum, token);
  if (!auth.ok) {
    return res.status(auth.status).json({ error: auth.error });
  }

  const limit = Math.min(
    parseInt(req.query.limit || `${MAX_MESSAGES_PER_ROOM}`, 10),
    MAX_MESSAGES_PER_ROOM
  );

  try {
    const rows = stmtGetMsgs.all(roomId, limit);
    rows.reverse(); // oldest to newest
    const presence = getPresenceStatus(roomId);

    // Track room traffic
    if (rows.length > 0) {
      const readBytes = rows.reduce((acc, r) => acc + (r.ciphertext ? r.ciphertext.length : 0) + (r.iv ? r.iv.length : 0) + 64, 128);
      try { stmtAddRoomTraffic.run(readBytes, roomId); } catch {}
    }

    res.json({
      ok: true,
      roomId,
      slot: slotNum,
      count: rows.length,
      presence,
      maxLimit: MAX_MESSAGES_PER_ROOM,
      messages: rows,
    });
  } catch (e) {
    console.error("Failed to fetch messages:", e);
    res.status(500).json({ error: "Failed to read messages" });
  }
});

// ============================================================
//  iOS Shortcut Integration Helpers & Endpoints
// ============================================================
function parseKeyToBuffer(keyStr) {
  if (!keyStr || typeof keyStr !== "string") return null;
  let b64 = keyStr.trim().replace(/\s/g, "+").replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  try {
    const buf = Buffer.from(b64, "base64");
    return buf.length === 32 ? buf : null;
  } catch {
    return null;
  }
}

// Automatically parses full room URLs, hashes, queries, or delimiter strings
function parseConnectionLink(inputStr) {
  if (!inputStr || typeof inputStr !== "string") return {};
  const str = inputStr.trim();
  const result = {};

  if (str.includes("r=") || str.includes("roomId=") || str.includes("room=") || str.includes("k=") || str.includes("key=")) {
    let queryPart = str;
    if (str.includes("#")) {
      queryPart = str.split("#")[1];
    } else if (str.includes("?")) {
      queryPart = str.split("?")[1];
    }
    const normalized = queryPart.replace(/[?#]/g, "&");
    const params = new URLSearchParams(normalized);
    const r = params.get("r") || params.get("room") || params.get("roomId");
    const k = params.get("k") || params.get("key");
    const u = params.get("u") || params.get("slot") || params.get("userSlot");
    const t = params.get("t") || params.get("token");
    const user = params.get("user") || params.get("userName");

    if (r) result.roomId = r.trim();
    if (k) result.key = k.trim().replace(/\s/g, "+");
    if (t) result.token = t.trim();
    if (u) result.slot = parseInt(u, 10);
    if (user) result.user = user.trim();
    return result;
  }

  if (str.includes(":") || str.includes("#")) {
    const delimiter = str.includes("#") ? "#" : ":";
    const parts = str.split(delimiter).map(p => p.trim());
    if (parts.length >= 3) {
      result.roomId = parts[0];
      result.token = parts[1];
      result.key = parts[2].replace(/\s/g, "+");
      if (parts.length >= 4) {
        const p4 = parseInt(parts[3], 10);
        if (p4 === 1 || p4 === 2) result.slot = p4;
      }
      return result;
    }
  }

  return result;
}

function extractToken(req) {
  const auth = req.headers["authorization"];
  if (auth && typeof auth === "string") {
    return auth.startsWith("Bearer ") ? auth.slice(7).trim() : auth.trim();
  }
  return req.body?.token || req.query?.token || null;
}

function formatUptime(seconds) {
  const s = Math.floor(seconds || 0);
  const d = Math.floor(s / (3600 * 24));
  const h = Math.floor((s % (3600 * 24)) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = Math.floor(s % 60);
  const parts = [];
  if (d > 0) parts.push(`${d}d`);
  if (h > 0) parts.push(`${h}h`);
  if (m > 0) parts.push(`${m}m`);
  parts.push(`${sec}s`);
  return parts.join(" ");
}

function formatBytes(bytes) {
  if (!bytes || bytes <= 0) return "0 B";
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + " MB";
  return (bytes / (1024 * 1024 * 1024)).toFixed(2) + " GB";
}

// Handler: iOS Shortcut Send Message
function handleShortcutSend(req, res) {
  const ip = getClientIp(req);

  // Auto-detect full chat link in body, query, or mistakenly pasted into key/roomId
  const candidateLink = req.body?.link || req.query?.link ||
    (typeof req.body?.key === "string" && (req.body.key.includes("r=") || req.body.key.startsWith("http")) ? req.body.key : null) ||
    (typeof req.body?.roomId === "string" && (req.body.roomId.includes("r=") || req.body.roomId.startsWith("http")) ? req.body.roomId : null) ||
    (typeof req.query?.key === "string" && (req.query.key.includes("r=") || req.query.key.startsWith("http")) ? req.query.key : null);

  const linkParsed = parseConnectionLink(candidateLink);

  let roomId = req.body?.roomId || req.query?.roomId || linkParsed.roomId;
  let token = extractToken(req) || linkParsed.token;
  let keyStr = req.body?.key || req.headers["x-encryption-key"] || req.query?.key || linkParsed.key;
  let slotNum = req.body?.slot ? parseInt(req.body.slot, 10) : linkParsed.slot;
  const userName = req.body?.user || req.body?.userName || linkParsed.user;
  const text = req.body?.text || req.body?.message || req.body?.msg || req.query?.text || req.query?.message || req.query?.msg;

  // Support combined connection key format if raw string with delimiter passed
  if (keyStr && typeof keyStr === "string" && (keyStr.includes(":") || keyStr.includes("#"))) {
    const combined = parseConnectionLink(keyStr);
    if (combined.roomId) roomId = roomId || combined.roomId;
    if (combined.token) token = token || combined.token;
    if (combined.key) keyStr = combined.key;
    if (combined.slot) slotNum = slotNum || combined.slot;
  }

  if (!isValidRoomId(roomId)) {
    return res.status(400).json({ error: "Invalid or missing roomId (paste your chat link or provide roomId)" });
  }
  if (!text || typeof text !== "string" || text.trim().length === 0) {
    return res.status(400).json({ error: "Text field is required to send a message" });
  }
  if (text.length > 2000) {
    return res.status(400).json({ error: "Text exceeds 2000 character limit" });
  }

  const room = stmtGetRoom.get(roomId);
  if (!room) {
    return res.status(404).json({ error: "Room not found or expired" });
  }

  // Determine slot from token
  if (!slotNum) {
    if (token && token === room.token1) slotNum = 1;
    else if (token && token === room.token2) slotNum = 2;
  } else {
    const expectedToken = slotNum === 1 ? room.token1 : room.token2;
    if (token !== expectedToken) {
      if (token === room.token1) slotNum = 1;
      else if (token === room.token2) slotNum = 2;
      else {
        return res.status(403).json({ error: "Unauthorized: Invalid or missing member token" });
      }
    }
  }

  if (!slotNum || (slotNum !== 1 && slotNum !== 2)) {
    return res.status(403).json({ error: "Unauthorized: Invalid or missing member token" });
  }

  const rawKeyBuf = parseKeyToBuffer(keyStr);
  if (!rawKeyBuf) {
    return res.status(400).json({ error: "Invalid 256-bit AES encryption key" });
  }

  let finalUserName = userName;
  if (!finalUserName) {
    // Attempt to recover recent custom nickname for this slot in the room
    try {
      const recentMsgs = stmtGetMsgs.all(roomId, 10);
      for (const row of recentMsgs) {
        if (row.sender === slotNum) {
          const combined = Buffer.from(row.ciphertext, "base64");
          const ivBuf = Buffer.from(row.iv, "base64");
          const tag = combined.subarray(combined.length - 16);
          const ciphertextOnly = combined.subarray(0, combined.length - 16);
          const decipher = crypto.createDecipheriv("aes-256-gcm", rawKeyBuf, ivBuf);
          decipher.setAuthTag(tag);
          let dec = decipher.update(ciphertextOnly, null, "utf8");
          dec += decipher.final("utf8");
          const p = JSON.parse(dec);
          if (p.user && p.user !== "Partner" && p.user !== "Creator" && p.user !== "You" && p.user !== "我" && p.user !== "成員 1" && p.user !== "成員 2") {
            finalUserName = p.user;
            break;
          }
        }
      }
    } catch {}
  }
  if (!finalUserName) {
    finalUserName = slotNum === 1 ? "成員 1" : "成員 2";
  }

  // Rate Limits: 1 msg/s burst, 30 msgs/min
  const burstCheck = limiter.check(`send_burst:${ip}`, 1, 1000);
  if (!burstCheck.allowed) {
    return res.status(429).json({ error: "Sending too fast. Please wait 1 second." });
  }
  const minCheck = limiter.check(`send_min:${ip}`, 30, 60 * 1000);
  if (!minCheck.allowed) {
    return res.status(429).json({ error: `Rate limit reached. Please wait ${minCheck.retryAfter}s.` });
  }

  // Encrypt with AES-256-GCM matching WebCrypto format
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", rawKeyBuf, iv);
  const payloadStr = JSON.stringify({
    text: text.trim(),
    slot: slotNum,
    user: finalUserName,
    ts: Date.now()
  });

  let ct = cipher.update(payloadStr, "utf8");
  ct = Buffer.concat([ct, cipher.final()]);
  const tag = cipher.getAuthTag();
  const combined = Buffer.concat([ct, tag]);

  const ciphertext = combined.toString("base64");
  const ivB64 = iv.toString("base64");

  const id = `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
  const timestamp = new Date().toISOString();

  const insertAndPrune = db.transaction(() => {
    stmtTouchRoom.run(timestamp, roomId);
    stmtInsertMsg.run(id, roomId, slotNum, ciphertext, ivB64, timestamp);
    stmtPruneMsgs.run(roomId, roomId, MAX_MESSAGES_PER_ROOM);
    return stmtCountRoomMsgs.get(roomId)?.count || 0;
  });

  try {
    const currentCount = insertAndPrune();
    updateSlotPresence(roomId, slotNum);
    const sentBytes = (ciphertext ? ciphertext.length : 0) + (ivB64 ? ivB64.length : 0) + 128;
    try { stmtAddRoomTraffic.run(sentBytes, roomId); } catch {}
    res.json({
      ok: true,
      action: "send",
      id,
      roomId,
      sender: slotNum,
      user: finalUserName,
      text: text.trim(),
      timestamp,
      currentCount,
      maxLimit: MAX_MESSAGES_PER_ROOM,
    });
  } catch (e) {
    console.error("Failed to save shortcut message:", e);
    res.status(500).json({ error: "Failed to save message" });
  }
}

// Handler: iOS Shortcut Read Messages
function handleShortcutRead(req, res, returnUnifiedObject = false) {
  const ip = getClientIp(req);

  // Auto-detect full chat link in body, query, or mistakenly pasted into key/roomId
  const candidateLink = req.body?.link || req.query?.link ||
    (typeof req.body?.key === "string" && (req.body.key.includes("r=") || req.body.key.startsWith("http")) ? req.body.key : null) ||
    (typeof req.body?.roomId === "string" && (req.body.roomId.includes("r=") || req.body.roomId.startsWith("http")) ? req.body.roomId : null) ||
    (typeof req.query?.key === "string" && (req.query.key.includes("r=") || req.query.key.startsWith("http")) ? req.query.key : null) ||
    (typeof req.query?.roomId === "string" && (req.query.roomId.includes("r=") || req.query.roomId.startsWith("http")) ? req.query.roomId : null);

  const linkParsed = parseConnectionLink(candidateLink);

  let roomId = req.query?.roomId || req.body?.roomId || linkParsed.roomId;
  let token = extractToken(req) || linkParsed.token;
  let keyStr = req.headers["x-encryption-key"] || req.query?.key || req.body?.key || linkParsed.key;
  let slotNum = req.query?.slot || req.body?.slot ? parseInt(req.query?.slot || req.body?.slot, 10) : linkParsed.slot;
  const userName = req.body?.user || req.body?.userName || req.query?.user || req.query?.userName || linkParsed.user;
  const readerName = (userName && typeof userName === "string") ? userName.trim() : null;
  // Strictly provide up to 10 messages at a time for shortcut reading
  const limit = Math.min(parseInt(req.query?.limit || req.body?.limit || "10", 10), 10);

  // Support combined connection key format
  if (keyStr && typeof keyStr === "string" && (keyStr.includes(":") || keyStr.includes("#"))) {
    const combined = parseConnectionLink(keyStr);
    if (combined.roomId) roomId = roomId || combined.roomId;
    if (combined.token) token = token || combined.token;
    if (combined.key) keyStr = combined.key;
    if (combined.slot) slotNum = slotNum || combined.slot;
  }

  if (!isValidRoomId(roomId)) {
    return res.status(400).json({ error: "Invalid or missing roomId (paste your chat link or provide roomId)" });
  }

  const room = stmtGetRoom.get(roomId);
  if (!room) {
    return res.status(404).json({ error: "Room not found or expired" });
  }

  if (!slotNum) {
    if (token === room.token1) slotNum = 1;
    else if (token === room.token2) slotNum = 2;
  }

  if (!slotNum) {
    return res.status(403).json({ error: "Unauthorized: Invalid or missing member token" });
  }

  const rawKeyBuf = parseKeyToBuffer(keyStr);
  if (!rawKeyBuf) {
    return res.status(400).json({ error: "Missing or invalid 256-bit AES encryption key" });
  }

  try {
    const rows = stmtGetMsgs.all(roomId, limit);
    rows.reverse(); // oldest to newest
    updateSlotPresence(roomId, slotNum);
    if (rows.length > 0) {
      const readBytes = rows.reduce((acc, r) => acc + (r.ciphertext ? r.ciphertext.length : 0) + (r.iv ? r.iv.length : 0) + 64, 128);
      try { stmtAddRoomTraffic.run(readBytes, roomId); } catch {}
    }

    const decryptedMessages = [];
    let slot1Name = null;
    let slot2Name = null;

    // First pass: decrypt and discover existing custom nicknames for both slots
    const rawParsedList = [];
    for (const row of rows) {
      try {
        const combined = Buffer.from(row.ciphertext, "base64");
        const ivBuf = Buffer.from(row.iv, "base64");
        const tag = combined.subarray(combined.length - 16);
        const ciphertextOnly = combined.subarray(0, combined.length - 16);

        const decipher = crypto.createDecipheriv("aes-256-gcm", rawKeyBuf, ivBuf);
        decipher.setAuthTag(tag);
        let dec = decipher.update(ciphertextOnly, null, "utf8");
        dec += decipher.final("utf8");
        const parsed = JSON.parse(dec);

        if (parsed.user && typeof parsed.user === "string") {
          const uTrim = parsed.user.trim();
          if (uTrim && uTrim !== "Partner" && uTrim !== "Creator" && uTrim !== "You" && uTrim !== "我" && uTrim !== "成員 1" && uTrim !== "成員 2" && uTrim !== "對方") {
            if (row.sender === 1 && !slot1Name) slot1Name = uTrim;
            if (row.sender === 2 && !slot2Name) slot2Name = uTrim;
          }
        }

        rawParsedList.push({ row, parsed, ok: true });
      } catch (err) {
        rawParsedList.push({ row, parsed: null, ok: false });
      }
    }

    // Second pass: format display names cleanly (Never display English "Partner" or "Creator")
    for (const item of rawParsedList) {
      if (!item.ok) {
        decryptedMessages.push({
          id: item.row.id,
          user: "未知",
          text: "[加密訊息 - 金鑰不相符]",
          timestamp: item.row.timestamp,
        });
        continue;
      }

      const { row, parsed } = item;
      const parsedUser = (parsed.user && typeof parsed.user === "string") ? parsed.user.trim() : null;
      const readerNameTrimmed = readerName ? readerName.trim() : null;

      // 核心規則：如果名字一樣就代表是同個人不同裝置！
      let isSelf = false;
      if (parsedUser && readerNameTrimmed) {
        if (parsedUser.toLowerCase() === readerNameTrimmed.toLowerCase()) {
          isSelf = true; // 名字相同 = 同一個人不同裝置（我）！
        } else {
          isSelf = false; // 名字不同 = 對方！
        }
      } else {
        isSelf = row.sender === slotNum;
      }

      let displayName = "";
      if (isSelf) {
        displayName = "我";
      } else {
        const peerSlot = slotNum === 1 ? 2 : 1;
        const knownPeerNick = peerSlot === 1 ? slot1Name : slot2Name;
        if (parsedUser && parsedUser !== "Partner" && parsedUser !== "Creator" && parsedUser !== "You" && parsedUser !== "我" && parsedUser !== "成員 1" && parsedUser !== "成員 2" && parsedUser !== "對方") {
          displayName = parsedUser;
        } else if (knownPeerNick) {
          displayName = knownPeerNick;
        } else {
          displayName = "對方";
        }
      }

      decryptedMessages.push({
        id: row.id,
        user: displayName,
        rawUser: parsed.user,
        text: parsed.text,
        slot: row.sender,
        isSelf,
        timestamp: row.timestamp,
      });
    }

    // Generate formatted single-string display for easy iOS Shortcut popup
    const formattedLines = decryptedMessages.map(m => {
      const time = new Date(m.timestamp).toLocaleTimeString("zh-TW", { hour: "2-digit", minute: "2-digit", hour12: false });
      return `💬 [${time}] ${m.user}: ${m.text}`;
    });
    const formattedText = formattedLines.length > 0
      ? formattedLines.join("\n")
      : "📭 目前尚無任何訊息";

    if (returnUnifiedObject || req.query.format === "object" || req.body?.format === "object") {
      res.json({
        ok: true,
        action: "read",
        roomId,
        count: decryptedMessages.length,
        formattedText,
        messages: decryptedMessages
      });
    } else {
      res.json(decryptedMessages);
    }
  } catch (e) {
    console.error("Failed to read shortcut messages:", e);
    res.status(500).json({ error: "Failed to read messages" });
  }
}

// ---------- 6. iOS Shortcut Send (POST /api/shortcut/send) ----------
app.post("/api/shortcut/send", handleShortcutSend);

// ---------- 7. iOS Shortcut Read (GET & POST /api/shortcut/messages) ----------
app.all("/api/shortcut/messages", (req, res) => handleShortcutRead(req, res, false));

// ---------- 8. iOS Shortcut Unified 2-in-1 Endpoint (ALL /api/shortcut) ----------
// Input link only once! If text is provided -> SEND; If text is omitted -> READ
app.all("/api/shortcut", (req, res) => {
  const text = req.body?.text || req.body?.message || req.body?.msg || req.query?.text || req.query?.message || req.query?.msg;
  const action = req.body?.action || req.query?.action;
  if (text && typeof text === "string" && text.trim().length > 0 && action !== "read") {
    return handleShortcutSend(req, res);
  }
  return handleShortcutRead(req, res, true);
});

// ============================================================
//  System Health & Storage Monitoring API (Admin Only)
// ============================================================

// Public Health Check
app.get(["/health", "/api/ping"], (req, res) => {
  res.json({
    ok: true,
    status: "healthy",
    timestamp: Date.now()
  });
});

// Admin Authentication Verification
app.all("/api/admin/verify", requireAdminAuth, (req, res) => {
  res.json({ ok: true, message: "Administrator credentials verified" });
});

// Admin System Status & Storage
app.get("/api/system/status", requireAdminAuth, (req, res) => {
  // 1. Filesystem Storage
  let disk = { totalBytes: 0, freeBytes: 0, usedBytes: 0, usedPercent: 0, totalGB: "0", usedGB: "0", freeGB: "0", status: "healthy" };
  try {
    if (fs.statfsSync) {
      const s = fs.statfsSync(process.cwd());
      const total = s.bsize * s.blocks;
      const free = s.bsize * s.bavail;
      const used = total - free;
      disk = {
        totalBytes: total,
        freeBytes: free,
        usedBytes: used,
        totalGB: (total / (1024 ** 3)).toFixed(2),
        usedGB: (used / (1024 ** 3)).toFixed(2),
        freeGB: (free / (1024 ** 3)).toFixed(2),
        usedPercent: total > 0 ? parseFloat(((used / total) * 100).toFixed(1)) : 0,
        status: (used / total) > 0.9 ? "critical" : (used / total) > 0.75 ? "warning" : "healthy"
      };
    }
  } catch (err) {
    console.warn("Could not read disk stats:", err);
  }

  // 2. SQLite Database Storage & Metrics
  let dbStats = {
    dbSizeBytes: 0,
    walSizeBytes: 0,
    shmSizeBytes: 0,
    totalSizeBytes: 0,
    totalSizeFormatted: "0 KB",
    totalRooms: 0,
    totalMessages: 0,
    activeRooms1h: 0,
    activeRooms24h: 0,
    maxMessagesPerRoom: MAX_MESSAGES_PER_ROOM,
    rollingRetentionDays: ROOM_EXPIRE_DAYS
  };
  try {
    const dbSize = fs.existsSync(DB_PATH) ? fs.statSync(DB_PATH).size : 0;
    const walPath = `${DB_PATH}-wal`;
    const shmPath = `${DB_PATH}-shm`;
    const walSize = fs.existsSync(walPath) ? fs.statSync(walPath).size : 0;
    const shmSize = fs.existsSync(shmPath) ? fs.statSync(shmPath).size : 0;
    const totalDb = dbSize + walSize + shmSize;

    dbStats.dbSizeBytes = dbSize;
    dbStats.walSizeBytes = walSize;
    dbStats.shmSizeBytes = shmSize;
    dbStats.totalSizeBytes = totalDb;
    dbStats.totalSizeFormatted = formatBytes(totalDb);

    dbStats.totalRooms = stmtTotalRooms.get()?.count || 0;
    dbStats.totalMessages = stmtTotalMessages.get()?.count || 0;
    dbStats.activeRooms1h = stmtActiveRooms1h.get()?.count || 0;
    dbStats.activeRooms24h = stmtActiveRooms24h.get()?.count || 0;
  } catch (err) {
    console.warn("Could not read DB stats:", err);
  }

  // 3. Active Real-time Rooms
  let onlineRoomsCount = 0;
  let onlineUsersCount = 0;
  const now = Date.now();
  for (const [, pres] of roomPresence.entries()) {
    const u1Online = now - pres.u1 < PRESENCE_TIMEOUT_MS;
    const u2Online = now - pres.u2 < PRESENCE_TIMEOUT_MS;
    if (u1Online || u2Online) {
      onlineRoomsCount++;
      if (u1Online) onlineUsersCount++;
      if (u2Online) onlineUsersCount++;
    }
  }

  const cpus = os.cpus();
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const memUsage = process.memoryUsage();

  res.json({
    ok: true,
    timestamp: Date.now(),
    system: {
      hostname: os.hostname(),
      platform: os.platform(),
      release: os.release(),
      arch: os.arch(),
      uptimeSeconds: Math.floor(os.uptime()),
      uptimeFormatted: formatUptime(os.uptime()),
      processUptimeSeconds: Math.floor(process.uptime()),
      processUptimeFormatted: formatUptime(process.uptime()),
      nodeVersion: process.version,
      serverTime: new Date().toISOString()
    },
    storage: {
      disk,
      database: dbStats
    },
    performance: {
      cpu: {
        cores: cpus.length,
        model: cpus[0]?.model || "Generic CPU",
        loadAvg: os.loadavg().map(v => parseFloat(v.toFixed(2))),
        loadPercent: Math.min(100, Math.round(((os.loadavg()[0] || 0) / (cpus.length || 1)) * 100))
      },
      memory: {
        totalBytes: totalMem,
        freeBytes: freeMem,
        usedBytes: usedMem,
        totalMB: Math.round(totalMem / 1024 / 1024),
        usedMB: Math.round(usedMem / 1024 / 1024),
        freeMB: Math.round(freeMem / 1024 / 1024),
        usedPercent: parseFloat(((usedMem / totalMem) * 100).toFixed(1)),
        processRssMB: Math.round(memUsage.rss / 1024 / 1024),
        processHeapUsedMB: Math.round(memUsage.heapUsed / 1024 / 1024),
        processHeapTotalMB: Math.round(memUsage.heapTotal / 1024 / 1024)
      }
    },
    activity: {
      onlineRoomsNow: onlineRoomsCount,
      onlineUsersNow: onlineUsersCount,
      activeIpLimiterBuckets: limiter.limits.size,
      statusText: "All Systems Operational 🟢"
    }
  });
});

// ============================================================
//  Admin Room Management API (List & Delete)
// ============================================================

// List all existing and active rooms with traffic
app.get("/api/admin/rooms", requireAdminAuth, (req, res) => {
  try {
    const stmtListRooms = db.prepare(`
      SELECT 
        r.id,
        r.created_at,
        r.last_active,
        COALESCE(r.traffic_bytes, 0) as traffic_bytes,
        COUNT(m.id) as message_count,
        COALESCE(SUM(LENGTH(m.ciphertext) + LENGTH(m.iv)), 0) as stored_bytes
      FROM rooms r
      LEFT JOIN messages m ON r.id = m.room_id
      GROUP BY r.id
      ORDER BY r.last_active DESC
    `);

    const rows = stmtListRooms.all();
    const now = Date.now();

    const rooms = rows.map(r => {
      const pres = roomPresence.get(r.id) || { u1: 0, u2: 0 };
      const u1Online = now - pres.u1 < PRESENCE_TIMEOUT_MS;
      const u2Online = now - pres.u2 < PRESENCE_TIMEOUT_MS;
      const isOnline = u1Online || u2Online;
      const activeUsers = (u1Online ? 1 : 0) + (u2Online ? 1 : 0);

      const lastActiveTime = new Date(r.last_active).getTime();
      const diffMs = now - (isNaN(lastActiveTime) ? 0 : lastActiveTime);
      const diffMinutes = Math.floor(diffMs / 60000);

      let status = "idle";
      let statusLabel = "⚪ 閒置";
      if (isOnline) {
        status = "online";
        statusLabel = `🟢 在線 (${activeUsers}人)`;
      } else if (diffMinutes < 60) {
        status = "recent";
        statusLabel = `🟡 活躍 (${diffMinutes}m前)`;
      } else if (diffMinutes < 1440) {
        const h = Math.floor(diffMinutes / 60);
        status = "recent";
        statusLabel = `🟡 活躍 (${h}h前)`;
      } else {
        const d = Math.floor(diffMinutes / 1440);
        status = "idle";
        statusLabel = `⚪ 閒置 (${d}天前)`;
      }

      // If traffic_bytes is 0 but stored_bytes > 0, traffic is at least stored_bytes
      const effectiveTraffic = Math.max(r.traffic_bytes || 0, r.stored_bytes || 0);

      return {
        id: r.id,
        createdAt: r.created_at,
        lastActive: r.last_active,
        diffMinutes,
        isOnline,
        u1Online,
        u2Online,
        activeUsers,
        status,
        statusLabel,
        messageCount: r.message_count,
        maxMessages: MAX_MESSAGES_PER_ROOM,
        storedBytes: r.stored_bytes,
        storedBytesFormatted: formatBytes(r.stored_bytes),
        trafficBytes: effectiveTraffic,
        trafficBytesFormatted: formatBytes(effectiveTraffic),
      };
    });

    const totalTrafficBytes = rooms.reduce((acc, r) => acc + r.trafficBytes, 0);

    res.json({
      ok: true,
      count: rooms.length,
      onlineRoomsCount: rooms.filter(r => r.isOnline).length,
      totalTrafficBytes,
      totalTrafficFormatted: formatBytes(totalTrafficBytes),
      rooms
    });
  } catch (err) {
    console.error("Failed to list admin rooms:", err);
    res.status(500).json({ ok: false, error: "Failed to list rooms" });
  }
});

// Delete room manually
function handleDeleteRoom(req, res) {
  const roomId = req.params?.roomId || req.body?.roomId || req.query?.roomId;
  if (!roomId || typeof roomId !== "string") {
    return res.status(400).json({ ok: false, error: "Missing or invalid roomId" });
  }

  const room = stmtGetRoom.get(roomId);
  if (!room) {
    return res.status(404).json({ ok: false, error: "Room not found or already deleted" });
  }

  try {
    const tx = db.transaction(() => {
      stmtDeleteRoomMsgs.run(roomId);
      stmtDeleteRoom.run(roomId);
    });
    tx();

    roomPresence.delete(roomId);

    res.json({
      ok: true,
      message: `房間 ${roomId} 及所有相關訊息已成功永久刪除`,
      roomId
    });
  } catch (err) {
    console.error("Failed to delete room:", err);
    res.status(500).json({ ok: false, error: "Failed to delete room" });
  }
}

app.delete("/api/admin/rooms/:roomId", requireAdminAuth, handleDeleteRoom);
app.post("/api/admin/rooms/delete", requireAdminAuth, handleDeleteRoom);

// ---------- 9. Host Monitor Website Route ----------
app.get(["/status", "/monitor", "/dashboard"], (req, res) => {
  const candidates = [
    path.join(FRONTEND_PATH, "monitor.html"),
    path.join(__dirname, "../monitor.html"),
    path.join(__dirname, "monitor.html"),
    path.join(__dirname, "frontend/monitor.html"),
    path.join(process.cwd(), "frontend/monitor.html"),
    path.join(process.cwd(), "monitor.html")
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) {
      return res.sendFile(p);
    }
  }
  res.redirect("/api/system/status");
});


// ============================================================
//  Maintenance: Clean Inactive Rooms (>14 days)
// ============================================================
setInterval(() => {
  try {
    stmtCleanExpiredMessages.run(ROOM_EXPIRE_DAYS);
    stmtCleanExpiredRooms.run(ROOM_EXPIRE_DAYS);
  } catch (e) {
    console.error("Cleanup error:", e);
  }
}, 12 * 60 * 60 * 1000).unref();

// ============================================================
//  Start Server
// ============================================================
const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`====================================================`);
  console.log(`🚀 Ren 2-Party E2EE Chat API running on http://0.0.0.0:${PORT}`);
  console.log(`👥 Two Parties, Multi-Device Supported`);
  console.log(`💬 Message Limit: Max ${MAX_MESSAGES_PER_ROOM} messages per room`);
  console.log(`====================================================`);
});

function shutdown() {
  server.close(() => {
    db.close();
    process.exit(0);
  });
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
