import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pkg from "pg";
import path from "path";
import { fileURLToPath } from "url";
import PDFDocument from "pdfkit";
import crypto from "crypto";

const { Pool } = pkg;

const app = express();
app.use(express.json({ limit: "200kb" }));

const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;

const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "emerson@dmminformatica.com.br").toLowerCase();
const APP_BASE_URL = process.env.APP_BASE_URL || "https://webapp-musicas.onrender.com";
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";

const CORS_ORIGIN = process.env.CORS_ORIGIN || APP_BASE_URL;
const NODE_ENV = process.env.NODE_ENV || "production";

if (!DATABASE_URL) throw new Error("DATABASE_URL não definido");
if (!JWT_SECRET) throw new Error("JWT_SECRET não definido");

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function ensureSchema() {
  // Tabelas principais
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(80) NOT NULL,
      email VARCHAR(160) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      is_admin BOOLEAN NOT NULL DEFAULT FALSE,
      is_super BOOLEAN NOT NULL DEFAULT FALSE,
      is_approved BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS approval_tokens (
      id SERIAL PRIMARY KEY,
      user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT UNIQUE NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS songs (
      id SERIAL PRIMARY KEY,
      created_by INT NULL REFERENCES users(id) ON DELETE SET NULL,
      cantor VARCHAR(120) NOT NULL,
      musica VARCHAR(160) NOT NULL,
      tom VARCHAR(50) NULL,
      link VARCHAR(800) NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  // LISTAS
  await pool.query(`
    CREATE TABLE IF NOT EXISTS lists (
      id SERIAL PRIMARY KEY,
      created_by INT NULL REFERENCES users(id) ON DELETE SET NULL,
      name VARCHAR(120) NOT NULL,
      description VARCHAR(300) NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS list_songs (
      list_id INT NOT NULL REFERENCES lists(id) ON DELETE CASCADE,
      song_id INT NOT NULL REFERENCES songs(id) ON DELETE CASCADE,
      added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (list_id, song_id)
    );
  `);
}

// Headers básicos de segurança
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  next();
});

// CORS + cookies
const allowedOrigins = new Set([CORS_ORIGIN]);
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (allowedOrigins.has(origin)) return cb(null, true);
    return cb(new Error("CORS bloqueado"), false);
  },
  credentials: true
}));

// Rate limit simples
function makeRateLimiter({ windowMs, max }) {
  const hits = new Map();
  return function rateLimit(req, res, next) {
    const key = `${req.ip}:${req.path}`;
    const now = Date.now();
    const item = hits.get(key);

    if (!item || now > item.resetAt) {
      hits.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }

    item.count += 1;
    if (item.count > max) {
      const retry = Math.ceil((item.resetAt - now) / 1000);
      res.setHeader("Retry-After", String(retry));
      return res.status(429).json({ error: "Muitas tentativas. Tente novamente em alguns minutos." });
    }
    return next();
  };
}

const loginLimiter = makeRateLimiter({ windowMs: 15 * 60 * 1000, max: 25 });
const registerLimiter = makeRateLimiter({ windowMs: 30 * 60 * 1000, max: 15 });

// Cookie helpers
const COOKIE_NAME = "session";

function setSessionCookie(res, token) {
  const secure = true; // Render https
  const sameSite = "Lax";
  const maxAgeSec = 7 * 24 * 60 * 60;

  const parts = [
    `${COOKIE_NAME}=${token}`,
    `Path=/`,
    `HttpOnly`,
    `SameSite=${sameSite}`,
    `Max-Age=${maxAgeSec}`
  ];
  if (secure) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearSessionCookie(res) {
  const parts = [
    `${COOKIE_NAME}=`,
    `Path=/`,
    `HttpOnly`,
    `SameSite=Lax`,
    `Max-Age=0`,
    `Secure`
  ];
  res.setHeader("Set-Cookie", parts.join("; "));
}

function getCookie(req, name) {
  const header = req.headers.cookie || "";
  const cookies = header.split(";").map(v => v.trim());
  for (const c of cookies) {
    const idx = c.indexOf("=");
    if (idx === -1) continue;
    const k = c.slice(0, idx).trim();
    const v = c.slice(idx + 1);
    if (k === name) return v;
  }
  return "";
}

// Validation helpers
function isEmail(x) {
  const s = String(x || "").trim();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
}
function clampStr(x, max) {
  const s = String(x ?? "").trim();
  if (!s) return "";
  return s.length > max ? s.slice(0, max) : s;
}
function validHttpUrl(x) {
  const s = String(x || "").trim();
  if (!s) return true;
  try {
    const u = new URL(s);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

// JWT
function signToken(user) {
  return jwt.sign(
    {
      uid: user.id,
      email: user.email,
      name: user.name || "",
      is_admin: !!user.is_admin,
      is_super: !!user.is_super
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function authMiddleware(req, res, next) {
  const tok = getCookie(req, COOKIE_NAME);
  if (!tok) return res.status(401).json({ error: "Sem sessão" });

  try {
    req.user = jwt.verify(tok, JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ error: "Sessão inválida" });
  }
}

function adminOnly(req, res, next) {
  if (!req.user?.is_admin) return res.status(403).json({ error: "Apenas administrador" });
  next();
}

// Resend helpers
function sha256Hex(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}
function randomToken() {
  return crypto.randomBytes(32).toString("hex");
}

async function sendResendEmail({ to, subject, html }) {
  if (!RESEND_API_KEY) return;
  await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from: "Musicas da Jhenny <onboarding@resend.dev>",
      to: [to],
      subject,
      html
    })
  });
}

async function createApprovalToken(userId) {
  const raw = randomToken();
  const hash = sha256Hex(raw);
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000);

  await pool.query(
    `INSERT INTO approval_tokens (user_id, token_hash, expires_at)
     VALUES ($1, $2, $3)`,
    [userId, hash, expires.toISOString()]
  );

  return raw;
}

async function emailAdminApproval({ userId, name, email }) {
  if (!RESEND_API_KEY) return;

  const token = await createApprovalToken(userId);
  const approveUrl = `${APP_BASE_URL}/dashboard.html?approve=${encodeURIComponent(token)}`;

  const subject = "Aprovação de usuário - Músicas da Jhenny";
  const html = `
    <div style="font-family: Arial, sans-serif; line-height:1.45">
      <h2>Novo usuário aguardando aprovação</h2>
      <p><b>Nome:</b> ${String(name || "")}</p>
      <p><b>Email:</b> ${String(email || "")}</p>
      <p>Para aprovar, clique:</p>
      <p><a href="${approveUrl}">${approveUrl}</a></p>
      <p style="color:#666;font-size:12px">Este link expira em 24 horas.</p>
    </div>
  `;

  await sendResendEmail({ to: ADMIN_EMAIL, subject, html });
}

// =========================
// Routes
// =========================
app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get("/api/me", authMiddleware, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT id, name, email, is_admin, is_super, is_approved
       FROM users
       WHERE id=$1`,
      [req.user.uid]
    );
    const u = r.rows[0];
    if (!u) return res.status(401).json({ error: "Sessão inválida" });
    if (!u.is_approved) return res.status(403).json({ error: "Aguardando aprovação do administrador." });

    res.json({
      id: u.id,
      name: u.name || "",
      email: u.email,
      is_admin: !!u.is_admin,
      is_super: !!u.is_super
    });
  } catch (e) {
    res.status(500).json({ error: String(e.message || "") });
  }
});

app.post("/api/logout", (req, res) => {
  clearSessionCookie(res);
  res.json({ ok: true });
});

// ===== AUTH =====
app.post("/api/register", registerLimiter, async (req, res) => {
  const name = clampStr(req.body?.name, 80);
  const email = String(req.body?.email || "").toLowerCase().trim();
  const password = String(req.body?.password || "");

  if (!name) return res.status(400).json({ error: "Nome é obrigatório" });
  if (!isEmail(email)) return res.status(400).json({ error: "Email inválido" });
  if (password.length < 8) return res.status(400).json({ error: "Senha deve ter no mínimo 8 caracteres" });

  try {
    const hash = await bcrypt.hash(password, 12);
    const isAdmin = email === ADMIN_EMAIL;

    const result = await pool.query(
      `INSERT INTO users (name, email, password_hash, is_admin, is_super, is_approved)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, name, email, is_admin, is_super, is_approved`,
      [name, email, hash, isAdmin, false, isAdmin]
    );

    const user = result.rows[0];

    if (!user.is_admin) {
      try { await emailAdminApproval({ userId: user.id, name: user.name, email: user.email }); } catch {}
      return res.json({
        pending: true,
        message: "Cadastro criado! Aguarde aprovação do administrador para acessar."
      });
    }

    const tok = signToken(user);
    setSessionCookie(res, tok);
    return res.json({ ok: true, user: { name: user.name, email: user.email, is_admin: true, is_super: false } });
  } catch (e) {
    const msg = String(e.message || "");
    if (msg.includes("duplicate key") || msg.includes("users_email_key")) {
      return res.status(409).json({ error: "Email já cadastrado" });
    }
    res.status(500).json({ error: msg });
  }
});

app.post("/api/login", loginLimiter, async (req, res) => {
  const email = String(req.body?.email || "").toLowerCase().trim();
  const password = String(req.body?.password || "");

  if (!isEmail(email)) return res.status(400).json({ error: "Email inválido" });
  if (!password) return res.status(400).json({ error: "Senha obrigatória" });

  try {
    const result = await pool.query(
      "SELECT id, name, email, password_hash, is_admin, is_super, is_approved FROM users WHERE email=$1",
      [email]
    );

    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: "Email ou senha inválidos" });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Email ou senha inválidos" });

    if (!user.is_approved) {
      return res.status(403).json({ error: "Aguardando aprovação do administrador." });
    }

    const tok = signToken(user);
    setSessionCookie(res, tok);

    res.json({
      ok: true,
      user: { name: user.name || "", email: user.email, is_admin: !!user.is_admin, is_super: !!user.is_super }
    });
  } catch (e) {
    res.status(500).json({ error: String(e.message || "") });
  }
});

// ===== ADMIN =====

// NOVO: listar TODOS os usuários (pendentes + aprovados)
app.get("/api/admin/users", authMiddleware, adminOnly, async (req, res) => {
  const r = await pool.query(
    `SELECT id, name, email, is_admin, is_super, is_approved, created_at
     FROM users
     ORDER BY is_approved ASC, created_at DESC
     LIMIT 500`
  );
  res.json(r.rows);
});

// Aprovar normal
app.post("/api/admin/approve/:id", authMiddleware, adminOnly, async (req, res) => {
  const id = Number(req.params.id);
  if (!id || Number.isNaN(id)) return res.status(400).json({ error: "ID inválido" });

  const r = await pool.query(
    `UPDATE users
     SET is_approved = TRUE
     WHERE id=$1
     RETURNING id, name, email, is_super, is_approved`,
    [id]
  );

  if (r.rowCount === 0) return res.status(404).json({ error: "Usuário não encontrado" });
  res.json({ ok: true, user: r.rows[0] });
});

// Aprovar como SUPER
app.post("/api/admin/approve-super/:id", authMiddleware, adminOnly, async (req, res) => {
  const id = Number(req.params.id);
  if (!id || Number.isNaN(id)) return res.status(400).json({ error: "ID inválido" });

  const r = await pool.query(
    `UPDATE users
     SET is_approved = TRUE,
         is_super = TRUE
     WHERE id=$1
     RETURNING id, name, email, is_super, is_approved`,
    [id]
  );

  if (r.rowCount === 0) return res.status(404).json({ error: "Usuário não encontrado" });
  res.json({ ok: true, user: r.rows[0] });
});

// Negar = deletar (não pode deletar admin)
app.post("/api/admin/deny/:id", authMiddleware, adminOnly, async (req, res) => {
  const id = Number(req.params.id);
  if (!id || Number.isNaN(id)) return res.status(400).json({ error: "ID inválido" });

  const check = await pool.query(`SELECT email, is_admin FROM users WHERE id=$1`, [id]);
  if (check.rowCount === 0) return res.status(404).json({ error: "Usuário não encontrado" });
  if (check.rows[0].is_admin) return res.status(400).json({ error: "Não é permitido deletar um administrador." });

  await pool.query(`DELETE FROM users WHERE id=$1`, [id]);
  res.json({ ok: true });
});

// Marcar/Desmarcar SUPER (para aprovados também)
app.post("/api/admin/set-super/:id", authMiddleware, adminOnly, async (req, res) => {
  const id = Number(req.params.id);
  const isSuper = !!req.body?.is_super;

  if (!id || Number.isNaN(id)) return res.status(400).json({ error: "ID inválido" });

  const check = await pool.query(`SELECT is_admin FROM users WHERE id=$1`, [id]);
  if (check.rowCount === 0) return res.status(404).json({ error: "Usuário não encontrado" });
  if (check.rows[0].is_admin) return res.status(400).json({ error: "Administrador não deve ser tratado como SUPER." });

  const r = await pool.query(
    `UPDATE users
     SET is_super = $2
     WHERE id=$1
     RETURNING id, name, email, is_super, is_admin, is_approved`,
    [id, isSuper]
  );

  res.json({ ok: true, user: r.rows[0] });
});

// Aprovar por TOKEN
app.post("/api/admin/approve-token/:token", authMiddleware, adminOnly, async (req, res) => {
  const raw = String(req.params.token || "").trim();
  if (raw.length < 20) return res.status(400).json({ error: "Token inválido" });

  const hash = crypto.createHash("sha256").update(String(raw)).digest("hex");

  const t = await pool.query(
    `SELECT id, user_id, expires_at, used_at
     FROM approval_tokens
     WHERE token_hash=$1`,
    [hash]
  );

  const row = t.rows[0];
  if (!row) return res.status(404).json({ error: "Token não encontrado" });
  if (row.used_at) return res.status(400).json({ error: "Token já usado" });

  const exp = new Date(row.expires_at).getTime();
  if (Date.now() > exp) return res.status(400).json({ error: "Token expirado" });

  await pool.query(`UPDATE users SET is_approved=TRUE WHERE id=$1`, [row.user_id]);
  await pool.query(`UPDATE approval_tokens SET used_at=NOW() WHERE id=$1`, [row.id]);

  res.json({ ok: true });
});

// ===== SONGS =====
function normalizeSongInput(body) {
  const cantor = clampStr(body?.cantor, 120);
  const musica = clampStr(body?.musica, 160);
  const tom = clampStr(body?.tom, 50);
  const link = clampStr(body?.link, 800);

  if (!cantor || !musica) return { error: "cantor e musica são obrigatórios" };
  if (!validHttpUrl(link)) return { error: "Link inválido (use http/https)" };

  return { cantor, musica, tom: tom || null, link: link || null };
}

app.post("/api/songs", authMiddleware, async (req, res) => {
  const input = normalizeSongInput(req.body);
  if (input.error) return res.status(400).json({ error: input.error });

  try {
    const r = await pool.query(
      `INSERT INTO songs (created_by, cantor, musica, tom, link)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, created_by, cantor, musica, tom, link, created_at`,
      [req.user.uid, input.cantor, input.musica, input.tom, input.link]
    );
    res.json(r.rows[0]);
  } catch (e) {
    res.status(500).json({ error: String(e.message || "") });
  }
});

// Editar: ADMIN OU SUPER OU AUTOR
app.put("/api/songs/:id", authMiddleware, async (req, res) => {
  const id = Number(req.params.id);
  if (!id || Number.isNaN(id)) return res.status(400).json({ error: "ID inválido" });

  const input = normalizeSongInput(req.body);
  if (input.error) return res.status(400).json({ error: input.error });

  try {
    const s = await pool.query(`SELECT id, created_by FROM songs WHERE id=$1`, [id]);
    const song = s.rows[0];
    if (!song) return res.status(404).json({ error: "Música não encontrada" });

    const isAdmin = !!req.user.is_admin;
    const isSuper = !!req.user.is_super;
    const isAuthor = (song.created_by && Number(song.created_by) === Number(req.user.uid));

    const canEdit = isAdmin || isSuper || isAuthor;
    if (!canEdit) return res.status(403).json({ error: "Você não tem permissão para editar esta música." });

    const r = await pool.query(
      `UPDATE songs
       SET cantor=$1, musica=$2, tom=$3, link=$4
       WHERE id=$5
       RETURNING id, created_by, cantor, musica, tom, link, created_at`,
      [input.cantor, input.musica, input.tom, input.link, id]
    );

    res.json(r.rows[0]);
  } catch (e) {
    res.status(500).json({ error: String(e.message || "") });
  }
});

app.get("/api/songs", authMiddleware, async (req, res) => {
  const q = String(req.query.q || "").trim();
  try {
    if (!q) {
      const r = await pool.query(
        `SELECT id, created_by, cantor, musica, tom, link, created_at
         FROM songs
         ORDER BY created_at DESC
         LIMIT 200`
      );
      return res.json(r.rows);
    }

    const like = `%${q}%`;
    const r = await pool.query(
      `SELECT id, created_by, cantor, musica, tom, link, created_at
       FROM songs
       WHERE (cantor ILIKE $1 OR musica ILIKE $1)
       ORDER BY created_at DESC
       LIMIT 200`,
      [like]
    );
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ error: String(e.message || "") });
  }
});

app.get("/api/songs/page", authMiddleware, async (req, res) => {
  const page = Math.max(1, Number(req.query.page || 1));
  const limit = Math.min(50, Math.max(1, Number(req.query.limit || 20)));
  const offset = (page - 1) * limit;

  try {
    const totalR = await pool.query(`SELECT COUNT(*)::int AS total FROM songs`);
    const total = totalR.rows[0]?.total || 0;
    const totalPages = Math.max(1, Math.ceil(total / limit));

    const itemsR = await pool.query(
      `SELECT id, created_by, cantor, musica, tom, link, created_at
       FROM songs
       ORDER BY LOWER(cantor) ASC, LOWER(musica) ASC
       LIMIT $1 OFFSET $2`,
      [limit, offset]
    );

    res.json({ items: itemsR.rows, total, page, limit, totalPages });
  } catch (e) {
    res.status(500).json({ error: String(e.message || "") });
  }
});

app.get("/api/songs/count", authMiddleware, async (req, res) => {
  try {
    const r = await pool.query(`SELECT COUNT(*)::int AS total FROM songs`);
    res.json({ total: r.rows[0]?.total || 0 });
  } catch (e) {
    res.status(500).json({ error: String(e.message || "") });
  }
});

app.get("/api/songs/suggest", authMiddleware, async (req, res) => {
  const q = String(req.query.q || "").trim();
  if (!q) return res.json([]);

  try {
    const like = `%${q}%`;
    const r = await pool.query(
      `SELECT cantor, musica
       FROM songs
       WHERE (cantor ILIKE $1 OR musica ILIKE $1)
       ORDER BY created_at DESC
       LIMIT 30`,
      [like]
    );

    const set = new Set();
    for (const row of r.rows) {
      if (row.cantor) set.add(row.cantor);
      if (row.musica) set.add(row.musica);
    }
    res.json([...set].slice(0, 10));
  } catch (e) {
    res.status(500).json({ error: String(e.message || "") });
  }
});

app.get("/api/songs/pdf", authMiddleware, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT cantor, musica, link
       FROM songs
       ORDER BY LOWER(cantor) ASC, LOWER(musica) ASC`
    );

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="musicas.pdf"`);

    const doc = new PDFDocument({ size: "A4", margin: 40 });
    doc.pipe(res);

    doc.fontSize(18).text("Músicas da Jhenny", { align: "left" });
    doc.moveDown(0.5);
    doc.fontSize(10).fillColor("#555").text(`Total: ${r.rows.length}`, { align: "left" });
    doc.moveDown(1);

    doc.fillColor("#000").fontSize(11);

    doc.font("Helvetica-Bold");
    doc.text("Cantor", 40, doc.y, { continued: true, width: 170 });
    doc.text("Música", 220, doc.y, { continued: true, width: 190 });
    doc.text("Link", 420, doc.y, { width: 150 });
    doc.moveDown(0.3);
    doc.font("Helvetica");
    doc.moveTo(40, doc.y).lineTo(555, doc.y).strokeColor("#cccccc").stroke();
    doc.moveDown(0.6);

    for (const s of r.rows) {
      const y = doc.y;
      doc.text(s.cantor || "", 40, y, { width: 170 });
      doc.text(s.musica || "", 220, y, { width: 190 });
      doc.text(s.link || "", 420, y, { width: 150, link: s.link || undefined, underline: !!s.link });
      doc.moveDown(0.6);
      if (doc.y > 760) doc.addPage();
    }

    doc.end();
  } catch (e) {
    res.status(500).json({ error: String(e.message || "") });
  }
});

// ===== LISTS =====
function canManageLists(req) {
  return !!(req.user?.is_admin || req.user?.is_super);
}

// Listar listas (qualquer usuário logado)
app.get("/api/lists", authMiddleware, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT id, created_by, name, description, created_at, updated_at
       FROM lists
       ORDER BY LOWER(name) ASC, id ASC`
    );
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ error: String(e.message || "") });
  }
});

// Criar lista (ADMIN/SUPER)
app.post("/api/lists", authMiddleware, async (req, res) => {
  if (!canManageLists(req)) return res.status(403).json({ error: "Apenas ADMIN/SUPER podem criar listas." });

  const name = clampStr(req.body?.name, 120);
  const description = clampStr(req.body?.description, 300) || null;
  if (!name) return res.status(400).json({ error: "Nome da lista é obrigatório" });

  try {
    const r = await pool.query(
      `INSERT INTO lists (created_by, name, description)
       VALUES ($1, $2, $3)
       RETURNING id, created_by, name, description, created_at, updated_at`,
      [req.user.uid, name, description]
    );
    res.json(r.rows[0]);
  } catch (e) {
    res.status(500).json({ error: String(e.message || "") });
  }
});

// Atualizar lista (ADMIN/SUPER)
app.put("/api/lists/:id", authMiddleware, async (req, res) => {
  if (!canManageLists(req)) return res.status(403).json({ error: "Apenas ADMIN/SUPER podem editar listas." });

  const id = Number(req.params.id);
  if (!id || Number.isNaN(id)) return res.status(400).json({ error: "ID inválido" });

  const name = clampStr(req.body?.name, 120);
  const description = clampStr(req.body?.description, 300) || null;
  if (!name) return res.status(400).json({ error: "Nome da lista é obrigatório" });

  try {
    const r = await pool.query(
      `UPDATE lists
       SET name=$1, description=$2, updated_at=NOW()
       WHERE id=$3
       RETURNING id, created_by, name, description, created_at, updated_at`,
      [name, description, id]
    );
    if (r.rowCount === 0) return res.status(404).json({ error: "Lista não encontrada" });
    res.json(r.rows[0]);
  } catch (e) {
    res.status(500).json({ error: String(e.message || "") });
  }
});

// Excluir lista (ADMIN/SUPER)
app.delete("/api/lists/:id", authMiddleware, async (req, res) => {
  if (!canManageLists(req)) return res.status(403).json({ error: "Apenas ADMIN/SUPER podem excluir listas." });

  const id = Number(req.params.id);
  if (!id || Number.isNaN(id)) return res.status(400).json({ error: "ID inválido" });

  try {
    const r = await pool.query(`DELETE FROM lists WHERE id=$1`, [id]);
    if (r.rowCount === 0) return res.status(404).json({ error: "Lista não encontrada" });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message || "") });
  }
});

// Músicas de uma lista (qualquer usuário logado)
app.get("/api/lists/:id/songs", authMiddleware, async (req, res) => {
  const listId = Number(req.params.id);
  if (!listId || Number.isNaN(listId)) return res.status(400).json({ error: "ID inválido" });

  try {
    const r = await pool.query(
      `SELECT s.id, s.created_by, s.cantor, s.musica, s.tom, s.link, s.created_at
       FROM list_songs ls
       JOIN songs s ON s.id = ls.song_id
       WHERE ls.list_id = $1
       ORDER BY LOWER(s.cantor) ASC, LOWER(s.musica) ASC`,
      [listId]
    );
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ error: String(e.message || "") });
  }
});

// Adicionar música na lista (ADMIN/SUPER)
app.post("/api/lists/:id/songs", authMiddleware, async (req, res) => {
  if (!canManageLists(req)) return res.status(403).json({ error: "Apenas ADMIN/SUPER podem alterar listas." });

  const listId = Number(req.params.id);
  const songId = Number(req.body?.songId);
  if (!listId || Number.isNaN(listId)) return res.status(400).json({ error: "ID inválido" });
  if (!songId || Number.isNaN(songId)) return res.status(400).json({ error: "songId inválido" });

  try {
    // valida existência
    const l = await pool.query(`SELECT id FROM lists WHERE id=$1`, [listId]);
    if (l.rowCount === 0) return res.status(404).json({ error: "Lista não encontrada" });
    const s = await pool.query(`SELECT id FROM songs WHERE id=$1`, [songId]);
    if (s.rowCount === 0) return res.status(404).json({ error: "Música não encontrada" });

    await pool.query(
      `INSERT INTO list_songs (list_id, song_id)
       VALUES ($1, $2)
       ON CONFLICT (list_id, song_id) DO NOTHING`,
      [listId, songId]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message || "") });
  }
});

// Remover música da lista (ADMIN/SUPER)
app.delete("/api/lists/:id/songs/:songId", authMiddleware, async (req, res) => {
  if (!canManageLists(req)) return res.status(403).json({ error: "Apenas ADMIN/SUPER podem alterar listas." });

  const listId = Number(req.params.id);
  const songId = Number(req.params.songId);
  if (!listId || Number.isNaN(listId)) return res.status(400).json({ error: "ID inválido" });
  if (!songId || Number.isNaN(songId)) return res.status(400).json({ error: "songId inválido" });

  try {
    await pool.query(`DELETE FROM list_songs WHERE list_id=$1 AND song_id=$2`, [listId, songId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message || "") });
  }
});

// ===== STATIC =====
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.join(__dirname, "public");

app.use(express.static(publicDir));
app.get("/", (req, res) => res.sendFile(path.join(publicDir, "index.html")));

const port = process.env.PORT || 3000;

async function main() {
  await ensureSchema();
  app.listen(port, () => console.log("Rodando na porta", port, "env:", NODE_ENV));
}

main().catch((e) => {
  console.error("Falha ao iniciar:", e);
  process.exit(1);
});
