"use strict";

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const PDFDocument = require("pdfkit");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// ============================
// ENV (valores esperados)
// ============================
// DATABASE_URL=postgresql://...
// JWT_SECRET=string_forte
// CORS_ORIGIN=https://webapp-musicas.onrender.com
// APP_BASE_URL=https://webapp-musicas.onrender.com
// ADMIN_EMAIL=emerson@dmminformatica.com.br

const {
  DATABASE_URL,
  JWT_SECRET,
  CORS_ORIGIN,
  ADMIN_EMAIL,
} = process.env;

if (!DATABASE_URL) console.warn("⚠️ DATABASE_URL não definido.");
if (!JWT_SECRET) console.warn("⚠️ JWT_SECRET não definido.");

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL && DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false },
});

// ============================
// Middlewares
// ============================
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

app.use(cors({
  origin: CORS_ORIGIN || true,
  credentials: true,
}));

// ============================
// Helpers de Auth
// ============================
function signToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      name: user.name,
      is_admin: user.is_admin,
      is_super: user.is_super,
      approved: user.approved,
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function setAuthCookie(res, token) {
  const isProd = process.env.NODE_ENV === "production";
  res.cookie("token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: isProd, // no Render geralmente é HTTPS, então em produção fica ok
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}

function requireAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Não autenticado" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    return next();
  } catch {
    return res.status(401).json({ error: "Token inválido" });
  }
}

function requireApproved(req, res, next) {
  if (!req.user?.approved) {
    return res.status(403).json({ error: "Aguardando aprovação do admin" });
  }
  return next();
}

function requireAdmin(req, res, next) {
  if (!req.user?.is_admin) return res.status(403).json({ error: "Apenas admin" });
  return next();
}

function requireAdminOrSuper(req, res, next) {
  if (req.user?.is_admin || req.user?.is_super) return next();
  return res.status(403).json({ error: "Sem permissão" });
}

// ============================
// DB Schema (auto-criação)
// ============================
async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL DEFAULT '',
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      approved BOOLEAN NOT NULL DEFAULT FALSE,
      is_admin BOOLEAN NOT NULL DEFAULT FALSE,
      is_super BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS songs (
      id SERIAL PRIMARY KEY,
      cantor TEXT NOT NULL,
      musica TEXT NOT NULL,
      tom TEXT DEFAULT '',
      link TEXT DEFAULT '',
      author_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  // LISTAS
  await pool.query(`
    CREATE TABLE IF NOT EXISTS lists (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_lists_name_unique ON lists (lower(name));
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS list_songs (
      list_id INTEGER NOT NULL REFERENCES lists(id) ON DELETE CASCADE,
      song_id INTEGER NOT NULL REFERENCES songs(id) ON DELETE CASCADE,
      added_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (list_id, song_id)
    );
  `);

  // Garanta admin pelo e-mail (se existir ADMIN_EMAIL)
  if (ADMIN_EMAIL) {
    await pool.query(
      `UPDATE users SET is_admin = TRUE, approved = TRUE WHERE lower(email) = lower($1)`,
      [ADMIN_EMAIL]
    );
  }
}

ensureSchema().then(() => {
  console.log("✅ Schema OK");
}).catch((e) => {
  console.error("❌ Erro ensureSchema:", e);
});

// ============================
// Rota ping (healthcheck)
// ============================
app.get("/ping", (req, res) => res.status(200).send("OK"));

// ============================
// AUTH
// ============================
app.post("/api/register", async (req, res) => {
  const name = String(req.body?.name || "").trim();
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");

  if (!name || !email || !password) {
    return res.status(400).json({ error: "Preencha nome, e-mail e senha" });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: "Senha deve ter pelo menos 6 caracteres" });
  }

  const hash = await bcrypt.hash(password, 10);

  try {
    const { rows } = await pool.query(
      `INSERT INTO users (name, email, password_hash, approved, is_admin, is_super)
       VALUES ($1, $2, $3, FALSE, FALSE, FALSE)
       RETURNING id, name, email, approved, is_admin, is_super`,
      [name, email, hash]
    );

    // Não loga automaticamente — fica aguardando aprovação
    return res.json({ ok: true, user: rows[0] });
  } catch (e) {
    if (String(e.message || "").toLowerCase().includes("unique")) {
      return res.status(409).json({ error: "E-mail já cadastrado" });
    }
    console.error(e);
    return res.status(500).json({ error: "Erro ao cadastrar" });
  }
});

app.post("/api/login", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  if (!email || !password) return res.status(400).json({ error: "Preencha e-mail e senha" });

  const { rows } = await pool.query(
    `SELECT id, name, email, password_hash, approved, is_admin, is_super
     FROM users WHERE lower(email) = lower($1)`,
    [email]
  );
  const user = rows[0];
  if (!user) return res.status(401).json({ error: "Credenciais inválidas" });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "Credenciais inválidas" });

  const token = signToken(user);
  setAuthCookie(res, token);
  return res.json({ ok: true });
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ ok: true });
});

app.get("/api/me", requireAuth, async (req, res) => {
  // Recarrega do banco (pra refletir aprovação/super/admin sem precisar relogar)
  const { rows } = await pool.query(
    `SELECT id, name, email, approved, is_admin, is_super FROM users WHERE id=$1`,
    [req.user.id]
  );
  const u = rows[0];
  if (!u) return res.status(401).json({ error: "Não autenticado" });

  // Se mudou, reemite cookie com token atualizado
  const token = signToken(u);
  setAuthCookie(res, token);

  res.json(u);
});

// ============================
// ADMIN - usuários
// ============================
app.get("/api/admin/users", requireAuth, requireAdmin, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, name, email, approved, is_admin, is_super, created_at
     FROM users
     ORDER BY created_at DESC`
  );
  res.json(rows);
});

app.post("/api/admin/approve/:id", requireAuth, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).json({ error: "ID inválido" });

  const { rowCount } = await pool.query(`UPDATE users SET approved=TRUE WHERE id=$1`, [id]);
  if (!rowCount) return res.status(404).json({ error: "Usuário não encontrado" });
  res.json({ ok: true });
});

app.post("/api/admin/deny/:id", requireAuth, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).json({ error: "ID inválido" });

  const { rowCount } = await pool.query(`DELETE FROM users WHERE id=$1`, [id]);
  if (!rowCount) return res.status(404).json({ error: "Usuário não encontrado" });
  res.json({ ok: true });
});

app.post("/api/admin/set-super/:id", requireAuth, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const is_super = !!req.body?.is_super;

  if (!Number.isFinite(id)) return res.status(400).json({ error: "ID inválido" });

  const { rowCount } = await pool.query(
    `UPDATE users SET is_super=$1 WHERE id=$2 AND is_admin=FALSE`,
    [is_super, id]
  );
  if (!rowCount) return res.status(404).json({ error: "Usuário não encontrado" });
  res.json({ ok: true });
});

// ============================
// SONGS (compartilhadas)
// ============================
function normalizeQ(q) {
  return String(q || "").trim().toLowerCase();
}

app.get("/api/songs", requireAuth, requireApproved, async (req, res) => {
  const q = normalizeQ(req.query.q);
  if (!q) {
    const { rows } = await pool.query(
      `SELECT id, cantor, musica, tom, link, author_id
       FROM songs
       ORDER BY lower(musica) ASC, lower(cantor) ASC`
    );
    return res.json(rows);
  }

  const like = `%${q}%`;
  const { rows } = await pool.query(
    `SELECT id, cantor, musica, tom, link, author_id
     FROM songs
     WHERE lower(cantor) LIKE $1 OR lower(musica) LIKE $1
     ORDER BY
       CASE WHEN lower(musica) LIKE $2 OR lower(cantor) LIKE $2 THEN 0 ELSE 1 END,
       lower(musica) ASC, lower(cantor) ASC`,
    [like, `${q}%`]
  );
  res.json(rows);
});

app.get("/api/songs/suggest", requireAuth, requireApproved, async (req, res) => {
  const q = normalizeQ(req.query.q);
  if (!q) return res.json([]);

  const like = `${q}%`;
  const { rows } = await pool.query(
    `SELECT DISTINCT musica FROM songs WHERE lower(musica) LIKE $1
     UNION
     SELECT DISTINCT cantor FROM songs WHERE lower(cantor) LIKE $1
     LIMIT 10`,
    [like]
  );
  res.json(rows.map(r => r.musica || r.cantor).filter(Boolean));
});

app.get("/api/songs/page", requireAuth, requireApproved, async (req, res) => {
  const page = Math.max(1, Number(req.query.page || 1));
  const limit = Math.min(50, Math.max(1, Number(req.query.limit || 20)));
  const offset = (page - 1) * limit;

  const totalRes = await pool.query(`SELECT COUNT(*)::int AS c FROM songs`);
  const total = totalRes.rows[0].c;
  const totalPages = Math.max(1, Math.ceil(total / limit));

  const { rows } = await pool.query(
    `SELECT id, cantor, musica, tom, link, author_id
     FROM songs
     ORDER BY lower(musica) ASC, lower(cantor) ASC
     LIMIT $1 OFFSET $2`,
    [limit, offset]
  );

  res.json({ page, totalPages, total, items: rows });
});

app.post("/api/songs", requireAuth, requireApproved, async (req, res) => {
  const cantor = String(req.body?.cantor || "").trim();
  const musica = String(req.body?.musica || "").trim();
  const tom = String(req.body?.tom || "").trim();
  const link = String(req.body?.link || "").trim();

  if (!cantor || !musica) return res.status(400).json({ error: "Cantor e música são obrigatórios" });

  const { rows } = await pool.query(
    `INSERT INTO songs (cantor, musica, tom, link, author_id)
     VALUES ($1,$2,$3,$4,$5)
     RETURNING id, cantor, musica, tom, link, author_id`,
    [cantor, musica, tom, link, req.user.id]
  );
  res.json(rows[0]);
});

app.put("/api/songs/:id", requireAuth, requireApproved, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).json({ error: "ID inválido" });

  // Permissão: admin/super ou autor
  const songRes = await pool.query(`SELECT author_id FROM songs WHERE id=$1`, [id]);
  const song = songRes.rows[0];
  if (!song) return res.status(404).json({ error: "Música não encontrada" });

  const canEdit = req.user.is_admin || req.user.is_super || (song.author_id === req.user.id);
  if (!canEdit) return res.status(403).json({ error: "Sem permissão para editar" });

  const cantor = String(req.body?.cantor || "").trim();
  const musica = String(req.body?.musica || "").trim();
  const tom = String(req.body?.tom || "").trim();
  const link = String(req.body?.link || "").trim();
  if (!cantor || !musica) return res.status(400).json({ error: "Cantor e música são obrigatórios" });

  const { rows } = await pool.query(
    `UPDATE songs SET cantor=$1, musica=$2, tom=$3, link=$4, updated_at=now()
     WHERE id=$5
     RETURNING id, cantor, musica, tom, link, author_id`,
    [cantor, musica, tom, link, id]
  );
  res.json(rows[0]);
});

app.get("/api/songs/pdf", requireAuth, requireApproved, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT cantor, musica, link
     FROM songs
     ORDER BY lower(musica) ASC, lower(cantor) ASC`
  );

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", "attachment; filename=musicas.pdf");

  const doc = new PDFDocument({ margin: 40 });
  doc.pipe(res);

  doc.fontSize(18).text("Músicas", { align: "center" });
  doc.moveDown();

  doc.fontSize(11);
  rows.forEach((r, i) => {
    doc.text(`${i + 1}. ${r.cantor} - ${r.musica}`);
    if (r.link) doc.fontSize(9).fillColor("blue").text(r.link).fillColor("black").fontSize(11);
    doc.moveDown(0.4);
  });

  doc.end();
});

// ============================
// LISTAS
// ============================
app.get("/api/lists", requireAuth, requireApproved, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, name, description, created_at, updated_at
     FROM lists
     ORDER BY lower(name) ASC`
  );
  res.json(rows);
});

app.post("/api/lists", requireAuth, requireApproved, requireAdminOrSuper, async (req, res) => {
  const name = String(req.body?.name || "").trim();
  const description = String(req.body?.description || "").trim();
  if (!name) return res.status(400).json({ error: "Nome da lista é obrigatório" });

  try {
    const { rows } = await pool.query(
      `INSERT INTO lists (name, description, created_by)
       VALUES ($1,$2,$3)
       RETURNING id, name, description, created_at, updated_at`,
      [name, description, req.user.id]
    );
    res.json(rows[0]);
  } catch (e) {
    if (String(e.message || "").toLowerCase().includes("idx_lists_name_unique")) {
      return res.status(409).json({ error: "Já existe uma lista com esse nome" });
    }
    console.error(e);
    return res.status(500).json({ error: "Erro ao criar lista" });
  }
});

app.put("/api/lists/:id", requireAuth, requireApproved, requireAdminOrSuper, async (req, res) => {
  const id = Number(req.params.id);
  const name = String(req.body?.name || "").trim();
  const description = String(req.body?.description || "").trim();
  if (!Number.isFinite(id)) return res.status(400).json({ error: "ID inválido" });
  if (!name) return res.status(400).json({ error: "Nome da lista é obrigatório" });

  try {
    const { rows } = await pool.query(
      `UPDATE lists SET name=$1, description=$2, updated_at=now()
       WHERE id=$3
       RETURNING id, name, description, created_at, updated_at`,
      [name, description, id]
    );
    if (!rows[0]) return res.status(404).json({ error: "Lista não encontrada" });
    res.json(rows[0]);
  } catch (e) {
    if (String(e.message || "").toLowerCase().includes("idx_lists_name_unique")) {
      return res.status(409).json({ error: "Já existe uma lista com esse nome" });
    }
    console.error(e);
    return res.status(500).json({ error: "Erro ao editar lista" });
  }
});

app.delete("/api/lists/:id", requireAuth, requireApproved, requireAdminOrSuper, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).json({ error: "ID inválido" });

  const { rowCount } = await pool.query(`DELETE FROM lists WHERE id=$1`, [id]);
  if (!rowCount) return res.status(404).json({ error: "Lista não encontrada" });
  res.json({ ok: true });
});

app.get("/api/lists/:id/songs", requireAuth, requireApproved, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).json({ error: "ID inválido" });

  const { rows } = await pool.query(
    `SELECT s.id, s.cantor, s.musica, s.tom, s.link, s.author_id
     FROM list_songs ls
     JOIN songs s ON s.id = ls.song_id
     WHERE ls.list_id = $1
     ORDER BY lower(s.musica) ASC, lower(s.cantor) ASC`,
    [id]
  );
  res.json(rows);
});

app.post("/api/lists/:id/songs", requireAuth, requireApproved, requireAdminOrSuper, async (req, res) => {
  const listId = Number(req.params.id);
  const songId = Number(req.body?.songId ?? req.body?.song_id); // aceita os 2 formatos

  if (!Number.isFinite(listId)) return res.status(400).json({ error: "listId inválido" });
  if (!Number.isFinite(songId)) return res.status(400).json({ error: "songId inválido" });

  await pool.query(
    `INSERT INTO list_songs (list_id, song_id, added_by)
     VALUES ($1,$2,$3)
     ON CONFLICT (list_id, song_id) DO NOTHING`,
    [listId, songId, req.user.id]
  );

  res.json({ ok: true });
});

app.delete("/api/lists/:id/songs/:songId", requireAuth, requireApproved, requireAdminOrSuper, async (req, res) => {
  const listId = Number(req.params.id);
  const songId = Number(req.params.songId);

  if (!Number.isFinite(listId)) return res.status(400).json({ error: "listId inválido" });
  if (!Number.isFinite(songId)) return res.status(400).json({ error: "songId inválido" });

  await pool.query(`DELETE FROM list_songs WHERE list_id=$1 AND song_id=$2`, [listId, songId]);
  res.json({ ok: true });
});

// ============================
// Servir FRONTEND da raiz /public
// ============================
// Como o Render está rodando dentro de /webapp-musicas-api,
// precisamos apontar para ../public (da raiz do repo).
const publicDir = path.join(__dirname, "..", "public");
app.use(express.static(publicDir));

// fallback: abre index
app.get("/", (req, res) => {
  res.sendFile(path.join(publicDir, "index.html"));
});

// ============================
// Start
// ============================
app.listen(PORT, () => {
  console.log(`✅ API rodando na porta ${PORT}`);
});
