import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pkg from "pg";
import path from "path";
import { fileURLToPath } from "url";
import PDFDocument from "pdfkit";

const { Pool } = pkg;

const app = express();
app.use(express.json());

const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";

if (!DATABASE_URL) throw new Error("DATABASE_URL não definido");
if (!JWT_SECRET) throw new Error("JWT_SECRET não definido");

app.use(cors({ origin: CORS_ORIGIN }));

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

function signToken(user) {
  return jwt.sign(
    { uid: user.id, email: user.email, name: user.name || "" },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || "";
  const parts = header.split(" ");
  const token = parts.length === 2 ? parts[1] : null;

  if (!token) return res.status(401).json({ error: "Sem token" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ error: "Token inválido" });
  }
}

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ===== AUTH =====
app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) {
    return res.status(400).json({ error: "Nome, email e senha são obrigatórios" });
  }

  try {
    const hash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email",
      [name.trim(), email.toLowerCase(), hash]
    );

    const user = result.rows[0];
    res.json({ token: signToken(user), name: user.name, email: user.email });
  } catch (e) {
    const msg = String(e.message || "");
    if (msg.includes("duplicate key") || msg.includes("users_email_key")) {
      return res.status(409).json({ error: "Email já cadastrado" });
    }
    res.status(500).json({ error: msg });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: "Email e senha são obrigatórios" });
  }

  try {
    const result = await pool.query(
      "SELECT id, name, email, password_hash FROM users WHERE email=$1",
      [email.toLowerCase()]
    );

    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: "Email ou senha inválidos" });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Email ou senha inválidos" });

    res.json({ token: signToken(user), name: user.name || "", email: user.email });
  } catch (e) {
    res.status(500).json({ error: String(e.message || "") });
  }
});

// ===== SONGS =====

// CREATE
app.post("/api/songs", authMiddleware, async (req, res) => {
  const { cantor, musica, tom, link } = req.body || {};
  if (!cantor || !musica) return res.status(400).json({ error: "cantor e musica são obrigatórios" });

  try {
    const r = await pool.query(
      `INSERT INTO songs (user_id, cantor, musica, tom, link)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, cantor, musica, tom, link, created_at`,
      [req.user.uid, cantor, musica, tom || null, link || null]
    );
    res.json(r.rows[0]);
  } catch (e) {
    res.status(500).json({ error: String(e.message || "") });
  }
});

// UPDATE
app.put("/api/songs/:id", authMiddleware, async (req, res) => {
  const id = Number(req.params.id);
  const { cantor, musica, tom, link } = req.body || {};
  if (!id || Number.isNaN(id)) return res.status(400).json({ error: "ID inválido" });
  if (!cantor || !musica) return res.status(400).json({ error: "cantor e musica são obrigatórios" });

  try {
    const r = await pool.query(
      `UPDATE songs
       SET cantor=$1, musica=$2, tom=$3, link=$4
       WHERE id=$5 AND user_id=$6
       RETURNING id, cantor, musica, tom, link, created_at`,
      [cantor, musica, tom || null, link || null, id, req.user.uid]
    );

    if (r.rowCount === 0) return res.status(404).json({ error: "Música não encontrada" });
    res.json(r.rows[0]);
  } catch (e) {
    res.status(500).json({ error: String(e.message || "") });
  }
});

// LIST/SEARCH
app.get("/api/songs", authMiddleware, async (req, res) => {
  const q = (req.query.q || "").toString().trim();
  try {
    if (!q) {
      const r = await pool.query(
        `SELECT id, cantor, musica, tom, link, created_at
         FROM songs
         WHERE user_id=$1
         ORDER BY created_at DESC
         LIMIT 200`,
        [req.user.uid]
      );
      return res.json(r.rows);
    }

    const like = `%${q}%`;
    const r = await pool.query(
      `SELECT id, cantor, musica, tom, link, created_at
       FROM songs
       WHERE user_id=$1 AND (cantor ILIKE $2 OR musica ILIKE $2)
       ORDER BY created_at DESC
       LIMIT 200`,
      [req.user.uid, like]
    );
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ error: String(e.message || "") });
  }
});

// PAGINADO + ALFABÉTICO
app.get("/api/songs/page", authMiddleware, async (req, res) => {
  const page = Math.max(1, Number(req.query.page || 1));
  const limit = Math.min(50, Math.max(1, Number(req.query.limit || 20)));
  const offset = (page - 1) * limit;

  try {
    const totalR = await pool.query(
      `SELECT COUNT(*)::int AS total
       FROM songs
       WHERE user_id=$1`,
      [req.user.uid]
    );

    const total = totalR.rows[0]?.total || 0;
    const totalPages = Math.max(1, Math.ceil(total / limit));

    const itemsR = await pool.query(
      `SELECT id, cantor, musica, tom, link, created_at
       FROM songs
       WHERE user_id=$1
       ORDER BY LOWER(cantor) ASC, LOWER(musica) ASC
       LIMIT $2 OFFSET $3`,
      [req.user.uid, limit, offset]
    );

    res.json({ items: itemsR.rows, total, page, limit, totalPages });
  } catch (e) {
    res.status(500).json({ error: String(e.message || "") });
  }
});

// SUGGEST
app.get("/api/songs/suggest", authMiddleware, async (req, res) => {
  const q = (req.query.q || "").toString().trim();
  if (!q) return res.json([]);

  try {
    const like = `%${q}%`;
    const r = await pool.query(
      `SELECT cantor, musica
       FROM songs
       WHERE user_id=$1 AND (cantor ILIKE $2 OR musica ILIKE $2)
       ORDER BY created_at DESC
       LIMIT 20`,
      [req.user.uid, like]
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

// PDF (sem TOM)
app.get("/api/songs/pdf", authMiddleware, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT cantor, musica, link
       FROM songs
       WHERE user_id=$1
       ORDER BY LOWER(cantor) ASC, LOWER(musica) ASC`,
      [req.user.uid]
    );

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="musicas.pdf"`);

    const doc = new PDFDocument({ size: "A4", margin: 40 });
    doc.pipe(res);

    doc.fontSize(18).text("Músicas da Jhenny", { align: "left" });
    doc.moveDown(0.5);
    doc.fontSize(10).fillColor("#555").text(`Total: ${r.rows.length}`, { align: "left" });
    doc.moveDown(1);

    doc.fillColor("#000");
    doc.fontSize(11);

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

// ===== STATIC =====
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.join(__dirname, "public");

app.use(express.static(publicDir));
app.get("/", (req, res) => res.sendFile(path.join(publicDir, "index.html")));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Rodando na porta", port));
