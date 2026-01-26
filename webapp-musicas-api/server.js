import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pkg from "pg";
import path from "path";
import { fileURLToPath } from "url";

const { Pool } = pkg;

const app = express();
app.use(express.json());

// ====== CONFIG ======
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;

// Se quiser travar o CORS depois, coloque sua URL do site aqui (ex: https://seusite.onrender.com)
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";

if (!DATABASE_URL) throw new Error("DATABASE_URL não definido");
if (!JWT_SECRET) throw new Error("JWT_SECRET não definido");

app.use(cors({ origin: CORS_ORIGIN }));

// SSL compatível com Neon/Supabase no Render
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

function signToken(user) {
  return jwt.sign(
    { uid: user.id, email: user.email },
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

// ====== HEALTH ======
app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ====== AUTH ======
app.post("/api/register", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: "Email e senha são obrigatórios" });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email",
      [email.toLowerCase(), hash]
    );
    const user = result.rows[0];
    const token = signToken(user);
    res.json({ token, email: user.email });
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
      "SELECT id, email, password_hash FROM users WHERE email=$1",
      [email.toLowerCase()]
    );

    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: "Email ou senha inválidos" });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Email ou senha inválidos" });

    const token = signToken(user);
    res.json({ token, email: user.email });
  } catch (e) {
    res.status(500).json({ error: String(e.message || "") });
  }
});

// ====== SONGS ======
app.post("/api/songs", authMiddleware, async (req, res) => {
  const { cantor, musica, tom, link } = req.body || {};
  if (!cantor || !musica) {
    return res.status(400).json({ error: "cantor e musica são obrigatórios" });
  }

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

// ====== STATIC SITE (serve /public) ======
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.join(__dirname, "public");

app.use(express.static(publicDir));

app.get("/", (req, res) => {
  res.sendFile(path.join(publicDir, "index.html"));
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Rodando na porta", port));
