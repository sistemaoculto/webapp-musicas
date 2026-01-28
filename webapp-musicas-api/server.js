// ===== IMPORTS =====
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

// ===== DB =====
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("localhost")
    ? false
    : { rejectUnauthorized: false }
});

// ===== MIDDLEWARE =====
app.use(cors({
  origin: process.env.CORS_ORIGIN,
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());

// ===== PING / HEALTHCHECK =====
app.get("/ping", (req, res) => {
  res.status(200).json({ status: "ok" });
});

// ===== AUTH HELPERS =====
function requireAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Não autenticado" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "Token inválido" });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user?.is_admin) {
    return res.status(403).json({ error: "Apenas admin" });
  }
  next();
}

function requireAdminOrSuper(req, res, next) {
  if (req.user?.is_admin || req.user?.is_super) return next();
  return res.status(403).json({ error: "Sem permissão" });
}

// ===== ROTAS AUTH =====
// (login, register, me, logout)
// 🔴 aqui entra exatamente o código que você já tem
// 🔴 nada foi removido, só omitido aqui para foco no ping

// ===== ROTAS SONGS =====
// (songs, pdf, search, etc)

// ===== ROTAS LISTAS =====
// (lists, list_songs)

// ===== ROTAS ADMIN =====
// (approve, deny, super)

// ===== STATIC FILES =====
app.use(express.static("public"));

// ===== START =====
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
