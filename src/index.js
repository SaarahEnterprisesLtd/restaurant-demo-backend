// src/index.js (CommonJS)

const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, "../.env") });

const dns = require("dns");
dns.setDefaultResultOrder("ipv4first");

const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");


const app = express();

// --------- Middleware ----------
app.use(express.json());
app.use(cookieParser());

// Allow multiple origins (local + Vercel later)
const allowedOrigins = (process.env.CORS_ORIGIN || "http://localhost:5173")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: function (origin, cb) {
      // allow requests like curl/postman (no origin)
      if (!origin) return cb(null, true);
      if (allowedOrigins.includes(origin)) return cb(null, true);
      return cb(new Error("Not allowed by CORS: " + origin));
    },
    credentials: true,
  })
);

// --------- MySQL Pool (DO Managed MySQL uses TLS) ----------
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: { rejectUnauthorized: false },
});

function signToken(payload) {
    return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "7d" });
  }
  
  function authCookieOptions() {
    const secure = String(process.env.COOKIE_SECURE) === "true";
    return {
      httpOnly: true,
      secure,
      sameSite: secure ? "none" : "lax", // cross-site cookies require Secure + None
      path: "/",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    };
  }
  
  function requireAuth(req, res, next) {
    try {
      const token = req.cookies?.token;
      if (!token) return res.status(401).json({ message: "Unauthorized" });
  
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded; // { id, role }
      next();
    } catch {
      return res.status(401).json({ message: "Unauthorized" });
    }
  }
  
  function requireAdmin(req, res, next) {
    if (req.user?.role !== "admin") return res.status(403).json({ message: "Forbidden" });
    next();
  }

// --------- Routes ----------
app.get("/health", async (_req, res) => {
  try {
    const [rows] = await pool.query("SELECT 1 AS ok");
    res.json({ ok: true, db: rows[0]?.ok === 1 });
  } catch (e) {
    res.status(500).json({
      ok: false,
      db: false,
      code: e?.code,
      message: e?.message,
      raw: String(e),
    });
  }
});

app.get("/db-test", async (_req, res) => {
  try {
    const [rows] = await pool.query("SELECT 1 AS ok");
    res.json({ ok: true, db: rows[0]?.ok === 1 });
  } catch (e) {
    res.status(500).json({
      ok: false,
      code: e?.code,
      message: e?.message,
      raw: String(e),
    });
  }
});

// Public menu endpoint
app.get("/menu", async (_req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, name, description, price_cents, currency, image_url AS imageUrl
       FROM menu_items
       WHERE is_available = 1
       ORDER BY sort_order ASC, id DESC`
    );

    const items = rows.map((r) => ({
      id: r.id,
      name: r.name,
      description: r.description,
      // cents → pounds (as string "9.99")
      price: (Number(r.price_cents) / 100).toFixed(2),
      currency: r.currency,
      imageUrl: r.imageUrl,
    }));

    res.json({ items });
  } catch (e) {
    res.status(500).json({
      message: "Failed to load menu",
      code: e?.code,
      error: e?.message,
      raw: String(e),
    });
  }
});

// --------- Start Server ----------
const port = Number(process.env.PORT || 8080);

app.post("/auth/register", async (req, res) => {
    try {
      const { name, email, password } = req.body || {};
      if (!name || !email || !password) {
        return res.status(400).json({ message: "name, email, password are required" });
      }
  
      const normalizedEmail = String(email).trim().toLowerCase();
  
      const passwordHash = await bcrypt.hash(password, 10);
  
      const [result] = await pool.query(
        `INSERT INTO users (name, email, password_hash, role)
         VALUES (?, ?, ?, 'user')`,
        [name.trim(), normalizedEmail, passwordHash]
      );
  
      const user = { id: result.insertId, name: name.trim(), email: normalizedEmail, role: "user" };
  
      const token = signToken({ id: user.id, role: user.role });
      res.cookie("token", token, authCookieOptions());
  
      res.status(201).json({ user });
    } catch (e) {
      // duplicate email
      if (e?.code === "ER_DUP_ENTRY") {
        return res.status(409).json({ message: "Email already registered" });
      }
      res.status(500).json({ message: "Register failed", error: e.message });
    }
  });
  
  app.post("/auth/login", async (req, res) => {
    try {
      const { email, password } = req.body || {};
      if (!email || !password) return res.status(400).json({ message: "email and password are required" });
  
      const normalizedEmail = String(email).trim().toLowerCase();
  
      const [rows] = await pool.query(
        `SELECT id, name, email, password_hash, role, is_active
         FROM users
         WHERE email = ?
         LIMIT 1`,
        [normalizedEmail]
      );
  
      const u = rows[0];
      if (!u || !u.is_active) return res.status(401).json({ message: "Invalid credentials" });
  
      const ok = await bcrypt.compare(password, u.password_hash);
      if (!ok) return res.status(401).json({ message: "Invalid credentials" });
  
      const token = signToken({ id: u.id, role: u.role });
      res.cookie("token", token, authCookieOptions());
  
      res.json({ user: { id: u.id, name: u.name, email: u.email, role: u.role } });
    } catch (e) {
      res.status(500).json({ message: "Login failed", error: e.message });
    }
  });
  
  app.get("/auth/me", requireAuth, async (req, res) => {
    try {
      const [rows] = await pool.query(
        `SELECT id, name, email, role
         FROM users
         WHERE id = ?
         LIMIT 1`,
        [req.user.id]
      );
  
      const u = rows[0];
      if (!u) return res.status(401).json({ message: "Unauthorized" });
  
      res.json({ user: u });
    } catch (e) {
      res.status(500).json({ message: "Failed to fetch user", error: e.message });
    }
  });
  
  app.post("/auth/logout", (_req, res) => {
    res.clearCookie("token", { path: "/" });
    res.json({ ok: true });
  });

app.listen(port, async () => {
  try {
    const [rows] = await pool.query("SELECT 1 AS ok");
    console.log("DB connected:", rows[0]?.ok === 1);
  } catch (e) {
    console.log("DB connected: false", e?.code, e?.message);
  }
  console.log("API running on", port);
});
