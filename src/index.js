require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const mysql = require("mysql2/promise");

const app = express();
app.use(express.json());
app.use(cookieParser());

// Allow multiple origins (local + vercel later)
const allowedOrigins = (process.env.CORS_ORIGIN || "http://localhost:5173")
  .split(",")
  .map((s) => s.trim());

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

// ✅ MySQL pool (DigitalOcean Managed MySQL uses TLS)
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

app.get("/health", async (_req, res) => {
  try {
    const [rows] = await pool.query("SELECT 1 AS ok");
    res.json({ ok: true, db: rows[0]?.ok === 1 });
  } catch (e) {
    res.status(500).json({ ok: false, db: false, error: e.message });
  }
});

// ✅ Public menu endpoint
app.get("/menu", async (_req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, name, description, price_cents, currency, image_url AS imageUrl
       FROM menu_items
       WHERE is_available = 1
       ORDER BY sort_order ASC, id DESC`
    );

    // convert cents → pounds for your current frontend
    const items = rows.map((r) => ({
      id: r.id,
      name: r.name,
      description: r.description,
      price: (Number(r.price_cents) / 100).toFixed(2),
      currency: r.currency,
      imageUrl: r.imageUrl,
    }));

    res.json({ items });
  } catch (e) {
    res.status(500).json({ message: "Failed to load menu", error: e.message });
  }
});

app.get("/db-test", async (_req, res) => {
    try {
      const [rows] = await pool.query("SELECT 1 AS ok");
      res.json({ ok: true, db: rows[0].ok });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

const port = process.env.PORT || 8080; // ✅ use 8080 for Railway
app.listen(port, async () => {
  try {
    const [rows] = await pool.query("SELECT 1 AS ok");
    console.log("DB connected:", rows[0]?.ok === 1);
  } catch (e) {
    console.log("DB connected: false", e.message);
  }
  console.log("API running on", port);
});
