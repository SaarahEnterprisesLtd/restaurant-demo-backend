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
const crypto = require("crypto");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;

const app = express();

// If you're behind a reverse proxy / load balancer / TLS termination (common on DO)
app.set("trust proxy", 1);

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

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 6 * 1024 * 1024 }, // 6MB
});

function uploadBuffer(buffer, options = {}) {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(options, (err, result) => {
      if (err) reject(err);
      else resolve(result);
    });
    stream.end(buffer);
  });
}

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

// --------- Auth helpers ----------
function signToken(payload) {
  // NOTE: no refresh token yet — simple & works. Add refresh later.
  const expiresIn = process.env.JWT_EXPIRES_IN || "15m";
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn });
}

function authCookieOptions() {
  const isProd = process.env.NODE_ENV === "production";
  const secure = isProd ? true : String(process.env.COOKIE_SECURE) === "true";

  return {
    httpOnly: true,
    secure:true, // true in production (HTTPS)
    sameSite: "none", // ✅ subdomains are same-site (app.domain.com <-> api.domain.com)
    path: "/",
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days cookie lifetime (token may expire earlier)

    // ✅ Share cookie across subdomains in prod (apex domain)
    ...(isProd && process.env.COOKIE_DOMAIN
      ? { domain: process.env.COOKIE_DOMAIN }
      : {}),
  };
}

function requireAuth(req, res, next) {
  const token = req.cookies?.token;

  if (!token) {
    return res.status(401).json({
      message: "Unauthorized",
      code: "NO_TOKEN",
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // { id, role }
    next();
  } catch (e) {
    if (e?.name === "TokenExpiredError") {
      return res.status(401).json({
        message: "Session expired",
        code: "TOKEN_EXPIRED",
      });
    }

    return res.status(401).json({
      message: "Unauthorized",
      code: "TOKEN_INVALID",
    });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== "admin") return res.status(403).json({ message: "Forbidden" });
  next();
}

function guestCartCookieOptions() {
  const isProd = process.env.NODE_ENV === "production";
  const secure = isProd ? true : String(process.env.COOKIE_SECURE) === "true";

  return {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    path: "/",
    maxAge: 7 * 24 * 60 * 60 * 1000,
    ...(isProd && process.env.COOKIE_DOMAIN
      ? { domain: process.env.COOKIE_DOMAIN }
      : {}),
  };
}

function newGuestToken() {
  return crypto.randomBytes(32).toString("hex"); // 64 chars
}

async function getOrCreateActiveCartId(userId) {
  const [rows] = await pool.query(
    `SELECT id FROM carts WHERE user_id = ? AND status = 'active' LIMIT 1`,
    [userId]
  );
  if (rows[0]) return rows[0].id;

  const [result] = await pool.query(
    `INSERT INTO carts (user_id, status) VALUES (?, 'active')`,
    [userId]
  );
  return result.insertId;
}

app.post(
  "/admin/upload-image",
  requireAuth,
  requireAdmin,
  upload.single("file"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: "No file uploaded" });
      }

      if (!req.file.mimetype.startsWith("image/")) {
        return res.status(400).json({ message: "Only images allowed" });
      }

      const result = await uploadBuffer(req.file.buffer, {
        folder: process.env.CLOUDINARY_FOLDER || "menu",
        resource_type: "image",
        transformation: [
          { width: 1200, crop: "limit" },
          { quality: "auto" },
          { fetch_format: "auto" },
        ],
      });

      res.json({
        ok: true,
        url: result.secure_url,
      });
    } catch (e) {
      console.error("❌ Cloudinary upload failed:", e);
      res.status(500).json({
        message: "Upload failed",
        error: e.message,
        name: e?.name,
      });
    }
  }
);

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

app.get("/menu", async (_req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT
         mi.id,
         mi.name,
         mi.description,
         mi.price_cents,
         mi.currency,
         mi.image_url AS imageUrl,
         mi.category_id AS categoryId,
         c.name AS categoryName
       FROM menu_items mi
       LEFT JOIN categories c ON c.id = mi.category_id
       WHERE mi.is_available = 1
       ORDER BY c.sort_order ASC, mi.sort_order ASC, mi.id DESC`
    );

    const items = rows.map((r) => ({
      id: r.id,
      name: r.name,
      description: r.description,
      price: (Number(r.price_cents) / 100).toFixed(2),
      currency: r.currency,
      imageUrl: r.imageUrl,
      categoryId: r.categoryId,
      categoryName: r.categoryName,
    }));

    res.json({ items });
  } catch (e) {
    res.status(500).json({ message: "Failed to load menu", error: e?.message });
  }
});

// Admin: list all menu items (including unavailable) + category info
app.get("/admin/menu", requireAuth, requireAdmin, async (_req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT
         mi.id,
         mi.name,
         mi.description,
         mi.price_cents,
         mi.currency,
         mi.image_url AS imageUrl,
         mi.is_available,
         mi.sort_order,
         mi.category_id AS categoryId,
         c.name AS categoryName
       FROM menu_items mi
       LEFT JOIN categories c ON c.id = mi.category_id
       ORDER BY mi.sort_order ASC, mi.id DESC`
    );

    res.json({ items: rows });
  } catch (e) {
    res.status(500).json({ message: "Failed to load admin menu", error: e?.message });
  }
});

app.get("/admin/categories", requireAuth, requireAdmin, async (_req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, name, sort_order, is_active
       FROM categories
       WHERE is_active = 1
       ORDER BY sort_order ASC, name ASC`
    );

    res.json({ categories: rows });
  } catch (e) {
    res.status(500).json({ message: "Failed to load categories", error: e?.message });
  }
});

app.post("/admin/menu", requireAuth, requireAdmin, async (req, res) => {
  try {
    const {
      name,
      description,
      price_cents,
      currency,
      imageUrl,
      is_available,
      sort_order,
      category_id,
    } = req.body || {};

    if (!name || price_cents == null || !currency) {
      return res.status(400).json({ message: "name, price_cents, currency are required" });
    }

    // category_id is optional (can be null) but if present must exist
    let catId = null;
    if (category_id !== undefined && category_id !== null && category_id !== "") {
      catId = Number(category_id);
      if (!Number.isFinite(catId)) {
        return res.status(400).json({ message: "category_id must be a number" });
      }

      const [cats] = await pool.query(
        `SELECT id FROM categories WHERE id = ? AND is_active = 1 LIMIT 1`,
        [catId]
      );
      if (!cats[0]) return res.status(400).json({ message: "Invalid category_id" });
    }

    const [result] = await pool.query(
      `INSERT INTO menu_items
        (name, description, price_cents, currency, image_url, is_available, sort_order, category_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        String(name).trim(),
        description ? String(description).trim() : "",
        Number(price_cents),
        String(currency).trim(),
        imageUrl || null,
        is_available ? 1 : 0,
        Number(sort_order || 0),
        catId,
      ]
    );

    res.status(201).json({ id: result.insertId });
  } catch (e) {
    res.status(500).json({ message: "Failed to create menu item", error: e?.message });
  }
});

app.get("/admin/menu/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ message: "Invalid id" });

    const [rows] = await pool.query(
      `SELECT
         mi.id,
         mi.name,
         mi.description,
         mi.price_cents,
         mi.currency,
         mi.image_url AS imageUrl,
         mi.is_available,
         mi.sort_order,
         mi.category_id AS categoryId
       FROM menu_items mi
       WHERE mi.id = ?
       LIMIT 1`,
      [id]
    );

    const item = rows[0];
    if (!item) return res.status(404).json({ message: "Not found" });

    res.json({ item });
  } catch (e) {
    res.status(500).json({ message: "Failed to load menu item", error: e?.message });
  }
});

// Admin: delete menu item (soft delete -> mark unavailable)
app.delete("/admin/menu/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ message: "Invalid id" });

    const [result] = await pool.query(
      "UPDATE menu_items SET is_available = 0 WHERE id = ?",
      [id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Not found" });
    }

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ message: "Failed to delete menu item", error: e?.message });
  }
});

app.put("/admin/menu/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ message: "Invalid id" });

    const {
      name,
      description,
      price_cents,
      currency,
      imageUrl,
      is_available,
      sort_order,
      category_id,
    } = req.body || {};

    // Validate category_id if provided (allow null)
    let catId = null;
    if (category_id !== undefined) {
      if (category_id === null || category_id === "") {
        catId = null;
      } else {
        catId = Number(category_id);
        if (!Number.isFinite(catId)) return res.status(400).json({ message: "category_id must be a number" });

        const [cats] = await pool.query(
          `SELECT id FROM categories WHERE id = ? AND is_active = 1 LIMIT 1`,
          [catId]
        );
        if (!cats[0]) return res.status(400).json({ message: "Invalid category_id" });
      }
    }

    await pool.query(
      `UPDATE menu_items
       SET name = COALESCE(?, name),
           description = COALESCE(?, description),
           price_cents = COALESCE(?, price_cents),
           currency = COALESCE(?, currency),
           image_url = COALESCE(?, image_url),
           is_available = COALESCE(?, is_available),
           sort_order = COALESCE(?, sort_order),
           category_id = COALESCE(?, category_id)
       WHERE id = ?`,
      [
        name != null ? String(name).trim() : null,
        description != null ? String(description).trim() : null,
        price_cents != null ? Number(price_cents) : null,
        currency != null ? String(currency).trim() : null,
        imageUrl != null ? imageUrl : null,
        is_available != null ? (is_available ? 1 : 0) : null,
        sort_order != null ? Number(sort_order) : null,
        category_id !== undefined ? catId : null, // only set when provided
        id,
      ]
    );

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ message: "Failed to update menu item", error: e?.message });
  }
});

async function getOrCreateActiveCartId(userId) {
  const [rows] = await pool.query(
    `SELECT id FROM carts WHERE user_id = ? AND status = 'active' LIMIT 1`,
    [userId]
  );
  if (rows[0]) return rows[0].id;

  const [result] = await pool.query(
    `INSERT INTO carts (user_id, status) VALUES (?, 'active')`,
    [userId]
  );
  return result.insertId;
}

app.get("/cart", requireAuth, async (req, res) => {
  try {
    const cartId = await getOrCreateActiveCartId(req.user.id);

    const [rows] = await pool.query(
      `SELECT
         ci.menu_item_id AS id,
         mi.name,
         mi.image_url AS imageUrl,
         ci.qty,
         (ci.unit_price_cents / 100) AS price,
         ci.currency
       FROM cart_items ci
       JOIN menu_items mi ON mi.id = ci.menu_item_id
       WHERE ci.cart_id = ?
       ORDER BY ci.id DESC`,
      [cartId]
    );

    // Normalize price as string "12.00" like your menu API
    const items = rows.map((r) => ({
      id: r.id,
      name: r.name,
      imageUrl: r.imageUrl,
      qty: r.qty,
      price: Number(r.price).toFixed(2),
      currency: r.currency,
    }));

    res.json({ cartId, items });
  } catch (e) {
    res.status(500).json({ message: "Failed to load cart", error: e?.message });
  }
});

app.post("/cart/items", requireAuth, async (req, res) => {
  try {
    const { menuItemId, qty } = req.body || {};
    const mid = Number(menuItemId);
    const q = qty == null ? 1 : Number(qty);

    if (!Number.isFinite(mid) || mid <= 0) {
      return res.status(400).json({ message: "menuItemId is required" });
    }
    if (!Number.isFinite(q) || q <= 0) {
      return res.status(400).json({ message: "qty must be > 0" });
    }

    // Ensure menu item exists + get price
    const [menuRows] = await pool.query(
      `SELECT id, price_cents, currency, is_available
       FROM menu_items
       WHERE id = ?
       LIMIT 1`,
      [mid]
    );
    const mi = menuRows[0];
    if (!mi) return res.status(404).json({ message: "Menu item not found" });
    if (!mi.is_available) return res.status(400).json({ message: "Item not available" });

    const cartId = await getOrCreateActiveCartId(req.user.id);

    await pool.query(
      `INSERT INTO cart_items (cart_id, menu_item_id, qty, unit_price_cents, currency)
       VALUES (?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
         qty = qty + VALUES(qty),
         unit_price_cents = VALUES(unit_price_cents),
         currency = VALUES(currency),
         updated_at = CURRENT_TIMESTAMP`,
      [cartId, mid, q, mi.price_cents, mi.currency]
    );

    res.status(201).json({ ok: true });
  } catch (e) {
    res.status(500).json({ message: "Failed to add cart item", error: e?.message });
  }
});

app.patch("/cart/items/:menuItemId", requireAuth, async (req, res) => {
  try {
    const mid = Number(req.params.menuItemId);
    const { qty } = req.body || {};
    const q = Number(qty);

    if (!Number.isFinite(mid) || mid <= 0) return res.status(400).json({ message: "Invalid menuItemId" });
    if (!Number.isFinite(q) || q < 0) return res.status(400).json({ message: "qty must be >= 0" });

    const cartId = await getOrCreateActiveCartId(req.user.id);

    if (q === 0) {
      await pool.query(
        `DELETE FROM cart_items WHERE cart_id = ? AND menu_item_id = ?`,
        [cartId, mid]
      );
      return res.json({ ok: true });
    }

    const [result] = await pool.query(
      `UPDATE cart_items
       SET qty = ?, updated_at = CURRENT_TIMESTAMP
       WHERE cart_id = ? AND menu_item_id = ?`,
      [q, cartId, mid]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Cart item not found" });
    }

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ message: "Failed to update cart item", error: e?.message });
  }
});

app.delete("/cart/items/:menuItemId", requireAuth, async (req, res) => {
  try {
    const mid = Number(req.params.menuItemId);
    if (!Number.isFinite(mid) || mid <= 0) return res.status(400).json({ message: "Invalid menuItemId" });

    const cartId = await getOrCreateActiveCartId(req.user.id);

    await pool.query(
      `DELETE FROM cart_items WHERE cart_id = ? AND menu_item_id = ?`,
      [cartId, mid]
    );

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ message: "Failed to remove cart item", error: e?.message });
  }
});

app.post("/guest-cart", async (req, res) => {
  try {
    const { items } = req.body || {};
    const list = Array.isArray(items) ? items : [];

    // Minimal validation
    const normalized = list
      .map((x) => ({
        id: Number(x.id),
        qty: Number(x.qty || 1),
      }))
      .filter((x) => Number.isFinite(x.id) && x.id > 0 && Number.isFinite(x.qty) && x.qty > 0);

    if (normalized.length === 0) {
      return res.status(400).json({ message: "Cart is empty" });
    }

    // Validate items against DB (prevents client price tampering)
    const ids = [...new Set(normalized.map((x) => x.id))];
    const [menuRows] = await pool.query(
      `SELECT id, name, price_cents, currency, image_url AS imageUrl, is_available
       FROM menu_items
       WHERE id IN (${ids.map(() => "?").join(",")})`,
      ids
    );

    const byId = new Map(menuRows.map((r) => [Number(r.id), r]));

    const fullItems = normalized.map((x) => {
      const mi = byId.get(x.id);
      if (!mi) throw new Error("Invalid menu item");
      if (!mi.is_available) throw new Error("Item not available");
      return {
        id: x.id,
        name: mi.name,
        qty: x.qty,
        price_cents: Number(mi.price_cents),
        currency: mi.currency,
        imageUrl: mi.imageUrl || null,
      };
    });

    const existingToken = req.cookies?.guest_cart;
    const token = existingToken || newGuestToken();

    // Upsert into guest_carts
    await pool.query(
      `INSERT INTO guest_carts (token, cart_json)
       VALUES (?, ?)
       ON DUPLICATE KEY UPDATE cart_json = VALUES(cart_json), updated_at = CURRENT_TIMESTAMP`,
      [token, JSON.stringify({ items: fullItems })]
    );

    // store token in httpOnly cookie
    res.cookie("guest_cart", token, guestCartCookieOptions());

    res.json({ ok: true, token });
  } catch (e) {
    res.status(500).json({ message: "Failed to save guest cart", error: e?.message });
  }
});

app.get("/guest-cart", async (req, res) => {
  try {
    const token = req.cookies?.guest_cart;
    if (!token) return res.json({ items: [] });

    const [rows] = await pool.query(
      `SELECT cart_json FROM guest_carts WHERE token = ? LIMIT 1`,
      [token]
    );

    const raw = rows[0]?.cart_json;

    // ✅ mysql2 may return JSON as object OR string depending on config
    let data;
    if (!raw) {
      data = { items: [] };
    } else if (typeof raw === "string") {
      data = JSON.parse(raw);
    } else {
      data = raw;
    }

    res.json({ items: Array.isArray(data?.items) ? data.items : [] });
  } catch (e) {
    res.status(500).json({ message: "Failed to load guest cart", error: e?.message });
  }
});

app.post("/cart/sync", requireAuth, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const list = Array.isArray(req.body?.items) ? req.body.items : [];

    const normalized = list
      .map((x) => ({
        id: Number(x.id),
        qty: Number(x.qty || 1),
      }))
      .filter((x) => Number.isFinite(x.id) && x.id > 0 && Number.isFinite(x.qty) && x.qty > 0);

    if (normalized.length === 0) {
      return res.status(400).json({ message: "Cart is empty" });
    }

    // Validate menu items + get canonical prices from DB
    const ids = [...new Set(normalized.map((x) => x.id))];

    const [menuRows] = await conn.query(
      `SELECT id, price_cents, currency, is_available
       FROM menu_items
       WHERE id IN (${ids.map(() => "?").join(",")})`,
      ids
    );

    const byId = new Map(menuRows.map((r) => [Number(r.id), r]));

    // Build safe rows to insert
    const safeItems = normalized.map((x) => {
      const mi = byId.get(x.id);
      if (!mi) throw new Error("Invalid menu item");
      if (!mi.is_available) throw new Error("Item not available");
      return {
        menu_item_id: x.id,
        qty: x.qty,
        unit_price_cents: Number(mi.price_cents),
        currency: mi.currency || "GBP",
      };
    });

    await conn.beginTransaction();

    const cartId = await getOrCreateActiveCartId(req.user.id);

    // Upsert each item
    for (const it of safeItems) {
      await conn.query(
        `INSERT INTO cart_items (cart_id, menu_item_id, qty, unit_price_cents, currency)
         VALUES (?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
           qty = VALUES(qty),
           unit_price_cents = VALUES(unit_price_cents),
           currency = VALUES(currency)`,
        [cartId, it.menu_item_id, it.qty, it.unit_price_cents, it.currency]
      );
    }

    // Remove items that are no longer in cart
    await conn.query(
      `DELETE FROM cart_items
       WHERE cart_id = ?
         AND menu_item_id NOT IN (${ids.map(() => "?").join(",")})`,
      [cartId, ...ids]
    );

    await conn.commit();
    res.json({ ok: true, cartId });
  } catch (e) {
    try { await conn.rollback(); } catch {}
    res.status(500).json({ message: "Failed to sync cart", error: e?.message });
  } finally {
    conn.release();
  }
});

// --------- Auth routes ----------
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
      [String(name).trim(), normalizedEmail, passwordHash]
    );

    const user = {
      id: result.insertId,
      name: String(name).trim(),
      email: normalizedEmail,
      role: "user",
    };

    const token = signToken({ id: user.id, role: user.role });
    res.cookie("token", token, authCookieOptions());

    res.status(201).json({ user });
  } catch (e) {
    if (e?.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ message: "Email already registered" });
    }
    res.status(500).json({ message: "Register failed", error: e?.message });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ message: "email and password are required" });
    }

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
    res.status(500).json({ message: "Login failed", error: e?.message });
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
    res.status(500).json({ message: "Failed to fetch user", error: e?.message });
  }
});

app.post("/auth/logout", (_req, res) => {
  const isProd = process.env.NODE_ENV === "production";

  res.clearCookie("token", {
    path: "/",
    ...(isProd && process.env.COOKIE_DOMAIN ? { domain: process.env.COOKIE_DOMAIN } : {}),
  });

  res.json({ ok: true });
});

// Example protected route (optional)
app.get("/admin/ping", requireAuth, requireAdmin, (_req, res) => {
  res.json({ ok: true, admin: true });
});

// --------- Start Server ----------
const port = Number(process.env.PORT || 8080);

app.listen(port, async () => {
  try {
    const [rows] = await pool.query("SELECT 1 AS ok");
    console.log("DB connected:", rows[0]?.ok === 1);
  } catch (e) {
    console.log("DB connected: false", e?.code, e?.message);
  }
  console.log("API running on", port);
  console.log("✅ DELETE /admin/menu/:id registered");
});
