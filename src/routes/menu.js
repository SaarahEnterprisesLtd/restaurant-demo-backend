import { Router } from "express";
import { pool } from "../db.js";

const router = Router();

router.get("/", async (_req, res) => {
  const [rows] = await pool.query(
    `SELECT id, name, description, price_cents, currency, image_url AS imageUrl
     FROM menu_items
     WHERE is_available = 1
     ORDER BY sort_order ASC, id DESC`
  );
  res.json({ items: rows });
});

export default router;
