require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: process.env.CORS_ORIGIN, credentials: true }));

app.get("/health", (_, res) => res.json({ ok: true }));

const port = process.env.PORT || 5000;
app.listen(port, () => console.log("API running on", port));
