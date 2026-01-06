const express = require("express");
const mongoose = require("mongoose");
const crypto = require("crypto");

const app = express();
app.use(express.json());

/* ================= DB ================= */

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => {
    console.error("❌ MongoDB error", err);
    process.exit(1);
  });

/* ================= MODEL ================= */

const LicenseSchema = new mongoose.Schema({
  key: { type: String, unique: true },
  active: Boolean,
  hwid: String,
  bots: {
    type: Map,
    of: {
      expiresAt: Date
    }
  }
});

const License = mongoose.model("License", LicenseSchema);

/* ================= UTILS ================= */

function generateKey() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const pick = (l) =>
    Array.from({ length: l }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
  return `${pick(4)}-${pick(3)}-${pick(4)}`;
}

function formatDate(date) {
  return date.toLocaleString("pl-PL", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  });
}

function hwidFromSeed(seed) {
  return crypto.createHash("sha256").update(seed).digest("hex");
}

/* ================= LICENSE CHECK ================= */

app.post("/license/check", async (req, res) => {
  const { key, botId, hwidSeed } = req.body;
  if (!key || !botId || !hwidSeed) {
    return res.json({ ok: false, reason: "BAD_REQUEST" });
  }

  const lic = await License.findOne({ key });
  if (!lic) return res.json({ ok: false, reason: "INVALID_KEY" });
  if (!lic.active) return res.json({ ok: false, reason: "DISABLED" });

  const bot = lic.bots.get(botId);
  if (!bot) return res.json({ ok: false, reason: "WRONG_BOT" });

  if (Date.now() > bot.expiresAt.getTime()) {
    return res.json({ ok: false, reason: "EXPIRED" });
  }

  const hwid = hwidFromSeed(hwidSeed);

  if (!lic.hwid) {
    lic.hwid = hwid;
    await lic.save();
  } else if (lic.hwid !== hwid) {
    return res.json({ ok: false, reason: "HWID_MISMATCH" });
  }

  res.json({
    ok: true,
    expiresAt: bot.expiresAt.toISOString(),
    expiresAtHuman: formatDate(bot.expiresAt)
  });
});

/* ================= ADMIN GENERATE ================= */

app.post("/admin/generate", async (req, res) => {
  const { botId, days, adminKey } = req.body;

  if (adminKey !== process.env.ADMIN_KEY) {
    return res.status(403).json({ ok: false, reason: "FORBIDDEN" });
  }

  if (!botId || !days) {
    return res.status(400).json({ ok: false, reason: "BAD_REQUEST" });
  }

  const key = generateKey();
  const expiresAt = new Date(Date.now() + Number(days) * 86400000);

  await License.create({
    key,
    active: true,
    hwid: null,
    bots: {
      [botId]: { expiresAt }
    }
  });

  res.json({
    ok: true,
    key,
    botId,
    expiresAt: expiresAt.toISOString(),
    expiresAtHuman: formatDate(expiresAt)
  });
});

/* ================= START ================= */

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log("🚀 LICENSE SERVER RUNNING ON PORT", PORT);
});
