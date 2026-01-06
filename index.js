const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.json());

/* ================= FILE ================= */
const LICENSE_FILE = path.join(__dirname, "licenses.json");

if (!fs.existsSync(LICENSE_FILE)) {
  fs.writeFileSync(LICENSE_FILE, JSON.stringify({}, null, 2));
}

/* ================= UTILS ================= */
function readLicenses() {
  return JSON.parse(fs.readFileSync(LICENSE_FILE, "utf8"));
}

function saveLicenses(data) {
  fs.writeFileSync(LICENSE_FILE, JSON.stringify(data, null, 2));
}

/* FORMAT: XXXX-XXX-XXXX */
function generateKey() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const pick = (len) =>
    Array.from({ length: len }, () => chars[Math.floor(Math.random() * chars.length)]).join("");

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
app.post("/license/check", (req, res) => {
  const { key, botId, hwidSeed } = req.body;

  if (!key || !botId || !hwidSeed) {
    return res.json({ ok: false, reason: "BAD_REQUEST" });
  }

  const licenses = readLicenses();
  const lic = licenses[key];

  if (!lic) return res.json({ ok: false, reason: "INVALID_KEY" });
  if (!lic.active) return res.json({ ok: false, reason: "DISABLED" });
  if (!lic.bots?.[botId]) return res.json({ ok: false, reason: "WRONG_BOT" });

  const expiresAt = new Date(lic.bots[botId].expiresAt);
  if (Date.now() > expiresAt.getTime()) {
    return res.json({ ok: false, reason: "EXPIRED" });
  }

  const hwid = hwidFromSeed(hwidSeed);

  if (!lic.hwid) {
    lic.hwid = hwid;
    saveLicenses(licenses);
  } else if (lic.hwid !== hwid) {
    return res.json({ ok: false, reason: "HWID_MISMATCH" });
  }

  return res.json({
    ok: true,
    expiresAt: expiresAt.toISOString(),
    expiresAtHuman: formatDate(expiresAt)
  });
});

/* ================= ADMIN GENERATE ================= */
app.post("/admin/generate", (req, res) => {
  const { botId, days, adminKey } = req.body;

  if (adminKey !== process.env.ADMIN_KEY) {
    return res.status(403).json({ ok: false, reason: "FORBIDDEN" });
  }

  if (!botId || !days) {
    return res.status(400).json({ ok: false, reason: "BAD_REQUEST" });
  }

  const licenses = readLicenses();
  const key = generateKey();
  const expiresAt = new Date(Date.now() + Number(days) * 86400000);

  licenses[key] = {
    active: true,
    hwid: null,
    bots: {
      [botId]: {
        expiresAt: expiresAt.toISOString()
      }
    }
  };

  saveLicenses(licenses);

  return res.json({
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
  console.log("LICENSE SERVER RUNNING ON PORT", PORT);
});
