const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.json());

/* ================= FILE ================= */

const LICENSE_FILE = path.join(__dirname, "licenses.json");
if (!fs.existsSync(LICENSE_FILE)) {
  fs.writeFileSync(LICENSE_FILE, "{}");
}

/* ================= UTILS ================= */

function getHWID(seed) {
  return crypto.createHash("sha256").update(seed).digest("hex");
}

function generateKey() {
  return crypto.randomBytes(8).toString("hex").toUpperCase();
}

function readLicenses() {
  return JSON.parse(fs.readFileSync(LICENSE_FILE, "utf8"));
}

function saveLicenses(data) {
  fs.writeFileSync(LICENSE_FILE, JSON.stringify(data, null, 2));
}

/* ================= ADMIN AUTH ================= */

function adminAuth(req, res, next) {
  const token = req.headers["x-admin-key"];
  if (!token || token !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ ok: false, reason: "UNAUTHORIZED" });
  }
  next();
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
  if (lic.botId !== botId) return res.json({ ok: false, reason: "WRONG_BOT" });

  if (lic.expiresAt && Date.now() > lic.expiresAt) {
    return res.json({ ok: false, reason: "EXPIRED" });
  }

  const hwid = getHWID(hwidSeed);

  if (!lic.hwid) {
    lic.hwid = hwid;
    saveLicenses(licenses);
  } else if (lic.hwid !== hwid) {
    return res.json({ ok: false, reason: "HWID_MISMATCH" });
  }

  return res.json({ ok: true, license: lic });
});

/* ================= LICENSE GENERATOR (ADMIN) ================= */

app.post("/license/generate", adminAuth, (req, res) => {
  const { botId, expiresInDays } = req.body;

  if (!botId) {
    return res.status(400).json({ ok: false, reason: "BOT_ID_REQUIRED" });
  }

  const licenses = readLicenses();
  const key = generateKey();

  const expiresAt = expiresInDays
    ? Date.now() + expiresInDays * 24 * 60 * 60 * 1000
    : null;

  licenses[key] = {
    key,
    botId,
    active: true,
    createdAt: Date.now(),
    expiresAt,
    hwid: null
  };

  saveLicenses(licenses);

  return res.json({
    ok: true,
    key,
    botId,
    expiresAt
  });
});

/* ================= START ================= */

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("LICENSE SERVER RUNNING ON PORT", PORT);
});
