/* ================= IMPORTS ================= */
const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

/* ================= APP INIT ================= */
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

function readLicenses() {
  return JSON.parse(fs.readFileSync(LICENSE_FILE, "utf8"));
}

function saveLicenses(data) {
  fs.writeFileSync(LICENSE_FILE, JSON.stringify(data, null, 2));
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

  const expiresAt = lic.bots[botId].expiresAt;
  if (expiresAt && Date.now() > new Date(expiresAt).getTime()) {
    return res.json({ ok: false, reason: "EXPIRED" });
  }

  const hwid = getHWID(hwidSeed);

  if (!lic.hwid) {
    lic.hwid = hwid;
    saveLicenses(licenses);
  } else if (lic.hwid !== hwid) {
    return res.json({ ok: false, reason: "HWID_MISMATCH" });
  }

  return res.json({
    ok: true,
    expiresAt,
    expiresAtHuman: new Date(expiresAt).toLocaleString("pl-PL")
  });
});

/* ================= ADMIN GENERATOR ================= */
app.post("/admin/generate", (req, res) => {
  const { botId, days, adminKey } = req.body;

  if (adminKey !== process.env.ADMIN_KEY) {
    return res.status(403).json({ ok: false, reason: "UNAUTHORIZED" });
  }

  if (!botId || !days) {
    return res.status(400).json({ ok: false, reason: "BAD_REQUEST" });
  }

  const licenses = readLicenses();

  // 13 znaków: XXXX-XXX-XXXX
  const raw = crypto.randomBytes(7).toString("hex").toUpperCase();
  const key = `${raw.slice(0,4)}-${raw.slice(4,7)}-${raw.slice(7,11)}`;

  const expiresAt = new Date(Date.now() + days * 86400000).toISOString();

  licenses[key] = {
    active: true,
    hwid: null,
    bots: {
      [botId]: {
        expiresAt
      }
    }
  };

  saveLicenses(licenses);

  res.json({
    ok: true,
    key,
    botId,
    expiresAt,
    expiresAtHuman: new Date(expiresAt).toLocaleString("pl-PL")
  });
});

/* ================= START ================= */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log("LICENSE SERVER RUNNING ON PORT", PORT);
});
