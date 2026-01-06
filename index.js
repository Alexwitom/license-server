const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();

/* ================= MIDDLEWARE ================= */
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
  // 13 znaków: XXXX-XXXX-XXXX
  return crypto
    .randomBytes(6)
    .toString("hex")
    .toUpperCase()
    .match(/.{1,4}/g)
    .slice(0, 3)
    .join("-");
}

function readLicenses() {
  return JSON.parse(fs.readFileSync(LICENSE_FILE, "utf8"));
}

function saveLicenses(data) {
  fs.writeFileSync(LICENSE_FILE, JSON.stringify(data, null, 2));
}

/* ================= ROOT (ŻEBY NIE BYŁO Cannot POST /) ================= */
app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "LICENSE SERVER",
    endpoints: [
      "POST /license/check",
      "POST /admin/generate"
    ]
  });
});

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

  const bot = lic.bots?.[botId];
  if (!bot) return res.json({ ok: false, reason: "WRONG_BOT" });

  if (bot.expiresAt && Date.now() > new Date(bot.expiresAt).getTime()) {
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
    expiresAt: bot.expiresAt
  });
});

/* ================= LICENSE GENERATOR (ADMIN) ================= */
app.post("/admin/generate", (req, res) => {
  const { botId, days, adminKey } = req.body;

  if (adminKey !== process.env.ADMIN_KEY) {
    return res.status(403).json({ ok: false, reason: "UNAUTHORIZED" });
  }

  if (!botId || !days) {
    return res.json({ ok: false, reason: "BAD_REQUEST" });
  }

  const licenses = readLicenses();
  const key = generateKey();

  licenses[key] = {
    active: true,
    hwid: null,
    bots: {
      [botId]: {
        expiresAt: new Date(
          Date.now() + days * 86400000
        ).toISOString()
      }
    }
  };

  saveLicenses(licenses);

  res.json({
    ok: true,
    key,
    expiresAt: licenses[key].bots[botId].expiresAt
  });
});

/* ================= START (ZAWSZE NA KOŃCU) ================= */
const PORT = process.env.PORT || 10000;

app.listen(PORT, () => {
  console.log("LICENSE SERVER RUNNING ON PORT", PORT);
});
