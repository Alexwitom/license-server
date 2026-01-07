const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

/* ================= HWID ================= */
function hwidFromSeed(seed) {
  return crypto.createHash("sha256").update(seed).digest("hex");
}

/* ================= FILE ================= */
const LICENSE_FILE = path.join(__dirname, "..", "licenses.json");

function loadLicenses() {
  if (!fs.existsSync(LICENSE_FILE)) return {};
  return JSON.parse(fs.readFileSync(LICENSE_FILE, "utf8"));
}

function saveLicenses(data) {
  fs.writeFileSync(LICENSE_FILE, JSON.stringify(data, null, 2));
}

/* ================= ROUTE ================= */
module.exports = (req, res) => {
  const { key, botId, hwidSeed } = req.body; // ✅ key DODANY

  if (!key || !botId || !hwidSeed) {
    return res.json({ ok: false, reason: "BAD_REQUEST" });
  }

  const licenses = loadLicenses();
  const lic = licenses[key];

  if (!lic) return res.json({ ok: false, reason: "NOT_FOUND" });
  if (!lic.active) return res.json({ ok: false, reason: "DISABLED" });

  const bot = lic.bots?.[botId];
  if (!bot) return res.json({ ok: false, reason: "BOT_NOT_ALLOWED" });

  const expiresAt = new Date(bot.expiresAt);
  if (expiresAt < new Date()) {
    return res.json({ ok: false, reason: "EXPIRED" });
  }

  /* ================= HWID BIND ================= */
  const hwid = hwidFromSeed(hwidSeed);

  if (!lic.hwid) {
    // 🟢 pierwsze uruchomienie → zapis HWID
    lic.hwid = hwid;
    saveLicenses(licenses);
  } else if (lic.hwid !== hwid) {
    // 🔴 inny komputer
    return res.json({ ok: false, reason: "HWID_MISMATCH" });
  }

  /* ================= OK ================= */
  return res.json({
    ok: true,
    expiresAt: expiresAt.toISOString(),
    expiresAtHuman: expiresAt.toLocaleString("pl-PL", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit"
    })
  });
};
