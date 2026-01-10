const License = require("../models/License");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const LICENSE_FILE = path.join(__dirname, "..", "licenses.json");

/* ================= UTILS ================= */
function loadLicenses() {
  if (!fs.existsSync(LICENSE_FILE)) return {};
  return JSON.parse(fs.readFileSync(LICENSE_FILE, "utf8"));
}

function saveLicenses(data) {
  fs.writeFileSync(LICENSE_FILE, JSON.stringify(data, null, 2));
}

/* ================= KEY FORMAT ================= */
function generateKey() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const pick = (len) =>
    Array.from({ length: len }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
  return `${pick(4)}-${pick(3)}-${pick(4)}`;
}

module.exports = (app) => {
  app.post("/admin/generate", async (req, res) => {
    const { botId, days, adminKey } = req.body;

    // 🔒 AUTORYZACJA
    if (adminKey !== process.env.ADMIN_KEY) {
      return res.status(403).json({ ok: false, reason: "FORBIDDEN" });
    }

    if (!botId || days === undefined) {
      return res.status(400).json({ ok: false, reason: "BAD_REQUEST" });
    }

    const key = generateKey();

    let expiresAt;
  // 🔥 HARD VALIDATION — MUSI TU BYĆ
  if (!(expiresAt instanceof Date) || isNaN(expiresAt.getTime())) {
  console.error("❌ INVALID expiresAt:", expiresAt, "days =", days);
  return res.status(400).json({
    ok: false,
    reason: "INVALID_EXPIRES_DATE"
    });
  }

    // ✅ lifetime
    if (typeof days === "string" && days.toLowerCase() === "lifetime") {
      expiresAt = new Date();
      expiresAt.setFullYear(expiresAt.getFullYear() + 100);
    } else {
      const daysNumber = Number(days);

      if (!Number.isFinite(daysNumber) || daysNumber <= 0) {
        return res.status(400).json({
          ok: false,
          reason: "INVALID_DAYS"
        });
      }

      expiresAt = new Date(Date.now() + daysNumber * 86400000);
    }

    // 🧠 MONGO
    try {
      await License.create({
        key,
        active: true,
        hwid: null,
        bots: {
          [botId]: { expiresAt }
        },
        createdAt: new Date()
      });
    } catch (err) {
      console.error("❌ MONGO SAVE ERROR:", err);
      return res.status(500).json({ ok: false, reason: "DB_ERROR" });
    }

    // 📄 JSON FALLBACK
    const licenses = loadLicenses();
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
      expiresAtHuman: expiresAt.toLocaleString("pl-PL")
    });
  });
};

