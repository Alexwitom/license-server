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
// FORMAT: XXXX-XXX-XXXX (13 znaków)
function generateKey() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const pick = (len) =>
    Array.from({ length: len }, () => chars[Math.floor(Math.random() * chars.length)]).join("");

  return `${pick(4)}-${pick(3)}-${pick(4)}`;
}

module.exports = (app) => {
  app.post("/admin/generate", (req, res) => {
    const { botId, days, adminKey } = req.body;

    // 🔒 AUTORYZACJA
    if (adminKey !== process.env.ADMIN_KEY) {
      return res.status(403).json({ ok: false, reason: "FORBIDDEN" });
    }

    if (!botId || !days) {
      return res.status(400).json({ ok: false, reason: "BAD_REQUEST" });
    }

    const licenses = loadLicenses();
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
      expiresAtHuman: expiresAt.toLocaleString("pl-PL", {
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
      })
    });
  });
};
