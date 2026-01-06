const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const LICENSE_FILE = path.join(__dirname, "..", "licenses.json");

function loadLicenses() {
  if (!fs.existsSync(LICENSE_FILE)) return {};
  return JSON.parse(fs.readFileSync(LICENSE_FILE, "utf8"));
}

function saveLicenses(data) {
  fs.writeFileSync(LICENSE_FILE, JSON.stringify(data, null, 2));
}

function generateKey() {
  return crypto.randomBytes(6).toString("hex").toUpperCase();
}

module.exports = (app) => {
  app.post("/admin/generate", (req, res) => {
    const { botId, days, adminKey } = req.body;

    // 🔒 ZABEZPIECZENIE
    if (adminKey !== process.env.ADMIN_KEY) {
      return res.status(403).json({ ok: false, reason: "FORBIDDEN" });
    }

    const licenses = loadLicenses();
    const key = generateKey();

    licenses[key] = {
      active: true,
      hwid: null,
      bots: {
        [botId]: {
          expiresAt: new Date(Date.now() + days * 86400000).toISOString()
        }
      }
    };

    saveLicenses(licenses);

    res.json({
      ok: true,
      key,
      expiresInDays: days
    });
  });
};
