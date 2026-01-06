const fs = require("fs");
const path = require("path");

const LICENSE_FILE = path.join(__dirname, "..", "licenses.json");

function loadLicenses() {
  if (!fs.existsSync(LICENSE_FILE)) return {};
  return JSON.parse(fs.readFileSync(LICENSE_FILE, "utf8"));
}

module.exports = (req, res) => {
  const { key, botId } = req.body;

  const licenses = loadLicenses();
  const lic = licenses[key];

  if (!lic) return res.json({ ok: false, reason: "NOT_FOUND" });
  if (!lic.active) return res.json({ ok: false, reason: "DISABLED" });

  const bot = lic.bots[botId];
  if (!bot) return res.json({ ok: false, reason: "BOT_NOT_ALLOWED" });

  if (new Date(bot.expiresAt) < new Date()) {
    return res.json({ ok: false, reason: "EXPIRED" });
  }

  return res.json({ ok: true });
};
