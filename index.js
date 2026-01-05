const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const LICENSE_FILE = path.join(__dirname, "licenses.json");

function getHWID(seed) {
  return crypto.createHash("sha256").update(seed).digest("hex");
}

app.post("/license/check", (req, res) => {
  const { key, botId, hwidSeed } = req.body;

  if (!key || !botId || !hwidSeed) {
    return res.json({ ok: false, reason: "BAD_REQUEST" });
  }

  const licenses = JSON.parse(fs.readFileSync(LICENSE_FILE, "utf8"));
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
    fs.writeFileSync(LICENSE_FILE, JSON.stringify(licenses, null, 2));
  } else if (lic.hwid !== hwid) {
    return res.json({ ok: false, reason: "HWID_MISMATCH" });
  }

  return res.json({ ok: true, license: lic });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("LICENSE SERVER RUNNING ON PORT", PORT);
});
