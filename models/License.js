const mongoose = require("mongoose");

const BotSchema = new mongoose.Schema({
  expiresAt: { type: Date, required: true }
}, { _id: false });

const LicenseSchema = new mongoose.Schema({
  key: { type: String, unique: true, required: true },
  active: { type: Boolean, default: true },
  hwid: { type: String, default: null },
  bots: { type: Map, of: BotSchema }
}, { timestamps: true });

module.exports = mongoose.model("License", LicenseSchema);
