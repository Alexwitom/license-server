const mongoose = require("mongoose");

const LicenseSchema = new mongoose.Schema({
  key: {
    type: String,
    required: true,
    unique: true,
    index: true
  },

  hwid: {
    type: String,
    default: null
  },

  active: {
    type: Boolean,
    default: true
  },

  createdAt: {
    type: Date,
    default: Date.now
  },

  // REAL expiration date
  expiresAt: {
    type: Date,
    required: true
  }
}, {
  versionKey: false
});

/**
 * Virtual field — days left
 * NIE zapisuje się w bazie, tylko do odczytu
 */
LicenseSchema.virtual("daysLeft").get(function () {
  if (!this.expiresAt) return 0;

  const now = new Date();
  const diff = this.expiresAt.getTime() - now.getTime();
  const days = Math.ceil(diff / (1000 * 60 * 60 * 24));

  return days > 0 ? days : 0;
});

/**
 * Always include virtuals when converting to JSON
 */
LicenseSchema.set("toJSON", { virtuals: true });
LicenseSchema.set("toObject", { virtuals: true });

module.exports = mongoose.model("License", LicenseSchema);
