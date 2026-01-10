const mongoose = require("mongoose");

const LicenseSchema = new mongoose.Schema({
  key: { 
    type: String, 
    required: true, 
    unique: true 
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

  expiresAt: {
    type: Date,
    required: true
  }
});

module.exports = mongoose.model("License", LicenseSchema);
