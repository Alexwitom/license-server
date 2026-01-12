const mongoose = require("mongoose");

/**
 * Client Model
 * Stores client information and Shopify OAuth credentials
 * Supports multi-client architecture (hundreds of shops)
 * 
 * PRIMARY KEY: clientId (unique, indexed)
 * Each clientId maps to exactly one Shopify store connection
 */
const ClientSchema = new mongoose.Schema({
  // PRIMARY KEY: Client identifier (e.g., Discord user ID, Electron app ID, etc.)
  // This is the PRIMARY KEY for client lookups - NEVER generate or overwrite
  clientId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },

  // Shop domain (e.g., "myshop.myshopify.com")
  shop: {
    type: String,
    default: null
  },

  // OAuth access token (from Shopify after OAuth approval)
  shopifyAccessToken: {
    type: String,
    default: null
  },

  // When the client document was created
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Index for efficient client lookups (clientId is PRIMARY KEY)
ClientSchema.index({ clientId: 1 }, { unique: true });

module.exports = mongoose.model("Client", ClientSchema);
