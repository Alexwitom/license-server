const mongoose = require("mongoose");

/**
 * ShopifyStore Model
 * Stores Shopify OAuth credentials per client
 * Each client connects their own Shopify store via OAuth
 */
const ShopifyStoreSchema = new mongoose.Schema({
  // Client identifier (e.g., Discord user ID or license key)
  clientId: {
    type: String,
    required: true,
    index: true
  },

  // Shop domain (e.g., "myshop.myshopify.com")
  shop: {
    type: String,
    required: true
  },

  // OAuth access token (from Shopify after OAuth approval)
  accessToken: {
    type: String,
    required: true
  },

  // OAuth scopes granted by the shop owner
  scopes: {
    type: String,
    default: ""
  },

  // When the token was obtained
  connectedAt: {
    type: Date,
    default: Date.now
  },

  // Last time the token was used/verified
  lastUsedAt: {
    type: Date,
    default: Date.now
  }
});

// Ensure one store per client (can be updated if client reconnects)
ShopifyStoreSchema.index({ clientId: 1 }, { unique: true });

module.exports = mongoose.model("ShopifyStore", ShopifyStoreSchema);
