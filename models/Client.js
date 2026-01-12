const mongoose = require("mongoose");

/**
 * Client Model
 * Stores client information and Shopify OAuth credentials
 * Supports multi-client architecture (hundreds of shops)
 */
const ClientSchema = new mongoose.Schema({
  // Client identifier (e.g., Discord user ID, Electron app ID, etc.)
  clientId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },

  // Shopify OAuth connection (nested object)
  shopify: {
    // Shop domain (e.g., "myshop.myshopify.com")
    shop: {
      type: String,
      default: null
    },

    // OAuth access token (from Shopify after OAuth approval)
    accessToken: {
      type: String,
      default: null
    },

    // OAuth scopes granted by the shop owner
    scopes: {
      type: String,
      default: ""
    },

    // When the Shopify connection was installed/obtained
    installedAt: {
      type: Date,
      default: null
    }
  },

  // When the client document was created
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Index for efficient client lookups
ClientSchema.index({ clientId: 1 }, { unique: true });

module.exports = mongoose.model("Client", ClientSchema);
