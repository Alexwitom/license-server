const mongoose = require("mongoose");

/**
 * Client Model
 * Stores client information and e-commerce platform credentials
 * Supports multi-client architecture (hundreds of shops)
 * Supports both Shopify and WooCommerce platforms
 * 
 * PRIMARY KEY: clientId (unique, indexed)
 * Each clientId maps to exactly one e-commerce store connection
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

  // Platform type: "shopify" or "woocommerce"
  platform: {
    type: String,
    enum: ["shopify", "woocommerce"],
    default: "shopify" // Backward compatibility: default to Shopify
  },

  // ========== SHOPIFY FIELDS ==========
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

  // ========== WOOCOMMERCE FIELDS ==========
  // Store URL (e.g., "https://example.com" or "https://example.com/wp")
  storeUrl: {
    type: String,
    default: null
  },

  // WooCommerce REST API consumer key
  consumerKey: {
    type: String,
    default: null
  },

  // WooCommerce REST API consumer secret
  consumerSecret: {
    type: String,
    default: null
  },

  // ========== THEME FIELDS ==========
  // Client theme preferences
  theme: {
    // Theme preset (e.g., "dark_green", "light_blue")
    // This is the PRIMARY theme identifier - prefer this over color
    preset: {
      type: String,
      default: null
    },
    // Legacy color field (kept for backward compatibility)
    // If preset exists, ignore color
    color: {
      type: String,
      default: null
    }
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
