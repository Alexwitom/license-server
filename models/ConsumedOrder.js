const mongoose = require("mongoose");

/**
 * ConsumedOrder Model
 * 
 * Tracks which Shopify orders have been used to grant Discord role access.
 * Each order can only be consumed once to prevent abuse.
 * 
 * Abuse Protection:
 * - Single-use orders prevent users from claiming the same purchase multiple times
 * - Prevents users from sharing order IDs to get unlimited role grants
 * - Ensures each purchase only grants access once, protecting store owner's business model
 * - Links orderId to discordUserId to track which user consumed which order
 */
const ConsumedOrderSchema = new mongoose.Schema({
  // Client identifier (store owner's identifier)
  clientId: {
    type: String,
    required: true,
    index: true
  },

  // Shopify order ID (unique identifier from Shopify)
  orderId: {
    type: String,
    required: true,
    index: true
  },

  // Customer email from the order
  email: {
    type: String,
    required: true
  },

  // Discord user ID who consumed this order
  discordUserId: {
    type: String,
    required: true,
    index: true
  },

  // Timestamp when the order was consumed
  consumedAt: {
    type: Date,
    default: Date.now,
    required: true
  }
});

// Ensure each order can only be consumed once per client
// This unique index prevents the same orderId from being used multiple times
ConsumedOrderSchema.index({ clientId: 1, orderId: 1 }, { unique: true });

module.exports = mongoose.model("ConsumedOrder", ConsumedOrderSchema);
