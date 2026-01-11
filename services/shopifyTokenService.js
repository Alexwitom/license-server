const ShopifyStore = require("../models/ShopifyStore");

/**
 * Shopify Token Service
 * 
 * Read-only access layer for Shopify OAuth data stored in MongoDB.
 * Used by the Discord bot to retrieve stored Shopify store credentials
 * for order verification and other Shopify API operations.
 * 
 * Usage in Discord Bot:
 * - Before verifying an order, check if client has connected their store
 * - Retrieve access token to make authenticated Shopify API calls
 * - Verify order exists in client's Shopify store
 */

/**
 * Get Shopify store credentials for a specific client
 * 
 * @param {string} clientId - Client identifier (e.g., Discord user ID)
 * @returns {Promise<Object|null>} - Store data with shop, accessToken, scopes, etc., or null if not found
 * 
 * Example usage in Discord bot:
 *   const store = await getStoreByClientId(userId);
 *   if (store) {
 *     // Make Shopify API call with store.accessToken
 *     // Verify order using store.shop domain
 *   }
 */
async function getStoreByClientId(clientId) {
  if (!clientId) {
    return null;
  }

  try {
    const store = await ShopifyStore.findOne({ clientId });
    return store;
  } catch (error) {
    console.error("❌ Error retrieving Shopify store:", error);
    return null;
  }
}

/**
 * Check if a client has connected their Shopify store
 * 
 * @param {string} clientId - Client identifier (e.g., Discord user ID)
 * @returns {Promise<boolean>} - true if store is connected, false otherwise
 * 
 * Example usage in Discord bot:
 *   const connected = await isStoreConnected(userId);
 *   if (!connected) {
 *     // Show "Connect Shopify" button in bot UI
 *     // Redirect user to /shopify/auth?clientId=userId&shop=xxx
 *   }
 */
async function isStoreConnected(clientId) {
  if (!clientId) {
    return false;
  }

  try {
    const store = await ShopifyStore.findOne({ clientId });
    return store !== null && store !== undefined;
  } catch (error) {
    console.error("❌ Error checking Shopify store connection:", error);
    return false;
  }
}

module.exports = {
  getStoreByClientId,
  isStoreConnected
};
