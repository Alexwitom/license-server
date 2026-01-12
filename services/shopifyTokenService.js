const Client = require("../models/Client");

/**
 * Shopify Token Service
 * 
 * Read-only access layer for Shopify OAuth data stored in MongoDB.
 * Uses multi-client architecture: each client has isolated Shopify credentials.
 * Used by the Discord bot to retrieve stored Shopify store credentials
 * for order verification and other Shopify API operations.
 * 
 * MULTI-CLIENT ARCHITECTURE:
 * - All clients are stored in Client collection
 * - Each client has nested shopify object with credentials
 * - Credentials are isolated per clientId
 * - Scalable to hundreds of clients
 * 
 * Usage in Discord Bot:
 * - Before verifying an order, check if client has connected their store
 * - Retrieve access token to make authenticated Shopify API calls
 * - Verify order exists in client's Shopify store
 */

/**
 * Get client document with Shopify credentials for a specific client
 * 
 * This is the SINGLE SOURCE OF TRUTH for client resolution in the service layer.
 * All Shopify operations MUST use this function to ensure multi-client isolation.
 * 
 * @param {string} clientId - Client identifier (e.g., Discord user ID)
 * @returns {Promise<Object|null>} - Client document with shopify credentials, or null if not found
 * 
 * Example usage in Discord bot:
 *   const client = await getClientByClientId(userId);
 *   if (client && client.shopify && client.shopify.accessToken) {
 *     // Make Shopify API call with client.shopify.accessToken
 *     // Verify order using client.shopify.shop domain
 *   }
 */
async function getClientByClientId(clientId) {
  if (!clientId || typeof clientId !== "string" || clientId.trim().length === 0) {
    return null;
  }

  try {
    const client = await Client.findOne({ clientId: clientId.trim() });
    return client;
  } catch (error) {
    console.error(`❌ Error retrieving client (clientId=${clientId}):`, error);
    return null;
  }
}

/**
 * Get Shopify store credentials for a specific client (legacy compatibility)
 * 
 * @deprecated Use getClientByClientId() instead for better multi-client support
 * @param {string} clientId - Client identifier (e.g., Discord user ID)
 * @returns {Promise<Object|null>} - Store data with shop, accessToken, scopes, etc., or null if not found
 */
async function getStoreByClientId(clientId) {
  const client = await getClientByClientId(clientId);
  if (!client || !client.shopify) {
    return null;
  }
  
  // Return in legacy format for backward compatibility
  return {
    clientId: client.clientId,
    shop: client.shopify.shop,
    accessToken: client.shopify.accessToken,
    scopes: client.shopify.scopes,
    connectedAt: client.shopify.installedAt,
    lastUsedAt: client.shopify.installedAt // Fallback since Client model doesn't have lastUsedAt
  };
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
  const client = await getClientByClientId(clientId);
  return client !== null && client !== undefined && client.shopify && client.shopify.accessToken;
}

module.exports = {
  getClientByClientId,
  getStoreByClientId, // Legacy compatibility
  isStoreConnected
};
