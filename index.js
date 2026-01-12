const express = require("express");
const mongoose = require("mongoose");
const crypto = require("crypto");
const https = require("https");
const querystring = require("querystring");

const app = express();

// Content-Type guard middleware: ensure POST requests have valid Content-Type (BEFORE body parsers)
app.use((req, res, next) => {
  // Skip check for GET/HEAD requests (no body expected)
  if (req.method === "GET" || req.method === "HEAD") {
    return next();
  }
  
  // For POST/PUT/PATCH, require application/json Content-Type
  const contentType = req.headers["content-type"] || "";
  if (!contentType.includes("application/json")) {
    return res.status(400).json({
      ok: false,
      reason: "INVALID_CONTENT_TYPE",
      message: "Content-Type must be application/json"
    });
  }
  
  next();
});

// Configure body parsers - accept multiple content types for crash-proof parsing
app.use(express.json({ strict: false, limit: "1mb" })); // Accept malformed JSON
app.use(express.text({ type: "*/*", limit: "1mb" })); // Accept text/plain and any other type (fallback)
app.use(express.urlencoded({ extended: true, limit: "1mb" })); // Accept URL-encoded (fallback)

/* ================= MONGO ================= */

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => {
    console.error("❌ Mongo error:", err);
    process.exit(1);
  });

/* ================= SCHEMA ================= */

const LicenseSchema = new mongoose.Schema({
  key: String,
  active: Boolean,
  hwid: String,
  bots: Object
});

const License = mongoose.model("License", LicenseSchema);

/* ================= SHOPIFY MODEL ================= */

const ShopifyStore = require("./models/ShopifyStore");
const ConsumedOrder = require("./models/ConsumedOrder");
const Client = require("./models/Client");

/* ================= MULTI-CLIENT ARCHITECTURE ================= */

/**
 * MULTI-CLIENT SHOPIFY ARCHITECTURE OVERVIEW
 * 
 * This backend supports hundreds of clients, each with their own Shopify store.
 * All Shopify-related operations are isolated per client using clientId.
 * 
 * CLIENT LIFECYCLE:
 * 1. Client document is auto-created during OAuth callback (/shopify/callback)
 *    - When a clientId doesn't exist, a new Client document is created
 *    - This enables multi-client support without manual setup
 * 2. Client document stores Shopify OAuth credentials in nested shopify object
 *    - shop: Shop domain (e.g., "myshop.myshopify.com")
 *    - accessToken: OAuth access token for API calls
 *    - scopes: Granted OAuth scopes
 *    - installedAt: When OAuth connection was established
 * 3. Client can reconnect/update their Shopify store anytime
 *    - OAuth callback updates existing Client document
 * 
 * OAUTH LIFECYCLE:
 * 1. Client initiates OAuth: GET /shopify/auth?clientId=xxx&shop=xxx
 *    - Generates secure state token with clientId
 *    - Redirects to Shopify OAuth authorization screen
 * 2. Shopify redirects back: GET /shopify/callback?code=xxx&state=xxx&shop=xxx
 *    - Validates HMAC (security)
 *    - Exchanges code for access_token
 *    - Fetches shop info from Shopify API
 *    - Auto-creates or updates Client document
 * 
 * WHERE NEW CLIENTS ARE CREATED:
 * - Location: /shopify/callback endpoint (line ~477)
 * - Logic: Client.findOne({ clientId }) → if null, Client.create()
 * - This ensures every clientId gets a document on first OAuth connection
 * 
 * FUTURE ENDPOINTS (orders, webhooks, etc.):
 * - MUST use getClientByClientId(clientId) helper
 * - MUST resolve credentials from Client.shopify object
 * - MUST never use global shop config
 * - MUST handle clientId isolation properly
 * 
 * DATA ISOLATION:
 * - Each client's Shopify data is isolated by clientId
 * - No cross-client data access
 * - Scalable to hundreds of clients
 */

/**
 * Helper function to get client by clientId
 * 
 * This is the SINGLE SOURCE OF TRUTH for resolving client credentials.
 * All Shopify-related endpoints MUST use this function to ensure:
 * - Consistent client resolution
 * - Proper error handling
 * - Multi-client isolation
 * - clientId is treated as PRIMARY KEY
 * 
 * @param {string} clientId - Client identifier (required, PRIMARY KEY)
 * @returns {Promise<Object|null>} - Client document with shop and shopifyAccessToken, or null if not found
 * 
 * Usage in endpoints:
 *   const client = await getClientByClientId(clientId);
 *   if (!client || !client.shop || !client.shopifyAccessToken) {
 *     return res.status(404).json({ ok: false, reason: "CLIENT_NOT_FOUND" });
 *   }
 *   // Use client.shop and client.shopifyAccessToken for API calls
 */
async function getClientByClientId(clientId) {
  if (!clientId || typeof clientId !== "string" || clientId.trim().length === 0) {
    return null;
  }

  try {
    const normalizedClientId = clientId.trim();
    const client = await Client.findOne({ clientId: normalizedClientId });
    
    // Log claim lookup for debugging
    if (client) {
      console.log(`[CLAIM] Client found: clientId=${normalizedClientId}, shop=${client.shop || "N/A"}`);
    } else {
      console.log(`[CLAIM] Client NOT found: clientId=${normalizedClientId}`);
    }
    
    return client;
  } catch (error) {
    console.error(`❌ Error retrieving client (clientId=${clientId}):`, error);
    return null;
  }
}

/* ================= ENV VALIDATION ================= */

const requiredEnvVars = [
  "SHOPIFY_API_KEY",
  "SHOPIFY_API_SECRET",
  "SERVER_BASE_URL"
];

const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingVars.length > 0) {
  console.warn(`⚠️  Missing Shopify environment variables: ${missingVars.join(", ")}`);
  console.warn("⚠️  Shopify OAuth endpoints may not function correctly without these variables.");
}

/* ================= UTILS ================= */

function generateKey() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const pick = (l) =>
    Array.from({ length: l }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
  return `${pick(4)}-${pick(3)}-${pick(4)}`;
}

function hwidFromSeed(seed) {
  return crypto.createHash("sha256").update(seed).digest("hex");
}

/* ================= CHECK ================= */

app.post("/license/check", async (req, res) => {
  const { key, botId, hwidSeed } = req.body;
  if (!key || !botId || !hwidSeed) {
    return res.json({ ok: false, reason: "BAD_REQUEST" });
  }

  const lic = await License.findOne({ key });
  if (!lic) return res.json({ ok: false, reason: "INVALID_KEY" });
  if (!lic.active) return res.json({ ok: false, reason: "DISABLED" });
  if (!lic.bots?.[botId]) return res.json({ ok: false, reason: "WRONG_BOT" });

  const expiresAt = new Date(lic.bots[botId].expiresAt);
  if (Date.now() > expiresAt.getTime()) {
    return res.json({ ok: false, reason: "EXPIRED" });
  }

  const hwid = hwidFromSeed(hwidSeed);
  if (!lic.hwid) {
    lic.hwid = hwid;
    await lic.save();
  } else if (lic.hwid !== hwid) {
    return res.json({ ok: false, reason: "HWID_MISMATCH" });
  }

  res.json({
    ok: true,
    expiresAt: expiresAt.toISOString(),
    expiresAtHuman: expiresAt.toLocaleString("pl-PL")
  });
});

/* ================= GENERATE ================= */

app.post("/admin/generate", async (req, res) => {
  const { botId, days, adminKey } = req.body;

  if (adminKey !== process.env.ADMIN_KEY) {
    return res.status(403).json({ ok: false, reason: "FORBIDDEN" });
  }

  const key = generateKey();
  const expiresAt = new Date(Date.now() + Number(days) * 86400000);

  await License.create({
    key,
    active: true,
    hwid: null,
    bots: {
      [botId]: { expiresAt }
    }
  });

  res.json({
    ok: true,
    key,
    expiresAt: expiresAt.toISOString(),
    expiresAtHuman: expiresAt.toLocaleString("pl-PL")
  });
});

/* ================= SHOPIFY OAUTH ================= */

/**
 * GET /shopify/auth
 * Initiates Shopify OAuth flow for multi-client architecture
 * Query params:
 *   - clientId: Client identifier (required, e.g., Discord user ID, Electron app ID)
 *   - shop: Shop domain (required, e.g., "myshop.myshopify.com")
 * 
 * Flow:
 * 1. Validates required params (clientId, shop)
 * 2. Validates shop domain format
 * 3. Generates state token (clientId encoded for security)
 * 4. Redirects user to Shopify OAuth authorization URL
 * 
 * Usage in Electron app:
 *   - User clicks "Connect Shopify" button
 *   - App redirects to: GET /shopify/auth?clientId=xxx&shop=xxx.myshopify.com
 *   - User is redirected to Shopify OAuth screen
 */
app.get("/shopify/auth", (req, res) => {
  const { clientId, shop } = req.query;

  // Validate required parameters
  if (!clientId) {
    console.error("❌ OAuth started: Missing clientId parameter");
    return res.status(400).json({
      ok: false,
      reason: "BAD_REQUEST",
      message: "clientId query parameter is required"
    });
  }

  if (!shop) {
    console.error(`❌ OAuth started: Missing shop parameter for clientId: ${clientId}`);
    return res.status(400).json({
      ok: false,
      reason: "BAD_REQUEST",
      message: "shop query parameter is required"
    });
  }

  // Validate clientId format (non-empty string)
  if (typeof clientId !== "string" || clientId.trim().length === 0) {
    console.error(`❌ OAuth started: Invalid clientId format: ${clientId}`);
    return res.status(400).json({
      ok: false,
      reason: "INVALID_CLIENT_ID",
      message: "clientId must be a non-empty string"
    });
  }

  // Validate shop domain format
  if (!shop.includes(".myshopify.com")) {
    console.error(`❌ OAuth started: Invalid shop format for clientId: ${clientId}, shop: ${shop}`);
    return res.status(400).json({
      ok: false,
      reason: "INVALID_SHOP",
      message: "Shop domain must be in format: shopname.myshopify.com"
    });
  }

  // Validate environment variables
  const apiKey = process.env.SHOPIFY_API_KEY;
  const scopes = process.env.SHOPIFY_SCOPES || "read_orders";
  const redirectUri = process.env.SHOPIFY_REDIRECT_URI || `${process.env.SERVER_BASE_URL}/shopify/callback`;

  if (!apiKey) {
    console.error("❌ OAuth started: SHOPIFY_API_KEY not set in environment");
    return res.status(500).json({
      ok: false,
      reason: "SERVER_ERROR",
      message: "Shopify API key not configured"
    });
  }

  // Log OAuth initiation
  console.log(`🔐 OAuth started: clientId=${clientId}, shop=${shop}`);

  // Create state token: base64 encode clientId + random nonce for security
  const nonce = crypto.randomBytes(16).toString("hex");
  const state = Buffer.from(JSON.stringify({ clientId, nonce })).toString("base64");

  // Build Shopify OAuth authorization URL
  const authUrl = `https://${shop}/admin/oauth/authorize?${querystring.stringify({
    client_id: apiKey,
    scope: scopes,
    redirect_uri: redirectUri,
    state: state
  })}`;

  // Redirect user to Shopify OAuth screen
  res.redirect(authUrl);
});

/**
 * Helper function to validate Shopify HMAC
 * @param {Object} queryParams - Query parameters from Shopify callback
 * @param {string} apiSecret - Shopify API secret
 * @returns {Object} - { valid: boolean, message: string }
 */
function validateShopifyHMAC(queryParams, apiSecret) {
  const { hmac, ...params } = queryParams;
  
  // HMAC is optional but recommended for security
  if (!hmac) {
    return { valid: true, message: "HMAC not provided (optional)" };
  }

  // Sort parameters and create message (exclude hmac from calculation)
  const sortedParams = Object.keys(params)
    .sort()
    .map(key => `${key}=${params[key]}`)
    .join("&");

  // Generate HMAC
  const generatedHmac = crypto
    .createHmac("sha256", apiSecret)
    .update(sortedParams)
    .digest("hex");

  // Compare HMACs (constant-time comparison for security)
  const isValid = crypto.timingSafeEqual(
    Buffer.from(hmac),
    Buffer.from(generatedHmac)
  );

  return {
    valid: isValid,
    message: isValid ? "HMAC valid" : "HMAC validation failed"
  };
}

/**
 * Helper function to fetch shop info from Shopify API
 * @param {string} shop - Shop domain
 * @param {string} accessToken - OAuth access token
 * @returns {Promise<Object|null>} - Shop info object or null if failed
 */
function fetchShopInfo(shop, accessToken) {
  return new Promise((resolve) => {
    const apiVersion = process.env.SHOPIFY_API_VERSION || "2024-01";
    const apiPath = `/admin/api/${apiVersion}/shop.json`;

    const shopRequest = https.request(
      {
        hostname: shop,
        path: apiPath,
        method: "GET",
        headers: {
          "X-Shopify-Access-Token": accessToken,
          "Content-Type": "application/json"
        }
      },
      (shopResponse) => {
        let data = "";

        shopResponse.on("data", (chunk) => {
          data += chunk;
        });

        shopResponse.on("end", () => {
          if (shopResponse.statusCode === 200) {
            try {
              const shopData = JSON.parse(data);
              resolve(shopData.shop || null);
            } catch (parseError) {
              console.error("❌ Failed to parse shop info:", parseError);
              resolve(null);
            }
          } else {
            console.error(`❌ Failed to fetch shop info: ${shopResponse.statusCode}`);
            resolve(null);
          }
        });
      }
    );

    shopRequest.on("error", (err) => {
      console.error("❌ Error fetching shop info:", err);
      resolve(null);
    });

    shopRequest.end();
  });
}

/**
 * GET /shopify/callback
 * Handles Shopify OAuth callback after user approval
 * Query params (from Shopify):
 *   - code: Authorization code to exchange for access token
 *   - state: State token containing clientId (from /shopify/auth)
 *   - shop: Shop domain
 *   - hmac: HMAC for request verification
 * 
 * Flow:
 * 1. Validates HMAC (security)
 * 2. Validates state and extracts clientId
 * 3. Exchanges authorization code for access token via Shopify API
 * 4. Fetches shop info from Shopify API
 * 5. Auto-creates or updates Client document in MongoDB
 * 6. Returns success response
 * 
 * Usage in Electron app:
 *   - Shopify redirects to this endpoint after OAuth approval
 *   - App receives success response and can update UI
 */
app.get("/shopify/callback", async (req, res) => {
  const { code, state, shop, hmac } = req.query;

  // Validate required parameters
  if (!code || !state || !shop) {
    console.error("❌ OAuth callback: Missing required parameters");
    return res.status(400).json({
      ok: false,
      reason: "BAD_REQUEST",
      message: "code, state, and shop query parameters are required"
    });
  }

  // Validate environment variables
  const apiKey = process.env.SHOPIFY_API_KEY;
  const apiSecret = process.env.SHOPIFY_API_SECRET;
  const redirectUri = process.env.SHOPIFY_REDIRECT_URI || `${process.env.SERVER_BASE_URL}/shopify/callback`;

  if (!apiKey || !apiSecret) {
    console.error("❌ OAuth callback: SHOPIFY_API_KEY or SHOPIFY_API_SECRET not set in environment");
    return res.status(500).json({
      ok: false,
      reason: "SERVER_ERROR",
      message: "Shopify API credentials not configured"
    });
  }

  // Validate HMAC (security check)
  const queryParams = { ...req.query };
  const hmacValidation = validateShopifyHMAC(queryParams, apiSecret);
  if (!hmacValidation.valid) {
    console.error(`❌ OAuth callback: ${hmacValidation.message}`);
    return res.status(400).json({
      ok: false,
      reason: "INVALID_HMAC",
      message: "HMAC verification failed"
    });
  }
  if (hmacValidation.message.includes("not provided")) {
    console.warn(`⚠️  OAuth callback: ${hmacValidation.message} - proceeding without HMAC validation`);
  }

  // Decode state to get clientId
  let clientId;
  try {
    const stateData = JSON.parse(Buffer.from(state, "base64").toString());
    clientId = stateData.clientId;
    if (!clientId || typeof clientId !== "string" || clientId.trim().length === 0) {
      throw new Error("clientId missing or invalid in state");
    }
    clientId = clientId.trim();
  } catch (err) {
    console.error("❌ OAuth callback: Invalid state token:", err);
    return res.status(400).json({
      ok: false,
      reason: "INVALID_STATE",
      message: "Invalid or corrupted state parameter"
    });
  }

  console.log(`🔐 OAuth callback: Processing for clientId=${clientId}, shop=${shop}`);

  // Exchange authorization code for access token
  const tokenRequestData = querystring.stringify({
    client_id: apiKey,
    client_secret: apiSecret,
    code: code
  });

  return new Promise((resolve) => {
    const tokenRequest = https.request(
      {
        hostname: shop,
        path: "/admin/oauth/access_token",
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Content-Length": Buffer.byteLength(tokenRequestData)
        }
      },
      (tokenResponse) => {
        let data = "";

        tokenResponse.on("data", (chunk) => {
          data += chunk;
        });

        tokenResponse.on("end", async () => {
          if (tokenResponse.statusCode !== 200) {
            console.error(`❌ OAuth callback: Token exchange failed (${tokenResponse.statusCode}):`, data);
            res.status(500).json({
              ok: false,
              reason: "TOKEN_EXCHANGE_FAILED",
              message: "Failed to exchange authorization code for access token"
            });
            return resolve();
          }

          try {
            const tokenData = JSON.parse(data);
            const { access_token, scope } = tokenData;

            if (!access_token) {
              throw new Error("Access token missing in Shopify response");
            }

            console.log(`✅ OAuth callback: Token exchange successful for clientId=${clientId}`);

            // Fetch shop info from Shopify API
            const shopInfo = await fetchShopInfo(shop, access_token);
            if (shopInfo) {
              console.log(`✅ OAuth callback: Shop info fetched for clientId=${clientId}, shop name: ${shopInfo.name || "N/A"}`);
            } else {
              console.warn(`⚠️  OAuth callback: Failed to fetch shop info for clientId=${clientId}, continuing anyway`);
            }

            // Auto-create or update Client document in MongoDB
            // IMPORTANT: clientId is PRIMARY KEY - NEVER generate or overwrite it
            try {
              // Check if client exists (lookup by PRIMARY KEY: clientId)
              let client = await Client.findOne({ clientId });

              if (!client) {
                // Auto-create new client document
                // NEVER generate clientId - use the one from OAuth state
                client = await Client.create({
                  clientId, // PRIMARY KEY - from OAuth state, never generated
                  shop,
                  shopifyAccessToken: access_token,
                  createdAt: new Date()
                });
                console.log(`[OAUTH] Client created: clientId=${clientId}, shop=${shop}`);
              } else {
                // Update existing client's Shopify connection
                // NEVER overwrite clientId - it's the PRIMARY KEY
                client.shop = shop;
                client.shopifyAccessToken = access_token;
                await client.save();
                console.log(`[OAUTH] Client updated: clientId=${clientId}, shop=${shop}`);
              }

              console.log(`✅ OAuth success: clientId=${clientId}, shop=${shop}`);

              // Return success response
              res.json({
                ok: true,
                message: "Shopify store connected successfully",
                shop,
                clientId
              });
            } catch (dbError) {
              console.error(`❌ OAuth callback: Database error for clientId=${clientId}:`, dbError);
              res.status(500).json({
                ok: false,
                reason: "DB_ERROR",
                message: "Failed to save client connection"
              });
            }
          } catch (parseError) {
            console.error(`❌ OAuth callback: Failed to parse token response for clientId=${clientId}:`, parseError);
            res.status(500).json({
              ok: false,
              reason: "PARSE_ERROR",
              message: "Invalid response from Shopify"
            });
          }

          resolve();
        });
      }
    );

    tokenRequest.on("error", (err) => {
      console.error(`❌ OAuth callback: Request error for clientId=${clientId}:`, err);
      res.status(500).json({
        ok: false,
        reason: "REQUEST_ERROR",
        message: "Failed to communicate with Shopify API"
      });
      resolve();
    });

    tokenRequest.write(tokenRequestData);
    tokenRequest.end();
  });
});

/**
 * GET /shopify/verify-order
 * Verifies if a customer has a paid order in the client's Shopify store
 * 
 * Query params:
 *   - clientId: Client identifier (e.g., Discord user ID)
 *   - email: Customer email address to check
 * 
 * Usage in Discord Bot:
 *   - User claims to have purchased from a Shopify store
 *   - Bot calls this endpoint with user's Discord ID as clientId and their email
 *   - Bot receives hasOrder flag to grant access or permissions
 *   - Bot can display orderId for confirmation if needed
 * 
 * Flow:
 * 1. Validates required query parameters (clientId, email)
 * 2. Loads client and Shopify credentials from MongoDB using getClientByClientId(clientId)
 *    - Multi-client architecture: Each client has isolated Shopify credentials
 *    - Returns STORE_NOT_FOUND if client doesn't exist or hasn't connected Shopify
 * 3. Makes authenticated request to Shopify Admin API using client's shop and accessToken
 * 4. Filters orders by email (case-insensitive) and financial_status = "paid"
 * 5. Returns whether a paid order exists and the order ID if found
 * 
 * Multi-client isolation:
 * - Each clientId resolves to their own Shopify store
 * - No cross-client data access
 * - Scalable to hundreds of clients
 */
app.get("/shopify/verify-order", async (req, res) => {
  const { clientId, email } = req.query;

  // Validate required query parameters
  if (!clientId || !email) {
    return res.status(400).json({
      ok: false,
      reason: "BAD_REQUEST",
      message: "clientId and email query parameters are required"
    });
  }

  // Load client and Shopify credentials from MongoDB (multi-client architecture)
  // clientId is PRIMARY KEY - lookup is strict and isolated per client
  let client;
  try {
    client = await getClientByClientId(clientId);
    if (!client || !client.shop || !client.shopifyAccessToken) {
      return res.status(404).json({
        ok: false,
        reason: "CLIENT_NOT_FOUND",
        message: "No Shopify store connected for this clientId"
      });
    }
  } catch (dbError) {
    console.error(`❌ Database error loading client (clientId=${clientId}):`, dbError);
    return res.status(500).json({
      ok: false,
      reason: "DB_ERROR",
      message: "Failed to load client credentials"
    });
  }

  // Extract Shopify credentials from client document (multi-client isolation)
  const shop = client.shop;
  const accessToken = client.shopifyAccessToken;

  // Prepare Shopify API request
  // Use Shopify Admin REST API to fetch orders
  // API version can be configured via env var, default to stable version
  const apiVersion = process.env.SHOPIFY_API_VERSION || "2024-01";
  const apiPath = `/admin/api/${apiVersion}/orders.json?status=any&limit=250`;

  return new Promise((resolve) => {
    const apiRequest = https.request(
      {
        hostname: shop,
        path: apiPath,
        method: "GET",
        headers: {
          "X-Shopify-Access-Token": accessToken,
          "Content-Type": "application/json"
        }
      },
      (apiResponse) => {
        let data = "";

        apiResponse.on("data", (chunk) => {
          data += chunk;
        });

        apiResponse.on("end", () => {
          // Handle non-200 responses from Shopify API
          if (apiResponse.statusCode !== 200) {
            console.error(`❌ Shopify API error (${apiResponse.statusCode}):`, data);
            return res.status(500).json({
              ok: false,
              reason: "SHOPIFY_API_ERROR",
              message: "Failed to fetch orders from Shopify"
            });
          }

          try {
            // Parse Shopify API response
            const responseData = JSON.parse(data);
            const orders = responseData.orders || [];

            // Filter orders by email (case-insensitive) and financial_status = "paid"
            const emailLower = email.toLowerCase().trim();
            const paidOrder = orders.find(order => {
              const orderEmail = (order.email || "").toLowerCase().trim();
              return orderEmail === emailLower && order.financial_status === "paid";
            });

            // Return verification result
            res.json({
              ok: true,
              hasOrder: paidOrder !== undefined,
              orderId: paidOrder ? String(paidOrder.id) : null
            });
          } catch (parseError) {
            console.error("❌ Failed to parse Shopify API response:", parseError);
            res.status(500).json({
              ok: false,
              reason: "PARSE_ERROR",
              message: "Invalid response from Shopify API"
            });
          }

          resolve();
        });
      }
    );

    apiRequest.on("error", (err) => {
      console.error("❌ Request error during Shopify API call:", err);
      res.status(500).json({
        ok: false,
        reason: "REQUEST_ERROR",
        message: "Failed to communicate with Shopify API"
      });
      resolve();
    });

    apiRequest.end();
  });
});

/**
 * POST /shopify/consume-order
 * Marks a Shopify order as consumed (used) for Discord role access
 * 
 * Request body:
 *   - clientId: Client identifier (store owner's ID)
 *   - orderId: Shopify order ID (explicit, required)
 *   - email: Customer email address
 *   - discordUserId: Discord user ID who is consuming the order
 * 
 * Usage in Discord Bot:
 *   - User provides their Shopify order ID
 *   - Bot calls this endpoint to mark the order as consumed
 *   - Bot grants Discord role based on successful consumption
 * 
 * TEMPORARY TESTING MODE:
 *   - Currently allows orders to be reused up to MAX_ORDER_USES times
 *   - This is FOR TESTING ONLY and should be reverted to single-use for production
 *   - Production should block reuse completely to prevent abuse
 * 
 * Flow:
 * 1. Validates required request body fields (clientId, orderId, email, discordUserId)
 * 2. Loads client and Shopify credentials from MongoDB using getClientByClientId(clientId)
 *    - Multi-client architecture: Each client has isolated Shopify credentials
 *    - Returns STORE_NOT_FOUND if client doesn't exist or hasn't connected Shopify
 * 3. Fetches specific order by orderId from Shopify API using client's shop and accessToken
 * 4. Verifies order exists, is paid, and email matches
 * 5. Counts how many times this orderId has already been consumed
 * 6. If count < MAX_ORDER_USES, stores new consumption record
 * 7. Returns success with orderId
 */

// TEMPORARY TESTING CONSTANT - REMOVE FOR PRODUCTION
// TODO: REVERT to single-use behavior for production (block on first use)
const MAX_ORDER_USES = 3;

app.post("/shopify/consume-order", async (req, res) => {
  // CRASH-PROOF WRAPPER: Ensure endpoint always returns JSON, never crashes
  try {
    // TEMPORARY DEBUG: Log raw headers and body
    console.log("[DEBUG] Raw headers:", JSON.stringify(req.headers, null, 2));
    const rawBodyBeforeParse = typeof req.body === 'string' ? req.body.substring(0, 200) : (req.body ? JSON.stringify(req.body).substring(0, 200) : '(empty)');
    console.log("[DEBUG] Raw body (before parsing, first 200 chars):", rawBodyBeforeParse);

    // DEFENSIVE LAYER 1: Safe JSON parsing if body is a string
    let body = req.body;
    if (typeof body === 'string') {
      try {
        body = JSON.parse(body);
      } catch (parseError) {
        return res.status(400).json({
          ok: false,
          reason: "INVALID_REQUEST"
        });
      }
    }

    // DEFENSIVE LAYER 2: Ensure body is an object
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({
        ok: false,
        reason: "INVALID_REQUEST"
      });
    }

    // DEFENSIVE LAYER 3: Extract and normalize clientId (MULTI-TENANT SAFE - NO FALLBACKS)
    // DO NOT override clientId - use EXACT value from request body
    // DO NOT default to "main" - require explicit clientId for multi-tenant isolation
    const rawClientId = body.clientId;
    
    // Validate clientId is present and non-empty
    if (!rawClientId || (typeof rawClientId === "string" && rawClientId.trim().length === 0)) {
      return res.status(400).json({
        ok: false,
        reason: "INVALID_REQUEST",
        message: "clientId is required"
      });
    }
    
    // Use EXACT clientId from request (trimmed for consistency, but no fallback)
    const clientId = String(rawClientId).trim();
    
    // Debug log for claim flow
    console.log("[CLAIM] clientId from request:", clientId);

    const rawOrderId = body.orderId;
    const rawEmail = body.email;
    const rawDiscordUserId = body.discordUserId;

    // DEFENSIVE LAYER 4: Validate required fields exist
    if (!rawOrderId || !rawEmail || !rawDiscordUserId) {
      return res.status(400).json({
        ok: false,
        reason: "INVALID_REQUEST"
      });
    }

    // DEFENSIVE LAYER 5: Normalize inputs safely
    const originalOrderId = String(rawOrderId); // Keep original for logging
    const orderId = String(rawOrderId); // Accept string or number
    const email = String(rawEmail).toLowerCase().trim();
    const discordUserId = String(rawDiscordUserId).trim();

    // DEFENSIVE LAYER 6: Normalize orderId (accept numeric ID, "#1001", or "1001")
    // TEMP DEBUG: Log original order input
    console.log("[DEBUG] Original order input:", originalOrderId);
    
    let normalizedOrderId = orderId.trim();
    if (normalizedOrderId.startsWith("#")) {
      normalizedOrderId = normalizedOrderId.substring(1);
    }
    normalizedOrderId = normalizedOrderId.trim();
    
    // TEMP DEBUG: Log normalized order input
    console.log("[DEBUG] Normalized order input:", normalizedOrderId);
    
    // Detect input type: length > 10 = Shopify order ID, else = order_number
    const inputType = normalizedOrderId.length > 10 ? "id" : "order_number";
    console.log("[DEBUG] Input type detected:", inputType);

    // Load client and Shopify credentials from MongoDB (multi-client architecture)
    // clientId is PRIMARY KEY - lookup is strict and isolated per client
    // Multi-tenant safe: Use EXACT clientId from request, no fallbacks
    let client;
    try {
      client = await getClientByClientId(clientId);
      // Return explicit CLIENT_NOT_FOUND error if client doesn't exist
      if (!client || !client.shop || !client.shopifyAccessToken) {
        console.log(`[CLAIM] Client NOT found or not connected: clientId=${clientId}`);
        return res.status(404).json({
          ok: false,
          reason: "CLIENT_NOT_FOUND",
          message: `No Shopify store connected for clientId: ${clientId}`
        });
      }
      
      // TEMP DEBUG: Log shop domain used
      console.log("[DEBUG] Shop domain used:", client.shop);
    } catch (dbError) {
      console.error(`❌ Database error loading client (clientId=${clientId}):`, dbError);
      return res.status(500).json({
        ok: false,
        reason: "INTERNAL_ERROR"
      });
    }

    // Extract Shopify credentials from client document (multi-client isolation)
    const shop = client.shop;
    const accessToken = client.shopifyAccessToken;

    // Helper function to fetch order by Shopify ID
    const fetchOrderById = (orderId) => {
      return new Promise((resolve, reject) => {
        const apiVersion = process.env.SHOPIFY_API_VERSION || "2024-01";
        const apiPath = `/admin/api/${apiVersion}/orders/${orderId}.json`;

        const apiRequest = https.request(
          {
            hostname: shop,
            path: apiPath,
            method: "GET",
            headers: {
              "X-Shopify-Access-Token": accessToken,
              "Content-Type": "application/json"
            }
          },
          (apiResponse) => {
            let data = "";

            apiResponse.on("data", (chunk) => {
              data += chunk;
            });

            apiResponse.on("end", () => {
              if (apiResponse.statusCode === 200) {
                try {
                  const responseData = JSON.parse(data);
                  resolve(responseData.order);
                } catch (parseError) {
                  reject(new Error(`Failed to parse response: ${parseError.message}`));
                }
              } else if (apiResponse.statusCode === 404) {
                resolve(null); // Order not found
              } else {
                reject(new Error(`API error ${apiResponse.statusCode}: ${data}`));
              }
            });
          }
        );

        apiRequest.on("error", (err) => {
          reject(err);
        });

        apiRequest.end();
      });
    };

    // Helper function to fetch orders list and find by order_number
    const fetchOrderByOrderNumber = (orderNumber) => {
      return new Promise((resolve, reject) => {
        const apiVersion = process.env.SHOPIFY_API_VERSION || "2024-01";
        const apiPath = `/admin/api/${apiVersion}/orders.json?status=any&limit=50`;

        const apiRequest = https.request(
          {
            hostname: shop,
            path: apiPath,
            method: "GET",
            headers: {
              "X-Shopify-Access-Token": accessToken,
              "Content-Type": "application/json"
            }
          },
          (apiResponse) => {
            let data = "";

            apiResponse.on("data", (chunk) => {
              data += chunk;
            });

            apiResponse.on("end", () => {
              if (apiResponse.statusCode === 200) {
                try {
                  const responseData = JSON.parse(data);
                  const orders = responseData.orders || [];
                  
                  // TEMP DEBUG: Log total orders scanned
                  console.log("[DEBUG] Total orders scanned:", orders.length);
                  
                  // Find order where order.order_number matches the input (as number)
                  const targetOrderNumber = Number(orderNumber);
                  const foundOrder = orders.find(order => {
                    return order.order_number === targetOrderNumber;
                  });
                  
                  resolve(foundOrder || null);
                } catch (parseError) {
                  reject(new Error(`Failed to parse response: ${parseError.message}`));
                }
              } else {
                reject(new Error(`API error ${apiResponse.statusCode}: ${data}`));
              }
            });
          }
        );

        apiRequest.on("error", (err) => {
          reject(err);
        });

        apiRequest.end();
      });
    };

    // Fetch order based on input type
    let order = null;
    try {
      if (inputType === "id") {
        // Fetch directly by Shopify order ID
        order = await fetchOrderById(normalizedOrderId);
      } else {
        // Fetch recent orders and find by order_number
        order = await fetchOrderByOrderNumber(normalizedOrderId);
      }
    } catch (fetchError) {
      console.error("❌ Error fetching order from Shopify:", fetchError);
      return res.status(500).json({
        ok: false,
        reason: "INTERNAL_ERROR"
      });
    }

    // Verify order exists
    if (!order) {
      return res.status(404).json({
        ok: false,
        reason: "ORDER_NOT_FOUND"
      });
    }

    // Extract the REAL Shopify order ID from the order object
    // IMPORTANT: Use ONLY this real ID for email comparison, consumed-order lookup, and reuse limits
    const verifiedOrderId = String(order.id);
    
    // TEMP DEBUG: Log resolved Shopify order ID
    console.log("[DEBUG] Resolved Shopify order ID:", verifiedOrderId);

    // Verify order is paid
    if (order.financial_status !== "paid") {
      return res.status(400).json({
        ok: false,
        reason: "ORDER_NOT_PAID"
      });
    }

    // Verify order email matches provided email (case-insensitive)
    const orderEmail = (order.email || "").toLowerCase().trim();
    
    // TEMP DEBUG: Log email comparison
    console.log("[DEBUG] Email from Shopify:", orderEmail);
    console.log("[DEBUG] Email from request:", email);
    console.log("[DEBUG] Email match result:", orderEmail === email ? "MATCH" : "MISMATCH");
    
    if (orderEmail !== email) {
      return res.status(400).json({
        ok: false,
        reason: "ORDER_EMAIL_MISMATCH"
      });
    }

    // DEFENSIVE LAYER 7: Check consumed order count (TEMP SAFE MODE - allows up to 3 uses)
    let existingConsumptionCount;
    try {
      existingConsumptionCount = await ConsumedOrder.countDocuments({
        clientId,
        orderId: verifiedOrderId
      });

      // TEMP DEBUG: Log consumed count
      console.log("[DEBUG] Consumed count:", existingConsumptionCount, "/", MAX_ORDER_USES);

      // TEMP: Allow up to MAX_ORDER_USES (3) per orderId
      if (existingConsumptionCount >= MAX_ORDER_USES) {
        return res.status(400).json({
          ok: false,
          reason: "ORDER_ALREADY_USED"
        });
      }
    } catch (checkError) {
      console.error("❌ Database error checking consumed order count:", checkError);
      return res.status(500).json({
        ok: false,
        reason: "INTERNAL_ERROR"
      });
    }

    // DEFENSIVE LAYER 8: Store consumed order record (TEMP SAFE MODE)
    try {
      await ConsumedOrder.create({
        clientId,
        orderId: verifiedOrderId,
        email: email,
        discordUserId,
        consumedAt: new Date()
      });

      // Return success with real Shopify order ID
      return res.json({
        ok: true,
        orderId: verifiedOrderId
      });
    } catch (saveError) {
      console.error("❌ Database error saving consumed order:", saveError);
      return res.status(500).json({
        ok: false,
        reason: "INTERNAL_ERROR"
      });
    }

  } catch (error) {
    // FINAL CRASH-PROOF LAYER: Catch any unhandled errors
    console.error("❌ Unhandled error in consume-order:", error);
    return res.status(500).json({
      ok: false,
      reason: "INTERNAL_ERROR"
    });
  }
});

/* ================= START ================= */

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log("🚀 LICENSE SERVER RUNNING ON PORT", PORT);
});
