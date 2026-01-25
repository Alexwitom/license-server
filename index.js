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

/* ================= EXPAND ================= */

/**
 * POST /admin/expand
 * Extends the expiration date of an existing license by adding days
 * 
 * Request body:
 *   - license: License key (required)
 *   - days: Number of days to add (required, must be positive number)
 *   - adminKey: Admin authentication key (required)
 * 
 * Usage:
 *   - Admin extends a license expiration date
 *   - Days are added to the current expiresAt date
 *   - If license doesn't exist, returns 404
 * 
 * Flow:
 * 1. Validates adminKey against process.env.ADMIN_KEY
 * 2. Validates required fields (license, days, adminKey)
 * 3. Validates days is a positive number
 * 4. Finds license in MongoDB by key
 * 5. If not found → returns 404
 * 6. Adds days to expiresAt date
 * 7. Saves updated license
 * 8. Returns success with updated expiresAt and formatted expiresAtHuman
 */
app.post("/admin/expand", async (req, res) => {
  const { license, days, adminKey } = req.body;

  // Validate adminKey
  if (adminKey !== process.env.ADMIN_KEY) {
    return res.status(403).json({ ok: false, reason: "FORBIDDEN" });
  }

  // Validate required fields
  if (!license || days === undefined) {
    return res.status(400).json({ ok: false, reason: "BAD_REQUEST" });
  }

  // Validate days is a positive number
  const daysNumber = Number(days);
  if (!Number.isFinite(daysNumber) || daysNumber <= 0) {
    return res.status(400).json({
      ok: false,
      reason: "INVALID_DAYS",
      message: "days must be a positive number"
    });
  }

  try {
    // Find license by key
    const lic = await License.findOne({ key: license });
    
    if (!lic) {
      return res.status(404).json({
        ok: false,
        reason: "NOT_FOUND",
        message: "License not found"
      });
    }

    // Determine base date: use expiresAt if valid, otherwise use current date
    let baseDate;
    
    if (lic.expiresAt) {
      // Try to create Date from expiresAt (handles both Date objects and strings)
      const parsedDate = new Date(lic.expiresAt);
      
      // Check if parsed date is valid
      if (parsedDate instanceof Date && !isNaN(parsedDate.getTime())) {
        baseDate = parsedDate;
      } else {
        // Invalid date, use current date
        baseDate = new Date();
      }
    } else {
      // expiresAt is null or undefined, use current date
      baseDate = new Date();
    }

    // Add days to base date
    const newExpiresAt = new Date(baseDate.getTime() + daysNumber * 86400000);

    // Update license - ensure expiresAt is saved as Date object
    lic.expiresAt = newExpiresAt;
    await lic.save();

    // Return success with updated expiration dates
    res.json({
      ok: true,
      expiresAt: newExpiresAt.toISOString(),
      expiresAtHuman: newExpiresAt.toLocaleString("pl-PL")
    });
  } catch (error) {
    console.error("❌ Error expanding license:", error);
    return res.status(500).json({
      ok: false,
      reason: "DB_ERROR",
      message: error.message || "Failed to update license"
    });
  }
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

  // CRITICAL: clientId MUST come from Electron app (query parameter)
  // NEVER use environment variables or bot config
  const clientIdSource = "query_param";
  
  // Log clientId source immediately
  console.log(`[OAUTH_AUTH] clientId received from ${clientIdSource}: ${clientId || "(missing)"}`);

  // Validate required parameters
  if (!clientId) {
    console.error(`❌ [OAUTH_AUTH] Missing clientId parameter (source: ${clientIdSource})`);
    return res.status(400).json({
      ok: false,
      reason: "BAD_REQUEST",
      message: "clientId query parameter is required"
    });
  }

  if (!shop) {
    console.error(`❌ [OAUTH_AUTH] Missing shop parameter for clientId: ${clientId} (source: ${clientIdSource})`);
    return res.status(400).json({
      ok: false,
      reason: "BAD_REQUEST",
      message: "shop query parameter is required"
    });
  }

  // Validate clientId format (non-empty string)
  if (typeof clientId !== "string" || clientId.trim().length === 0) {
    console.error(`❌ [OAUTH_AUTH] Invalid clientId format: ${clientId} (source: ${clientIdSource})`);
    return res.status(400).json({
      ok: false,
      reason: "INVALID_CLIENT_ID",
      message: "clientId must be a non-empty string"
    });
  }

  // Normalize clientId (trim only, no fallbacks)
  const normalizedClientId = String(clientId).trim();
  console.log(`[OAUTH_AUTH] Normalized clientId: ${normalizedClientId} (source: ${clientIdSource})`);

  // Validate shop domain format
  if (!shop.includes(".myshopify.com")) {
    console.error(`❌ [OAUTH_AUTH] Invalid shop format for clientId: ${normalizedClientId}, shop: ${shop} (source: ${clientIdSource})`);
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
    console.error("❌ [OAUTH_AUTH] SHOPIFY_API_KEY not set in environment");
    return res.status(500).json({
      ok: false,
      reason: "SERVER_ERROR",
      message: "Shopify API key not configured"
    });
  }

  // Log OAuth initiation with source
  console.log(`🔐 [OAUTH_AUTH] OAuth started: clientId=${normalizedClientId} (source: ${clientIdSource}), shop=${shop}`);

  // Create state token: base64 encode normalizedClientId + random nonce for security
  const nonce = crypto.randomBytes(16).toString("hex");
  const state = Buffer.from(JSON.stringify({ clientId: normalizedClientId, nonce })).toString("base64");

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
  const { code, state, shop, hmac, clientId: queryClientId } = req.query;

  // Validate required parameters
  if (!code || !shop) {
    console.error("❌ OAuth callback: Missing required parameters");
    return res.status(400).json({
      ok: false,
      reason: "BAD_REQUEST",
      message: "code and shop query parameters are required"
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

  // CRITICAL: clientId MUST come from Electron/Discord, NEVER from shop name or environment
  // Priority: 1) query param clientId, 2) state token clientId
  // NEVER use process.env.CLIENT_ID or bot config
  let clientId;
  let clientIdSource = "unknown";

  // Try to get clientId from query parameter first (preferred - from Electron/Discord)
  if (queryClientId && typeof queryClientId === "string" && queryClientId.trim().length > 0) {
    clientId = String(queryClientId).trim();
    clientIdSource = "query_param";
    console.log(`[OAUTH_CALLBACK] clientId received from ${clientIdSource}: ${clientId}`);
  } else if (state) {
    // Fallback: try to get clientId from state token
    try {
      const stateData = JSON.parse(Buffer.from(state, "base64").toString());
      const stateClientId = stateData.clientId;
      if (stateClientId && typeof stateClientId === "string" && stateClientId.trim().length > 0) {
        clientId = String(stateClientId).trim();
        clientIdSource = "state_token";
        console.log(`[OAUTH_CALLBACK] clientId received from ${clientIdSource}: ${clientId}`);
      }
    } catch (err) {
      console.warn(`⚠️  [OAUTH_CALLBACK] Failed to decode state token: ${err.message}`);
    }
  }

  // Validate clientId was found
  if (!clientId || clientId.trim().length === 0) {
    console.error(`❌ [OAUTH_CALLBACK] clientId is required (must come from Electron/Discord, not shop name or environment). Source: ${clientIdSource}`);
    return res.status(400).json({
      ok: false,
      reason: "MISSING_CLIENT_ID",
      message: "clientId query parameter is required. clientId must come from Electron/Discord, never from shop name or environment."
    });
  }

  // CRITICAL: NEVER use shop name as clientId
  // Validate that clientId is not the shop name
  if (clientId === shop || clientId.includes(".myshopify.com")) {
    console.error(`❌ [OAUTH_CALLBACK] Invalid clientId - cannot use shop name as clientId. clientId=${clientId}, shop=${shop} (source: ${clientIdSource})`);
    return res.status(400).json({
      ok: false,
      reason: "INVALID_CLIENT_ID",
      message: "clientId cannot be the shop name. clientId must come from Electron/Discord."
    });
  }

  console.log(`🔐 [OAUTH_CALLBACK] Processing OAuth: clientId=${clientId} (source: ${clientIdSource}), shop=${shop}`);

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

            // Update or create Client document in MongoDB
            // CRITICAL: clientId is PRIMARY KEY - NEVER generate or overwrite it
            // CRITICAL: shop name is a FIELD, not an identifier
            // CRITICAL: clientId MUST come from Electron/Discord request, NEVER from environment
            try {
              // Check if client already exists (for logging purposes)
              const existingClient = await Client.findOne({ clientId });
              const isNewClient = !existingClient;
              
              // Log whether existing client was found
              if (existingClient) {
                console.log(`[OAUTH_CALLBACK] Existing client found: clientId=${clientId} (source: ${clientIdSource}), shop=${existingClient.shop || "N/A"}`);
              } else {
                console.log(`[OAUTH_CALLBACK] No existing client found: clientId=${clientId} (source: ${clientIdSource}) - will create new client`);
              }

              // Check for duplicate clients with same shop (warn only, don't delete)
              const duplicateClients = await Client.find({ shop: shop });
              if (duplicateClients.length > 1 || (duplicateClients.length === 1 && duplicateClients[0].clientId !== clientId)) {
                const duplicateClientIds = duplicateClients.map(c => c.clientId).filter(id => id !== clientId);
                if (duplicateClientIds.length > 0) {
                  console.warn(`⚠️  [OAUTH_CALLBACK] WARNING: Multiple clients found for shop=${shop}. Other clientIds: ${duplicateClientIds.join(", ")}. Current clientId: ${clientId} (source: ${clientIdSource})`);
                }
              }

              // Use updateOne with upsert to update existing client or create new one
              // This ensures: one clientId = one Mongo document
              const updateResult = await Client.updateOne(
                { clientId: clientId },
                {
                  $set: {
                    platform: "shopify",
                    shop: shop,
                    shopifyAccessToken: access_token
                  }
                },
                {
                  upsert: true,
                  setDefaultsOnInsert: true
                }
              );

              if (isNewClient) {
                console.log(`[OAUTH_CALLBACK] Client created: clientId=${clientId} (source: ${clientIdSource}), shop=${shop}, platform=shopify`);
              } else {
                console.log(`[OAUTH_CALLBACK] Client updated: clientId=${clientId} (source: ${clientIdSource}), shop=${shop}, platform=shopify`);
              }

              console.log(`✅ [OAUTH_CALLBACK] OAuth success: clientId=${clientId} (source: ${clientIdSource}), shop=${shop}, created=${isNewClient}, existingClientFound=${!isNewClient}`);

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
 * WooCommerce API Helper Functions
 * 
 * These functions handle WooCommerce REST API authentication and order fetching.
 * WooCommerce uses HTTP Basic Auth with consumer key and consumer secret.
 */

/**
 * Make authenticated WooCommerce API request
 * @param {string} storeUrl - WooCommerce store URL (e.g., "https://example.com")
 * @param {string} consumerKey - WooCommerce consumer key
 * @param {string} consumerSecret - WooCommerce consumer secret
 * @param {string} endpoint - API endpoint path (e.g., "/wp-json/wc/v3/orders")
 * @returns {Promise<Object>} - Parsed JSON response
 */
function makeWooCommerceRequest(storeUrl, consumerKey, consumerSecret, endpoint) {
  return new Promise((resolve, reject) => {
    // Normalize store URL (remove trailing slash, ensure https)
    let normalizedUrl = storeUrl.trim();
    if (!normalizedUrl.startsWith("http://") && !normalizedUrl.startsWith("https://")) {
      normalizedUrl = "https://" + normalizedUrl;
    }
    normalizedUrl = normalizedUrl.replace(/\/$/, "");

    // Parse URL
    const url = new URL(normalizedUrl + endpoint);
    const isHttps = url.protocol === "https:";

    // WooCommerce uses HTTP Basic Auth
    const auth = Buffer.from(`${consumerKey}:${consumerSecret}`).toString("base64");

    const options = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + url.search,
      method: "GET",
      headers: {
        "Authorization": `Basic ${auth}`,
        "Content-Type": "application/json"
      }
    };

    const httpModule = isHttps ? https : require("http");
    const apiRequest = httpModule.request(options, (apiResponse) => {
      let data = "";

      apiResponse.on("data", (chunk) => {
        data += chunk;
      });

      apiResponse.on("end", () => {
        if (apiResponse.statusCode === 200 || apiResponse.statusCode === 201) {
          try {
            const responseData = JSON.parse(data);
            resolve(responseData);
          } catch (parseError) {
            reject(new Error(`Failed to parse WooCommerce response: ${parseError.message}`));
          }
        } else {
          reject(new Error(`WooCommerce API error ${apiResponse.statusCode}: ${data.substring(0, 200)}`));
        }
      });
    });

    apiRequest.on("error", (err) => {
      reject(err);
    });

    apiRequest.end();
  });
}

/**
 * Fetch WooCommerce orders by customer email
 * @param {string} storeUrl - WooCommerce store URL
 * @param {string} consumerKey - WooCommerce consumer key
 * @param {string} consumerSecret - WooCommerce consumer secret
 * @param {string} email - Customer email address
 * @returns {Promise<Array>} - Array of paid orders matching the email
 */
async function fetchWooCommerceOrdersByEmail(storeUrl, consumerKey, consumerSecret, email) {
  try {
    // WooCommerce API: search orders by customer email
    // Note: WooCommerce API doesn't have direct email filter, so we fetch recent orders and filter
    const endpoint = `/wp-json/wc/v3/orders?per_page=100&status=any`;
    const orders = await makeWooCommerceRequest(storeUrl, consumerKey, consumerSecret, endpoint);

    // Filter orders by email (case-insensitive) and status = "completed" or "processing" (paid)
    const emailLower = email.toLowerCase().trim();
    const paidOrders = orders.filter(order => {
      const orderEmail = (order.billing?.email || "").toLowerCase().trim();
      const isPaid = order.status === "completed" || order.status === "processing";
      return orderEmail === emailLower && isPaid;
    });

    return paidOrders;
  } catch (error) {
    console.error("❌ Error fetching WooCommerce orders:", error);
    throw error;
  }
}

/**
 * Fetch WooCommerce order by ID
 * @param {string} storeUrl - WooCommerce store URL
 * @param {string} consumerKey - WooCommerce consumer key
 * @param {string} consumerSecret - WooCommerce consumer secret
 * @param {string} orderId - WooCommerce order ID
 * @returns {Promise<Object|null>} - Order object or null if not found
 */
async function fetchWooCommerceOrderById(storeUrl, consumerKey, consumerSecret, orderId) {
  try {
    const endpoint = `/wp-json/wc/v3/orders/${orderId}`;
    const order = await makeWooCommerceRequest(storeUrl, consumerKey, consumerSecret, endpoint);
    return order;
  } catch (error) {
    if (error.message.includes("404")) {
      return null; // Order not found
    }
    throw error;
  }
}

/**
 * GET /shopify/verify-order
 * Verifies if a customer has a paid order in the client's e-commerce store
 * Supports both Shopify and WooCommerce platforms
 * 
 * Query params:
 *   - clientId: Client identifier (e.g., Discord user ID)
 *   - email: Customer email address to check
 * 
 * Usage in Discord Bot:
 *   - User claims to have purchased from a store
 *   - Bot calls this endpoint with user's Discord ID as clientId and their email
 *   - Bot receives hasOrder flag to grant access or permissions
 *   - Bot can display orderId for confirmation if needed
 * 
 * Flow:
 * 1. Validates required query parameters (clientId, email)
 * 2. Loads client and platform credentials from MongoDB using getClientByClientId(clientId)
 *    - Multi-client architecture: Each client has isolated store credentials
 *    - Returns CLIENT_NOT_FOUND if client doesn't exist or hasn't connected a store
 * 3. Detects platform (shopify or woocommerce)
 * 4. Makes authenticated request to appropriate API (Shopify Admin API or WooCommerce REST API)
 * 5. Filters orders by email (case-insensitive) and payment status
 * 6. Returns whether a paid order exists and the order ID if found
 * 
 * Multi-client isolation:
 * - Each clientId resolves to their own store
 * - No cross-client data access
 * - Scalable to hundreds of clients
 */
app.get("/shopify/verify-order", async (req, res) => {
  const { clientId, email } = req.query;

  // CRITICAL: clientId MUST come from Electron/Discord request (query parameter)
  // NEVER use environment variables or bot config
  const clientIdSource = "query_param";
  
  // Log clientId source immediately
  console.log(`[VERIFY_ORDER] clientId received from ${clientIdSource}: ${clientId || "(missing)"}`);

  // Validate required query parameters
  if (!clientId || !email) {
    console.error(`❌ [VERIFY_ORDER] Missing required parameters: clientId=${clientId || "(missing)"}, email=${email || "(missing)"} (source: ${clientIdSource})`);
    return res.status(400).json({
      ok: false,
      reason: "BAD_REQUEST",
      message: "clientId and email query parameters are required"
    });
  }

  // Normalize clientId (trim only, no fallbacks)
  const normalizedClientId = String(clientId).trim();
  console.log(`[VERIFY_ORDER] Normalized clientId: ${normalizedClientId} (source: ${clientIdSource})`);

  // Load client and platform credentials from MongoDB (multi-client architecture)
  // clientId is PRIMARY KEY - lookup is strict and isolated per client
  // NEVER use process.env.CLIENT_ID or bot config
  let client;
  try {
    client = await getClientByClientId(normalizedClientId);
    if (!client) {
      console.log(`[VERIFY_ORDER] Client NOT found: clientId=${normalizedClientId} (source: ${clientIdSource})`);
      return res.status(404).json({
        ok: false,
        reason: "CLIENT_NOT_FOUND",
        message: "No store connected for this clientId"
      });
    }
    console.log(`[VERIFY_ORDER] Client found: clientId=${normalizedClientId} (source: ${clientIdSource}), shop=${client.shop || "N/A"}, platform=${client.platform || "shopify"}`);
  } catch (dbError) {
    console.error(`❌ [VERIFY_ORDER] Database error loading client (clientId=${normalizedClientId}, source: ${clientIdSource}):`, dbError);
    return res.status(500).json({
      ok: false,
      reason: "DB_ERROR",
      message: "Failed to load client credentials"
    });
  }

  // Detect platform (default to "shopify" for backward compatibility)
  const platform = client.platform || "shopify";
  console.log(`[VERIFY] Platform: ${platform}, clientId: ${clientId}`);

  // Validate platform-specific credentials
  if (platform === "shopify") {
    if (!client.shop || !client.shopifyAccessToken) {
      return res.status(404).json({
        ok: false,
        reason: "CLIENT_NOT_FOUND",
        message: "No Shopify store connected for this clientId"
      });
    }
  } else if (platform === "woocommerce") {
    if (!client.storeUrl || !client.consumerKey || !client.consumerSecret) {
      return res.status(404).json({
        ok: false,
        reason: "CLIENT_NOT_FOUND",
        message: "No WooCommerce store connected for this clientId"
      });
    }
  } else {
    return res.status(400).json({
      ok: false,
      reason: "INVALID_PLATFORM",
      message: `Unsupported platform: ${platform}`
    });
  }

  // Verify order based on platform
  try {
    if (platform === "shopify") {
      // Shopify order verification
      const shop = client.shop;
      const accessToken = client.shopifyAccessToken;

      // Prepare Shopify API request
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
              if (apiResponse.statusCode !== 200) {
                console.error(`❌ Shopify API error (${apiResponse.statusCode}):`, data);
                return res.status(500).json({
                  ok: false,
                  reason: "SHOPIFY_API_ERROR",
                  message: "Failed to fetch orders from Shopify"
                });
              }

              try {
                const responseData = JSON.parse(data);
                const orders = responseData.orders || [];

                // Filter orders by email (case-insensitive) and financial_status = "paid"
                const emailLower = email.toLowerCase().trim();
                const paidOrder = orders.find(order => {
                  const orderEmail = (order.email || "").toLowerCase().trim();
                  return orderEmail === emailLower && order.financial_status === "paid";
                });

                console.log(`[VERIFY] Shopify result: hasOrder=${paidOrder !== undefined}, orderId=${paidOrder ? paidOrder.id : null}`);

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
    } else if (platform === "woocommerce") {
      // WooCommerce order verification
      const storeUrl = client.storeUrl;
      const consumerKey = client.consumerKey;
      const consumerSecret = client.consumerSecret;

      const paidOrders = await fetchWooCommerceOrdersByEmail(storeUrl, consumerKey, consumerSecret, email);

      console.log(`[VERIFY] WooCommerce result: hasOrder=${paidOrders.length > 0}, orderCount=${paidOrders.length}`);

      res.json({
        ok: true,
        hasOrder: paidOrders.length > 0,
        orderId: paidOrders.length > 0 ? String(paidOrders[0].id) : null
      });
    }
  } catch (apiError) {
    console.error(`❌ ${platform} API error:`, apiError);
    return res.status(500).json({
      ok: false,
      reason: `${platform.toUpperCase()}_API_ERROR`,
      message: `Failed to fetch orders from ${platform}`
    });
  }
});

/**
 * POST /shopify/consume-order
 * Marks an e-commerce order as consumed (used) for Discord role access
 * Supports both Shopify and WooCommerce platforms
 * 
 * Request body:
 *   - clientId: Client identifier (store owner's ID)
 *   - orderId: Order ID (explicit, required) - Shopify numeric ID or WooCommerce order ID
 *   - email: Customer email address
 *   - discordUserId: Discord user ID who is consuming the order
 * 
 * Usage in Discord Bot:
 *   - User provides their order ID
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
 * 2. Loads client and platform credentials from MongoDB using getClientByClientId(clientId)
 *    - Multi-client architecture: Each client has isolated store credentials
 *    - Returns CLIENT_NOT_FOUND if client doesn't exist or hasn't connected a store
 * 3. Detects platform (shopify or woocommerce)
 * 4. Fetches specific order by orderId from appropriate API (Shopify or WooCommerce)
 * 5. Verifies order exists, is paid, and email matches
 * 6. Counts how many times this orderId has already been consumed
 * 7. If count < MAX_ORDER_USES, stores new consumption record
 * 8. Returns success with orderId
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
    // CRITICAL: clientId MUST come from Electron/Discord request (body parameter)
    // NEVER use process.env.CLIENT_ID or bot config
    // DO NOT override clientId - use EXACT value from request body
    // DO NOT default to "main" - require explicit clientId for multi-tenant isolation
    const clientIdSource = "body_param";
    const rawClientId = body.clientId;
    
    // Log clientId source immediately
    console.log(`[CONSUME_ORDER] clientId received from ${clientIdSource}: ${rawClientId || "(missing)"}`);
    
    // Validate clientId is present and non-empty
    if (!rawClientId || (typeof rawClientId === "string" && rawClientId.trim().length === 0)) {
      console.error(`❌ [CONSUME_ORDER] Missing or empty clientId (source: ${clientIdSource})`);
      return res.status(400).json({
        ok: false,
        reason: "INVALID_REQUEST",
        message: "clientId is required"
      });
    }
    
    // Use EXACT clientId from request (trimmed for consistency, but no fallback)
    const clientId = String(rawClientId).trim();
    console.log(`[CONSUME_ORDER] Normalized clientId: ${clientId} (source: ${clientIdSource})`);

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

    // Load client and platform credentials from MongoDB (multi-client architecture)
    // clientId is PRIMARY KEY - lookup is strict and isolated per client
    // Multi-tenant safe: Use EXACT clientId from request, no fallbacks
    // NEVER use process.env.CLIENT_ID or bot config
    let client;
    try {
      client = await getClientByClientId(clientId);
      if (!client) {
        console.log(`[CONSUME_ORDER] Client NOT found: clientId=${clientId} (source: ${clientIdSource})`);
        return res.status(404).json({
          ok: false,
          reason: "CLIENT_NOT_FOUND",
          message: `No store connected for clientId: ${clientId}`
        });
      }
      console.log(`[CONSUME_ORDER] Client found: clientId=${clientId} (source: ${clientIdSource}), shop=${client.shop || "N/A"}, platform=${client.platform || "shopify"}`);
    } catch (dbError) {
      console.error(`❌ [CONSUME_ORDER] Database error loading client (clientId=${clientId}, source: ${clientIdSource}):`, dbError);
      return res.status(500).json({
        ok: false,
        reason: "INTERNAL_ERROR"
      });
    }

    // Detect platform (default to "shopify" for backward compatibility)
    const platform = client.platform || "shopify";
    console.log(`[CLAIM] Platform: ${platform}, clientId: ${clientId}`);

    // Validate platform-specific credentials
    if (platform === "shopify") {
      if (!client.shop || !client.shopifyAccessToken) {
        console.log(`[CLAIM] Shopify store not connected: clientId=${clientId}`);
        return res.status(404).json({
          ok: false,
          reason: "CLIENT_NOT_FOUND",
          message: `No Shopify store connected for clientId: ${clientId}`
        });
      }
    } else if (platform === "woocommerce") {
      if (!client.storeUrl || !client.consumerKey || !client.consumerSecret) {
        console.log(`[CLAIM] WooCommerce store not connected: clientId=${clientId}`);
        return res.status(404).json({
          ok: false,
          reason: "CLIENT_NOT_FOUND",
          message: `No WooCommerce store connected for clientId: ${clientId}`
        });
      }
    } else {
      return res.status(400).json({
        ok: false,
        reason: "INVALID_PLATFORM",
        message: `Unsupported platform: ${platform}`
      });
    }

    // Fetch order based on platform
    let order = null;
    let verifiedOrderId = null;

    try {
      if (platform === "shopify") {
        // Shopify order fetching logic
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
        if (inputType === "id") {
          // Fetch directly by Shopify order ID
          order = await fetchOrderById(normalizedOrderId);
        } else {
          // Fetch recent orders and find by order_number
          order = await fetchOrderByOrderNumber(normalizedOrderId);
        }

        if (!order) {
          return res.status(404).json({
            ok: false,
            reason: "ORDER_NOT_FOUND"
          });
        }

        // Extract the REAL Shopify order ID
        verifiedOrderId = String(order.id);
        console.log(`[CLAIM] Shopify order ID resolved: ${verifiedOrderId}`);

        // Verify order is paid
        if (order.financial_status !== "paid") {
          return res.status(400).json({
            ok: false,
            reason: "ORDER_NOT_PAID"
          });
        }

        // Verify order email matches provided email (case-insensitive)
        const orderEmail = (order.email || "").toLowerCase().trim();
        console.log(`[CLAIM] Shopify email check: orderEmail=${orderEmail}, requestEmail=${email}`);
        
        if (orderEmail !== email) {
          return res.status(400).json({
            ok: false,
            reason: "ORDER_EMAIL_MISMATCH"
          });
        }

      } else if (platform === "woocommerce") {
        // WooCommerce order fetching logic
        const storeUrl = client.storeUrl;
        const consumerKey = client.consumerKey;
        const consumerSecret = client.consumerSecret;

        // WooCommerce uses numeric order IDs directly (no order_number concept like Shopify)
        order = await fetchWooCommerceOrderById(storeUrl, consumerKey, consumerSecret, normalizedOrderId);

        if (!order) {
          return res.status(404).json({
            ok: false,
            reason: "ORDER_NOT_FOUND"
          });
        }

        // Extract WooCommerce order ID
        verifiedOrderId = String(order.id);
        console.log(`[CLAIM] WooCommerce order ID resolved: ${verifiedOrderId}`);

        // Verify order is paid (WooCommerce: status must be "completed" or "processing")
        if (order.status !== "completed" && order.status !== "processing") {
          return res.status(400).json({
            ok: false,
            reason: "ORDER_NOT_PAID"
          });
        }

        // Verify order email matches provided email (case-insensitive)
        const orderEmail = (order.billing?.email || "").toLowerCase().trim();
        console.log(`[CLAIM] WooCommerce email check: orderEmail=${orderEmail}, requestEmail=${email}`);
        
        if (orderEmail !== email) {
          return res.status(400).json({
            ok: false,
            reason: "ORDER_EMAIL_MISMATCH"
          });
        }
      }

    } catch (fetchError) {
      console.error(`❌ Error fetching order from ${platform}:`, fetchError);
      return res.status(500).json({
        ok: false,
        reason: "INTERNAL_ERROR"
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

/**
 * POST /client/theme
 * Updates the theme preset for an existing client
 * 
 * Request body:
 *   - clientId: Client identifier (required)
 *   - preset: Theme preset name (required, e.g., "dark_green", "light_blue")
 * 
 * Usage:
 *   - Client selects a theme preset in UI
 *   - Frontend calls this endpoint to save the preference
 *   - Preset is stored per clientId for future use
 * 
 * Flow:
 * 1. Validates required fields (clientId, preset)
 * 2. Validates preset is a non-empty string
 * 3. Checks if client exists (MUST exist - no implicit creation)
 * 4. Updates theme.preset using updateOne with upsert: false
 * 5. Returns success with saved preset
 * 
 * CRITICAL RULES:
 * - Client document MUST exist before saving theme
 * - Client can ONLY be created during Shopify OAuth or WooCommerce config save
 * - NEVER create client implicitly during theme save
 * - Returns CLIENT_NOT_FOUND error if client doesn't exist
 * 
 * Multi-client support:
 * - Each clientId has its own theme preset
 * - Safe for hundreds of clients
 * - One clientId = one Mongo document
 */
app.post("/client/theme", async (req, res) => {
  try {
    // DEFENSIVE LAYER 1: Safe JSON parsing if body is a string
    let body = req.body;
    if (typeof body === 'string') {
      try {
        body = JSON.parse(body);
      } catch (parseError) {
        return res.status(400).json({
          ok: false,
          reason: "INVALID_REQUEST",
          message: "Invalid JSON in request body"
        });
      }
    }

    // DEFENSIVE LAYER 2: Ensure body is an object
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({
        ok: false,
        reason: "INVALID_REQUEST",
        message: "Request body must be a JSON object"
      });
    }

    // DEFENSIVE LAYER 3: Extract and validate clientId
    // CRITICAL: clientId MUST come from Electron/Discord request (body parameter)
    // NEVER use process.env.CLIENT_ID or bot config
    const clientIdSource = "body_param";
    const rawClientId = body.clientId;
    
    // Log clientId source immediately
    console.log(`[THEME_SAVE] clientId received from ${clientIdSource}: ${rawClientId || "(missing)"}`);
    
    if (!rawClientId || (typeof rawClientId === "string" && rawClientId.trim().length === 0)) {
      console.error(`❌ [THEME_SAVE] Missing or empty clientId (source: ${clientIdSource})`);
      return res.status(400).json({
        ok: false,
        reason: "INVALID_REQUEST",
        message: "clientId is required"
      });
    }
    const clientId = String(rawClientId).trim();
    console.log(`[THEME_SAVE] Normalized clientId: ${clientId} (source: ${clientIdSource})`);

    // DEFENSIVE LAYER 4: Extract and validate preset
    const rawPreset = body.preset;
    if (!rawPreset || typeof rawPreset !== "string" || rawPreset.trim().length === 0) {
      return res.status(400).json({
        ok: false,
        reason: "INVALID_PRESET",
        message: "preset is required and must be a non-empty string"
      });
    }

    // Normalize preset: trim whitespace
    const preset = String(rawPreset).trim();

    // Log theme save attempt
    console.log(`[THEME_SAVE] Attempting to save theme: clientId=${clientId} (source: ${clientIdSource}), preset=${preset}`);

    // CRITICAL: Check if client exists BEFORE updating
    // Client MUST exist - never create implicitly during theme save
    // NEVER use process.env.CLIENT_ID or bot config
    let existingClient;
    try {
      existingClient = await Client.findOne({ clientId: clientId });
      if (existingClient) {
        console.log(`[THEME_SAVE] Existing client found: clientId=${clientId} (source: ${clientIdSource}), shop=${existingClient.shop || "N/A"}`);
      } else {
        console.log(`[THEME_SAVE] No existing client found: clientId=${clientId} (source: ${clientIdSource})`);
      }
    } catch (dbError) {
      console.error(`❌ [THEME_SAVE] Database error checking client existence (clientId=${clientId}, source: ${clientIdSource}):`, dbError);
      return res.status(500).json({
        ok: false,
        reason: "INTERNAL_ERROR",
        message: "Failed to check client existence"
      });
    }

    // If client doesn't exist, return error (DO NOT create)
    if (!existingClient) {
      console.warn(`⚠️  [THEME_SAVE] WARNING: Theme save attempted for non-existing client: clientId=${clientId} (source: ${clientIdSource})`);
      return res.status(404).json({
        ok: false,
        reason: "CLIENT_NOT_FOUND",
        message: `Client with clientId=${clientId} does not exist. Client must be created during Shopify OAuth or WooCommerce configuration.`
      });
    }

    // Client exists - update theme preset using updateOne with upsert: false
    // This ensures we NEVER create a client during theme save
    try {
      const updateResult = await Client.updateOne(
        { clientId: clientId },
        {
          $set: {
            "theme.preset": preset
          }
        },
        { upsert: false } // CRITICAL: upsert: false - never create client here
      );

      // Log update result
      if (updateResult.matchedCount === 0) {
        // This should never happen since we checked existence above, but log it anyway
        console.error(`❌ [THEME_SAVE] Update matched 0 documents (unexpected): clientId=${clientId}`);
        return res.status(404).json({
          ok: false,
          reason: "CLIENT_NOT_FOUND",
          message: `Client with clientId=${clientId} was not found during update`
        });
      }

      if (updateResult.modifiedCount === 1) {
        console.log(`✅ [THEME_SAVE] Theme updated: clientId=${clientId}, preset=${preset} (update occurred)`);
      } else if (updateResult.modifiedCount === 0) {
        console.log(`ℹ️  [THEME_SAVE] Theme unchanged: clientId=${clientId}, preset=${preset} (no update needed - preset already set)`);
      }

      // Return success response
      return res.json({
        ok: true,
        message: "Theme updated",
        preset: preset
      });
    } catch (dbError) {
      console.error(`❌ [THEME_SAVE] Database error updating theme (clientId=${clientId}):`, dbError);
      return res.status(500).json({
        ok: false,
        reason: "INTERNAL_ERROR",
        message: "Failed to update theme"
      });
    }

  } catch (error) {
    // FINAL CRASH-PROOF LAYER: Catch any unhandled errors
    console.error("❌ [THEME_SAVE] Unhandled error in /client/theme:", error);
    return res.status(500).json({
      ok: false,
      reason: "INTERNAL_ERROR",
      message: "An unexpected error occurred"
    });
  }
});

/**
 * GET /client/:clientId
 * Fetches client theme preset
 * NEVER returns 404 - always returns a valid theme response
 * NEVER creates or modifies client - read-only operation
 * 
 * URL params:
 *   - clientId: Client identifier (required)
 * 
 * Usage in Discord Bot:
 *   - Bot fetches client theme when creating menu
 *   - Always receives a valid preset (default if missing)
 *   - Menu creation never fails due to missing theme
 * 
 * Flow:
 * 1. Extracts clientId from URL parameter
 * 2. Looks up client in MongoDB by clientId (read-only)
 * 3. If client exists and has theme.preset:
 *    - Returns client's theme preset
 * 4. If client exists but only has theme.color (legacy):
 *    - Ignores color, returns default preset
 * 5. If client doesn't exist or has no theme:
 *    - Returns default theme preset "dark_green"
 * 6. Always returns 200 status with valid response
 * 
 * CRITICAL RULES:
 * - NEVER creates or modifies client document
 * - Read-only operation
 * - Always returns valid response (never 404)
 * - Prefers theme.preset over theme.color (backward compatibility)
 * 
 * Response format (ALWAYS 200):
 * {
 *   ok: true,
 *   clientId: string,
 *   theme: {
 *     preset: "dark_green" | client's preset
 *   }
 * }
 */
app.get("/client/:clientId", async (req, res) => {
  try {
    // CRITICAL: clientId MUST come from Electron/Discord request (URL parameter)
    // NEVER use process.env.CLIENT_ID or bot config
    const clientIdSource = "url_param";
    
    // Extract clientId from URL parameter
    const rawClientId = req.params.clientId;
    
    // Log clientId source immediately
    console.log(`[THEME_FETCH] clientId received from ${clientIdSource}: ${rawClientId || "(missing)"}`);
    
    // Validate clientId is present
    if (!rawClientId || (typeof rawClientId === "string" && rawClientId.trim().length === 0)) {
      // Even if invalid, return default theme (never 404)
      const defaultPreset = "dark_green";
      console.log(`[THEME_FETCH] Invalid clientId provided (source: ${clientIdSource}), using default theme: ${defaultPreset}`);
      return res.status(200).json({
        ok: true,
        clientId: rawClientId || "",
        theme: {
          preset: defaultPreset
        }
      });
    }

    const clientId = String(rawClientId).trim();
    const defaultPreset = "dark_green"; // Default theme preset
    
    console.log(`[THEME_FETCH] Normalized clientId: ${clientId} (source: ${clientIdSource})`);

    // Log theme fetch attempt
    console.log(`[THEME_FETCH] Fetching theme: clientId=${clientId} (source: ${clientIdSource})`);

    // Look up client in MongoDB (read-only - never create or modify)
    // NEVER use process.env.CLIENT_ID or bot config
    let client;
    let usedDefault = false;
    let readOccurred = false;
    
    try {
      client = await Client.findOne({ clientId: clientId });
      readOccurred = true;
      
      if (!client) {
        // Client doesn't exist - use default
        usedDefault = true;
        console.log(`[THEME_FETCH] Client not found: clientId=${clientId} (source: ${clientIdSource}), using default theme: ${defaultPreset} (read occurred, client not found)`);
      } else if (!client.theme || !client.theme.preset) {
        // Client exists but has no preset
        // Check if old theme.color exists (backward compatibility - ignore it)
        if (client.theme && client.theme.color) {
          console.log(`[THEME_FETCH] Client found with legacy theme.color (ignored): clientId=${clientId} (source: ${clientIdSource}), shop=${client.shop || "N/A"}, legacyColor=${client.theme.color}, using default preset: ${defaultPreset} (read occurred, preset missing, legacy color ignored)`);
        } else {
          console.log(`[THEME_FETCH] Client found but no theme preset set: clientId=${clientId} (source: ${clientIdSource}), shop=${client.shop || "N/A"}, using default theme: ${defaultPreset} (read occurred, theme missing)`);
        }
        usedDefault = true;
      } else {
        // Client exists and has theme preset
        const clientPreset = client.theme.preset;
        console.log(`[THEME_FETCH] Client theme preset found: clientId=${clientId} (source: ${clientIdSource}), shop=${client.shop || "N/A"}, preset=${clientPreset} (read occurred, preset returned)`);
        
        // Return client's theme preset
        return res.status(200).json({
          ok: true,
          clientId: clientId,
          theme: {
            preset: clientPreset
          }
        });
      }
    } catch (dbError) {
      // Database error - use default (never 404)
      console.error(`❌ [THEME_FETCH] Database error fetching client theme (clientId=${clientId}, source: ${clientIdSource}):`, dbError);
      usedDefault = true;
      readOccurred = false; // Read failed
    }

    // Return default theme (client not found or no theme set)
    console.log(`[THEME_FETCH] Returning default theme: clientId=${clientId} (source: ${clientIdSource}), preset=${defaultPreset} (read occurred: ${readOccurred}, used default: ${usedDefault})`);
    return res.status(200).json({
      ok: true,
      clientId: clientId,
      theme: {
        preset: defaultPreset
      }
    });

  } catch (error) {
    // FINAL CRASH-PROOF LAYER: Catch any unhandled errors
    // Even on error, return default theme (never 404)
    console.error("❌ [THEME_FETCH] Unhandled error in GET /client/:clientId:", error);
    const defaultPreset = "dark_green";
    return res.status(200).json({
      ok: true,
      clientId: req.params.clientId || "",
      theme: {
        preset: defaultPreset
      }
    });
  }
});

/* ================= START ================= */

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log("🚀 LICENSE SERVER RUNNING ON PORT", PORT);
});
