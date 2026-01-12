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
 * Initiates Shopify OAuth flow
 * Query params:
 *   - clientId: Client identifier (e.g., Discord user ID)
 *   - shop: Shop domain (e.g., "myshop.myshopify.com")
 * 
 * Flow:
 * 1. Validates required params
 * 2. Generates state token (clientId encoded for security)
 * 3. Redirects user to Shopify OAuth authorization URL
 */
app.get("/shopify/auth", (req, res) => {
  const { clientId, shop } = req.query;

  // Validate required parameters
  if (!clientId || !shop) {
    return res.status(400).json({
      ok: false,
      reason: "BAD_REQUEST",
      message: "clientId and shop query parameters are required"
    });
  }

  // Validate shop domain format
  if (!shop.includes(".myshopify.com")) {
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
    console.error("❌ SHOPIFY_API_KEY not set in environment");
    return res.status(500).json({
      ok: false,
      reason: "SERVER_ERROR",
      message: "Shopify API key not configured"
    });
  }

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
 * GET /shopify/callback
 * Handles Shopify OAuth callback after user approval
 * Query params (from Shopify):
 *   - code: Authorization code to exchange for access token
 *   - state: State token containing clientId (from /shopify/auth)
 *   - shop: Shop domain
 *   - hmac: HMAC for request verification (optional but recommended)
 * 
 * Flow:
 * 1. Validates state and extracts clientId
 * 2. Exchanges authorization code for access token via Shopify API
 * 3. Stores access token, shop domain, and scopes in MongoDB
 * 4. Redirects user to success page or returns JSON
 */
app.get("/shopify/callback", async (req, res) => {
  const { code, state, shop } = req.query;

  // Validate required parameters
  if (!code || !state || !shop) {
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
    console.error("❌ SHOPIFY_API_KEY or SHOPIFY_API_SECRET not set in environment");
    return res.status(500).json({
      ok: false,
      reason: "SERVER_ERROR",
      message: "Shopify API credentials not configured"
    });
  }

  // Decode state to get clientId
  let clientId;
  try {
    const stateData = JSON.parse(Buffer.from(state, "base64").toString());
    clientId = stateData.clientId;
    if (!clientId) {
      throw new Error("clientId missing in state");
    }
  } catch (err) {
    console.error("❌ Invalid state token:", err);
    return res.status(400).json({
      ok: false,
      reason: "INVALID_STATE",
      message: "Invalid or corrupted state parameter"
    });
  }

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
            console.error("❌ Shopify token exchange failed:", data);
            const errorResponse = {
              ok: false,
              reason: "TOKEN_EXCHANGE_FAILED",
              message: "Failed to exchange authorization code for access token"
            };
            res.status(500).json(errorResponse);
            return resolve();
          }

          try {
            const tokenData = JSON.parse(data);
            const { access_token, scope } = tokenData;

            if (!access_token) {
              throw new Error("Access token missing in Shopify response");
            }

            // Store or update Shopify store credentials in MongoDB
            try {
              await ShopifyStore.findOneAndUpdate(
                { clientId },
                {
                  clientId,
                  shop,
                  accessToken: access_token,
                  scopes: scope || process.env.SHOPIFY_SCOPES || "",
                  connectedAt: new Date(),
                  lastUsedAt: new Date()
                },
                { upsert: true, new: true }
              );

              console.log(`✅ Shopify store connected for client: ${clientId}, shop: ${shop}`);

              // Return success response (bot can handle redirect or JSON)
              res.json({
                ok: true,
                message: "Shopify store connected successfully",
                shop,
                clientId
              });
            } catch (dbError) {
              console.error("❌ Database error saving Shopify store:", dbError);
              res.status(500).json({
                ok: false,
                reason: "DB_ERROR",
                message: "Failed to save Shopify store credentials"
              });
            }
          } catch (parseError) {
            console.error("❌ Failed to parse Shopify token response:", parseError);
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
      console.error("❌ Request error during token exchange:", err);
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
 * 2. Loads Shopify store credentials from MongoDB using clientId
 * 3. Makes authenticated request to Shopify Admin API to fetch recent orders
 * 4. Filters orders by email (case-insensitive) and financial_status = "paid"
 * 5. Returns whether a paid order exists and the order ID if found
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

  // Load Shopify store credentials from MongoDB
  let store;
  try {
    store = await ShopifyStore.findOne({ clientId });
    if (!store) {
      return res.status(404).json({
        ok: false,
        reason: "STORE_NOT_FOUND",
        message: "No Shopify store connected for this client"
      });
    }
  } catch (dbError) {
    console.error("❌ Database error loading Shopify store:", dbError);
    return res.status(500).json({
      ok: false,
      reason: "DB_ERROR",
      message: "Failed to load Shopify store credentials"
    });
  }

  // Update lastUsedAt timestamp
  try {
    store.lastUsedAt = new Date();
    await store.save();
  } catch (updateError) {
    // Non-fatal: continue even if timestamp update fails
    console.warn("⚠️  Failed to update lastUsedAt:", updateError);
  }

  // Prepare Shopify API request
  // Use Shopify Admin REST API to fetch orders
  // API version can be configured via env var, default to stable version
  const apiVersion = process.env.SHOPIFY_API_VERSION || "2024-01";
  const apiPath = `/admin/api/${apiVersion}/orders.json?status=any&limit=250`;

  return new Promise((resolve) => {
    const apiRequest = https.request(
      {
        hostname: store.shop,
        path: apiPath,
        method: "GET",
        headers: {
          "X-Shopify-Access-Token": store.accessToken,
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
 * 2. Loads Shopify store credentials from MongoDB
 * 3. Fetches specific order by orderId from Shopify API
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

    // DEFENSIVE LAYER 3: Extract and normalize clientId (TEMP FIX FOR TESTING)
    const originalClientId = body.clientId;
    const clientId = (body.clientId && String(body.clientId).trim()) ? String(body.clientId).trim() : "main";
    
    // TEMP DEBUG: Log clientId resolution
    console.log("[DEBUG] Original clientId:", originalClientId || "(missing)");
    console.log("[DEBUG] Resolved clientId:", clientId);

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

    // Load Shopify store credentials from MongoDB
    let store;
    try {
      store = await ShopifyStore.findOne({ clientId });
      if (!store) {
        return res.status(404).json({
          ok: false,
          reason: "STORE_NOT_FOUND"
        });
      }
      
      // TEMP DEBUG: Log shop domain used
      console.log("[DEBUG] Shop domain used:", store.shop);
    } catch (dbError) {
      console.error("❌ Database error loading Shopify store:", dbError);
      return res.status(500).json({
        ok: false,
        reason: "INTERNAL_ERROR"
      });
    }

    // Helper function to fetch order from Shopify API
    const fetchOrderFromShopify = (identifier, isOrderNumber = false) => {
      return new Promise((resolve, reject) => {
        const apiVersion = process.env.SHOPIFY_API_VERSION || "2024-01";
        // If searching by order_number, use query parameter; otherwise use path parameter
        const apiPath = isOrderNumber
          ? `/admin/api/${apiVersion}/orders.json?name=${encodeURIComponent(identifier)}`
          : `/admin/api/${apiVersion}/orders/${identifier}.json`;

        const apiRequest = https.request(
          {
            hostname: store.shop,
            path: apiPath,
            method: "GET",
            headers: {
              "X-Shopify-Access-Token": store.accessToken,
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
                  // When searching by order_number, response is { orders: [...] }
                  // When searching by ID, response is { order: {...} }
                  const order = isOrderNumber
                    ? (responseData.orders && responseData.orders.length > 0 ? responseData.orders[0] : null)
                    : responseData.order;
                  resolve(order);
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

    // Try to fetch order: first by ID, then by order_number if not found
    let order = null;
    try {
      // First attempt: try as numeric ID
      order = await fetchOrderFromShopify(normalizedOrderId, false);
      
      // If not found, try by order_number
      if (!order) {
        order = await fetchOrderFromShopify(normalizedOrderId, true);
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

    // Extract the real Shopify order ID from the order object
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
