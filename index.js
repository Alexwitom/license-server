const express = require("express");
const mongoose = require("mongoose");
const crypto = require("crypto");
const https = require("https");
const querystring = require("querystring");

const app = express();
app.use(express.json());

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

/* ================= START ================= */

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log("🚀 LICENSE SERVER RUNNING ON PORT", PORT);
});
