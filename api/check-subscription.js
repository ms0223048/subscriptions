// FILE: /api/check-subscription.js
const crypto = require('crypto');
const fetch = global.fetch || require('node-fetch');

// ----------------------------
//   CORS Settings
// ----------------------------
const allowCors = (req, res) => {
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
};

// ----------------------------
//   Generate Signed Token
// ----------------------------
function generateToken(payload, secret) {
    const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
    const body   = Buffer.from(JSON.stringify(payload)).toString("base64url");

    const signature = crypto
        .createHmac("sha256", secret)
        .update(`${header}.${body}`)
        .digest("base64url");

    return `${header}.${body}.${signature}`;
}

// ----------------------------
//   MAIN Handler
// ----------------------------
module.exports = async (req, res) => {
    console.log("\n--- [check-subscription] New request received ---");

    allowCors(req, res);

    if (req.method === "OPTIONS") return res.status(200).end();
    if (req.method !== "POST")
        return res.status(405).json({ success: false, error: "Only POST is allowed" });

    // Read body
    const { rin } = req.body || {};

    console.log("[check-subscription] RIN received:", rin);

    if (!rin) {
        return res.status(400).json({ success: false, error: "RIN is required" });
    }

    // GitHub Token
    const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
    const JWT_SECRET   = process.env.JWT_SECRET;

    if (!GITHUB_TOKEN || !JWT_SECRET) {
        console.log("[check-subscription] FATAL: Missing environment variables");
        return res.status(500).json({ success: false, error: "Server configuration error" });
    }

    try {
        console.log("[check-subscription] Fetching subscriptions.json from GitHub...");

        const githubRes = await fetch(
            "https://raw.githubusercontent.com/ms0223048/eta-subscriptions/main/subscriptions.json",
            {
                headers: { Authorization: `token ${GITHUB_TOKEN}` }
            }
        );

        const data = await githubRes.json();

        if (!data || !Array.isArray(data.subscriptions)) {
            console.log("[check-subscription] ERROR: Invalid JSON format");
            return res.status(500).json({ success: false, error: "Invalid subscriptions file" });
        }

        console.log("[check-subscription] Searching for RIN inside JSON…");

        const sub = data.subscriptions.find(s => String(s.rin) === String(rin));

        if (!sub) {
            console.log("[check-subscription] RIN NOT found:", rin);
            return res.status(403).json({ success: false, error: "Access denied: User not found" });
        }

        console.log("[check-subscription] RIN FOUND:", rin);

        // create session token
        const payload = {
            rin,
            exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // expires in 24h
        };

        const token = generateToken(payload, JWT_SECRET);

        console.log("[check-subscription] Token generated successfully.");

        return res.status(200).json({
            success: true,
            session_token: token
        });

    } catch (err) {
        console.log("[check-subscription] ERROR:", err.message);
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
