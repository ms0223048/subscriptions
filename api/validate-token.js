// FILE: /api/validate-token.js
const crypto = require('crypto');
const fetch = global.fetch || require('node-fetch');

// ----------------------------
//   CORS
// ----------------------------
const allowCors = (req, res) => {
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
};

// ----------------------------
//   Verify Token
// ----------------------------
function verifyToken(token, secret) {
    const [header, payload, signature] = token.split('.');

    if (!header || !payload || !signature) throw new Error("Invalid token format");

    const checkSig = crypto
        .createHmac("sha256", secret)
        .update(`${header}.${payload}`)
        .digest("base64url");

    if (checkSig !== signature) throw new Error("Invalid signature");

    const data = JSON.parse(Buffer.from(payload, "base64url").toString());

    if (data.exp < Math.floor(Date.now() / 1000))
        throw new Error("Token expired");

    return data;
}

// ----------------------------
//   Handler
// ----------------------------
module.exports = async (req, res) => {
    console.log("\n--- [validate-token] New request received ---");

    allowCors(req, res);

    if (req.method === "OPTIONS") return res.status(200).end();
    if (req.method !== "POST")
        return res.status(405).json({ success: false, error: "Only POST is allowed" });

    // check token
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith("Bearer "))
        return res.status(401).json({ success: false, error: "Missing Authorization header" });

    const token = auth.split(" ")[1];

    const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
    const JWT_SECRET   = process.env.JWT_SECRET;

    try {
        console.log("[validate-token] Verifying token…");

        const payload = verifyToken(token, JWT_SECRET);

        console.log("[validate-token] Token valid for RIN:", payload.rin);

        console.log("[validate-token] Fetching subscriptions.json from GitHub…");

        const githubRes = await fetch(
            "https://raw.githubusercontent.com/ms0223048/eta-subscriptions/main/subscriptions.json",
            { headers: { Authorization: `token ${GITHUB_TOKEN}` } }
        );

        const data = await githubRes.json();

        const sub = data.subscriptions.find(s => String(s.rin) === String(payload.rin));

        if (!sub) {
            console.log("[validate-token] ERROR: RIN not found");
            return res.status(401).json({ success: false, error: "Subscription not found" });
        }

        console.log("[validate-token] Subscription valid.");

        return res.status(200).json({
            success: true,
            data: sub
        });

    } catch (err) {
        console.log("[validate-token] ERROR:", err.message);
        return res.status(401).json({ success: false, error: err.message });
    }
};
