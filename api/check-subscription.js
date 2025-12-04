const fetch = global.fetch || require('node-fetch');

// ----------------------------
//   CORS Settings
// ----------------------------
const allowCors = (req, res) => {
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
};

// ----------------------------
//   JWT Helpers
// ----------------------------
function base64url(source) {
    let base64 = Buffer.from(source).toString('base64');
    return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

async function createToken(payload, secret) {
    const header = { alg: 'HS256', typ: 'JWT' };
    const encodedHeader = base64url(JSON.stringify(header));
    const encodedPayload = base64url(JSON.stringify(payload));
    const data = `${encodedHeader}.${encodedPayload}`;
    const crypto = require('crypto');
    const signature = crypto.createHmac('sha256', secret).update(data).digest('base64url');
    return `${data}.${signature}`;
}

// ----------------------------
//   Fetch subscriptions from GitHub
// ----------------------------
async function fetchSubscriptionsFromGithub() {
    const RAW_URL = "https://raw.githubusercontent.com/ms0223048/subscriptions2/refs/heads/main/subscriptions.json";
    const res = await fetch(RAW_URL);
    if (!res.ok) throw new Error(`GitHub fetch failed: ${res.status}`);
    return await res.json();
}

// ----------------------------
//   MAIN HANDLER
// ----------------------------
module.exports = async (request, response) => {
    allowCors(request, response);
    response.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    response.setHeader('Pragma', 'no-cache');
    response.setHeader('Expires', '0');

    if (request.method === 'OPTIONS') return response.status(200).end();
    if (request.method !== 'POST') return response.status(405).json({ success: false, error: 'Only POST is allowed' });

    const JWT_SECRET = process.env.JWT_SECRET;
    if (!JWT_SECRET) return response.status(500).json({ success: false, error: 'Server error: JWT missing.' });

    try {
        const { rin } = request.body;
        console.log("[check-subscription] Received RIN:", rin);
        if (!rin) return response.status(400).json({ success: false, error: 'RIN is required' });

        const data = await fetchSubscriptionsFromGithub();
        const userSubscription = (data.subscriptions || []).find(sub => sub.rin === rin);

        if (!userSubscription) {
            console.log("[check-subscription] User not found in subscriptions.json");
            return response.status(403).json({ success: false, error: 'Access denied: User not found' });
        }

        if (new Date(userSubscription.expiry_date) < new Date()) {
            console.log("[check-subscription] Subscription expired for RIN:", rin);
            return response.status(403).json({ success: false, error: 'Access denied: Subscription expired' });
        }

        console.log("[check-subscription] Subscription valid → creating token");

        const now = Math.floor(Date.now() / 1000);
        const payload = { rin: userSubscription.rin, iat: now, exp: now + (24 * 60 * 60) };
        const sessionToken = await createToken(payload, JWT_SECRET);

        return response.status(200).json({ success: true, session_token: sessionToken });

    } catch (error) {
        console.error("[check-subscription] ERROR:", error.message);
        return response.status(500).json({ success: false, error: error.message });
    }
};
