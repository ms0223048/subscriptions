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
//  Token Verification
// ----------------------------
async function verifyToken(token, secret) {
    const [encodedHeader, encodedPayload, signature] = token.split('.');
    if (!encodedHeader || !encodedPayload || !signature) throw new Error('Invalid token format');

    const data = `${encodedHeader}.${encodedPayload}`;
    const crypto = require('crypto');
    const expectedSignature = crypto.createHmac('sha256', secret).update(data).digest('base64url');

    if (signature !== expectedSignature) throw new Error('Invalid signature');

    const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString());
    if (payload.exp < Math.floor(Date.now() / 1000)) throw new Error('Token expired');

    return payload;
}

// ----------------------------
//   GitHub Fetch + Caching
// ----------------------------
let SUBS_CACHE = null;
let SUBS_CACHE_TIME = 0;
const CACHE_TTL = 60000;

async function fetchSubscriptionsFromGithub(rawUrl) {
    console.log("Fetching subscriptions from GitHub...");
    const now = Date.now();
    if (SUBS_CACHE && (now - SUBS_CACHE_TIME) < CACHE_TTL) return SUBS_CACHE;

    const headers = { "Authorization": `token ${process.env.GITHUB_TOKEN}` };
    const res = await fetch(rawUrl, { headers });
    if (!res.ok) throw new Error(`GitHub fetch failed: ${res.status}`);

    const json = await res.json();
    SUBS_CACHE = json;
    SUBS_CACHE_TIME = now;

    console.log("Subscriptions fetched:", json.subscriptions.map(s => s.rin));
    return json;
}

// ----------------------------
//       MAIN HANDLER
// ----------------------------
module.exports = async (request, response) => {
    console.log("\n--- [validate-token] Received a new request ---");
    allowCors(request, response);

    response.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    response.setHeader('Pragma', 'no-cache');
    response.setHeader('Expires', '0');

    if (request.method === 'OPTIONS') return response.status(200).end();
    if (request.method !== 'POST') return response.status(405).json({ success: false, error: 'Only POST is allowed' });

    const JWT_SECRET = process.env.JWT_SECRET;
    if (!JWT_SECRET) return response.status(500).json({ success: false, error: 'Server configuration error.' });

    try {
        const authHeader = request.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) return response.status(401).json({ success: false, error: 'Authorization header missing.' });

        const token = authHeader.split(' ')[1];
        const payload = await verifyToken(token, JWT_SECRET);
        const rin = payload.rin;
        console.log("[validate-token] Token valid for RIN:", rin);

        const RAW_URL = "https://raw.githubusercontent.com/ms0223048/eta-subscriptions/main/subscriptions.json";
        const data = await fetchSubscriptionsFromGithub(RAW_URL);

        const userSubscription = (data.subscriptions || []).find(sub => String(sub.rin).trim() === String(rin).trim());

        if (!userSubscription) return response.status(401).json({ success: false, error: 'Subscription is no longer valid.' });
        if (new Date(userSubscription.expiry_date) < new Date()) return response.status(401).json({ success: false, error: 'Subscription has expired.' });

        console.log("[validate-token] Subscription valid. Returning data.");
        return response.status(200).json({ success: true, data: userSubscription });

    } catch (error) {
        console.error("[validate-token] ERROR:", error.message);
        return response.status(401).json({ success: false, error: error.message });
    }
};
