// الملف: /api/check-subscription.js (النسخة النهائية الكاملة)

const allowCors = (req, res) => {
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
};

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

module.exports = async (request, response) => {
    console.log("\n--- [check-subscription] Received a new request ---");
    allowCors(request, response);

    // ✅ ترويسات منع التخزين المؤقت
    response.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    response.setHeader('Pragma', 'no-cache');
    response.setHeader('Expires', '0');

    if (request.method === 'OPTIONS') {
        return response.status(200).end();
    }
    if (request.method !== 'POST') {
        return response.status(405).json({ success: false, error: 'Only POST is allowed' });
    }

    const BIN_ID = '6918dafcd0ea881f40eaa45b';
    const ACCESS_KEY = '$2a$10$rXrBfSrwkJ60zqKQInt5.eVxCq14dTw9vQX8LXcpnWb7SJ5ZLNoKe';
    const JWT_SECRET = process.env.JWT_SECRET;

    if (!JWT_SECRET) {
        console.error("[check-subscription] FATAL ERROR: JWT_SECRET is not set.");
        return response.status(500).json({ success: false, error: 'Server configuration error.' });
    }

    try {
        const { rin } = request.body;
        console.log(`[check-subscription] RIN received: ${rin}`);
        if (!rin) {
            console.log("[check-subscription] Error: RIN is missing.");
            return response.status(400).json({ success: false, error: 'RIN is required' });
        }

        const binResponse = await fetch(`https://api.jsonbin.io/v3/b/${BIN_ID}/latest`, {
            headers: { 'X-Access-Key': ACCESS_KEY }
        } );
        console.log(`[check-subscription] Fetched from jsonbin, status: ${binResponse.status}`);

        if (!binResponse.ok) {
            console.log("[check-subscription] Error: Failed to fetch from jsonbin.");
            return response.status(500).json({ success: false, error: 'Failed to fetch subscription data.' });
        }

        const data = await binResponse.json();
        const userSubscription = (data.record?.subscriptions || []).find(sub => sub.rin === rin);

        if (!userSubscription || new Date(userSubscription.expiry_date) < new Date()) {
            const reason = !userSubscription ? 'User not found in bin.' : 'Subscription expired.';
            console.log(`[check-subscription] Access Denied for RIN ${rin}. Reason: ${reason}`);
            return response.status(403).json({ success: false, error: `Access denied. ${reason}` });
        }

        console.log(`[check-subscription] User ${rin} is valid. Creating token.`);
        const now = Math.floor(Date.now() / 1000);
        const payload = {
            rin: userSubscription.rin,
            iat: now,
            exp: now + (24 * 60 * 60) // صلاحية 24 ساعة
        };

        const sessionToken = await createToken(payload, JWT_SECRET);

        console.log("[check-subscription] Token created successfully. Sending to client.");
        return response.status(200).json({
            success: true,
            session_token: sessionToken
        });

    } catch (error) {
        console.error("[check-subscription] CATCH BLOCK ERROR:", error);
        return response.status(500).json({ success: false, error: error.message });
    }
};