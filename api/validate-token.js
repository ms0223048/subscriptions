// الملف: /api/validate-token.js (النسخة النهائية الكاملة)

const allowCors = (req, res) => {
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
};

async function verifyToken(token, secret) {
    const [encodedHeader, encodedPayload, signature] = token.split('.');
    if (!encodedHeader || !encodedPayload || !signature) {
        throw new Error('Invalid token format');
    }
    const data = `${encodedHeader}.${encodedPayload}`;
    const crypto = require('crypto');
    const expectedSignature = crypto.createHmac('sha256', secret).update(data).digest('base64url');

    if (signature !== expectedSignature) {
        throw new Error('Invalid signature');
    }

    const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString());
    if (payload.exp < Math.floor(Date.now() / 1000)) {
        throw new Error('Token expired');
    }
    return payload;
}

module.exports = async (request, response) => {
    console.log("\n--- [validate-token] Received a new request ---");
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
        console.error("[validate-token] FATAL ERROR: JWT_SECRET is not set.");
        return response.status(500).json({ success: false, error: 'Server configuration error.' });
    }

    try {
        const authHeader = request.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            console.log("[validate-token] Error: Authorization header missing.");
            return response.status(401).json({ success: false, error: 'Authorization header missing.' });
        }
        const token = authHeader.split(' ')[1];

        const payload = await verifyToken(token, JWT_SECRET);
        const rin = payload.rin;
        console.log(`[validate-token] Token is technically valid for RIN: ${rin}`);

        const binResponse = await fetch(`https://api.jsonbin.io/v3/b/${BIN_ID}/latest`, {
            headers: { 'X-Access-Key': ACCESS_KEY }
        } );
        console.log(`[validate-token] Fetched from jsonbin, status: ${binResponse.status}`);

        if (!binResponse.ok) {
            console.log("[validate-token] Error: Failed to fetch from jsonbin during validation.");
            return response.status(500).json({ success: false, error: 'Failed to fetch subscription data during validation.' });
        }

        const data = await binResponse.json();
        const userSubscription = (data.record?.subscriptions || []).find(sub => sub.rin === rin);

        if (!userSubscription || new Date(userSubscription.expiry_date) < new Date()) {
            console.log(`[validate-token] Access Denied: Subscription for ${rin} is no longer valid in bin.`);
            return response.status(401).json({ success: false, error: 'Subscription is no longer valid.' });
        }
        
        console.log(`[validate-token] Subscription for ${rin} is still valid. Granting access.`);
        return response.status(200).json({
            success: true,
            data: {
                seller: { name: "Authenticated User", id: payload.rin },
                devices: []
            }
        });

    } catch (error) {
        console.error("[validate-token] CATCH BLOCK ERROR:", error.message);
        return response.status(401).json({ success: false, error: error.message });
    }
};