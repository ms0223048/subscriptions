const fs = require('fs');
const path = require('path');

const allowCors = (req, res) => {
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
};

// ----------------------------
// Token Verification
// ----------------------------
async function verifyToken(token, secret) {
    const [headerB64, payloadB64, signature] = token.split('.');
    if (!headerB64 || !payloadB64 || !signature) throw new Error('Invalid token format');

    const crypto = require('crypto');
    const data = `${headerB64}.${payloadB64}`;
    const expectedSig = crypto.createHmac('sha256', secret).update(data).digest('base64url');

    if (signature !== expectedSig) throw new Error('Invalid signature');

    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
    if (payload.exp < Math.floor(Date.now() / 1000)) throw new Error('Token expired');

    return payload;
}

// ----------------------------
// Main Handler
// ----------------------------
module.exports = async (req, res) => {
    allowCors(req, res);
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ success: false, error: 'Only POST allowed' });

    const JWT_SECRET = process.env.JWT_SECRET;
    if (!JWT_SECRET) return res.status(500).json({ success: false, error: 'JWT_SECRET missing' });

    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ success: false, error: 'Authorization header missing.' });
        }

        const token = authHeader.split(' ')[1];
        const payload = await verifyToken(token, JWT_SECRET);
        const rin = payload.rin;

        // ---- اقرأ JSON محلي مباشر ----
        const subscriptionsPath = path.join(__dirname, 'subscriptions.json');
        const raw = fs.readFileSync(subscriptionsPath);
        const data = JSON.parse(raw);

        const sub = (data.subscriptions || []).find(s => s.rin === rin);

        // ---- رفض فوري لو الرقم غير موجود أو الاشتراك انتهى ----
        if (!sub) return res.status(401).json({ success: false, error: 'Subscription is no longer valid.' });
        if (new Date(sub.expiry_date) < new Date()) return res.status(401).json({ success: false, error: 'Subscription expired.' });

        // ---- لو كل شيء تمام ----
        return res.status(200).json({
            success: true,
            data: sub
        });

    } catch (err) {
        console.error('[validate-token] ERROR:', err.message);
        return res.status(401).json({ success: false, error: err.message });
    }
};
