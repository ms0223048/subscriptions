const fs = require('fs');
const path = require('path');

const allowCors = (req, res) => {
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
};

async function createToken(payload, secret) {
    const crypto = require('crypto');
    const header = { alg: 'HS256', typ: 'JWT' };
    const encode = obj => Buffer.from(JSON.stringify(obj)).toString('base64url');
    const data = `${encode(header)}.${encode(payload)}`;
    const signature = crypto.createHmac('sha256', secret).update(data).digest('base64url');
    return `${data}.${signature}`;
}

module.exports = async (req, res) => {
    allowCors(req, res);
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ success: false, error: 'Only POST allowed' });

    const JWT_SECRET = process.env.JWT_SECRET;
    if (!JWT_SECRET) return res.status(500).json({ success: false, error: 'JWT_SECRET missing' });

    try {
        const { rin } = req.body;
        if (!rin) return res.status(400).json({ success: false, error: 'RIN is required' });

        // ---- اقرأ الملف المحلي مباشرة ----
        const subscriptionsPath = path.join(__dirname, 'subscriptions.json');
        const raw = fs.readFileSync(subscriptionsPath);
        const data = JSON.parse(raw);

        const sub = (data.subscriptions || []).find(s => s.rin === rin);

        if (!sub) return res.status(403).json({ success: false, error: 'Access denied: User not found' });
        if (new Date(sub.expiry_date) < new Date()) return res.status(403).json({ success: false, error: 'Subscription expired' });

        // ---- إنشاء توكن JWT ----
        const now = Math.floor(Date.now()/1000);
        const payload = { rin, iat: now, exp: now + 24*60*60 }; // صالح 24 ساعة
        const token = await createToken(payload, JWT_SECRET);

        return res.status(200).json({ success: true, session_token: token });

    } catch (e) {
        console.error(e);
        return res.status(500).json({ success: false, error: e.message });
    }
};
