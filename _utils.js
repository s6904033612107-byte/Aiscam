// ฟังก์ชันช่วยร่วมของ serverless functions (ไฟล์ขึ้นต้นด้วย _ จะไม่ถูกเปิดเป็น endpoint บน Vercel)

const hits = new Map();

/** จำกัดจำนวนครั้งต่อ IP ต่อนาที (ในหน่วยความจำของ instance เดียว เหมาะกับงานเรียน ถ้าใช้จริงควรใช้ Upstash/Vercel Firewall) */
function rateLimit(req, limit = 20, windowMs = 60000) {
  const ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0].trim();
  const now = Date.now();
  const rec = (hits.get(ip) || []).filter((t) => now - t < windowMs);
  rec.push(now);
  hits.set(ip, rec);
  if (hits.size > 5000) hits.clear();
  return rec.length <= limit;
}

function readBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  try {
    return JSON.parse(req.body || '{}');
  } catch (e) {
    return null;
  }
}

function send(res, status, obj) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(obj));
}

module.exports = { rateLimit, readBody, send };
