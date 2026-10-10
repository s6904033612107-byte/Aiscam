/**
 * POST /api/url-reputation — ตรวจลิงก์/ไฟล์กับบริการภายนอก (ใส่ key เฉพาะที่ต้องการ)
 *   GOOGLE_SAFE_BROWSING_KEY  → Google Safe Browsing v4 (threatMatches:find)
 *   VIRUSTOTAL_API_KEY        → VirusTotal v3 (ค้นจาก URL id / SHA-256 ที่มีอยู่แล้ว ไม่อัปโหลดไฟล์)
 *
 * Request : { urls: string[], hashes: string[] }
 * Response: { configured:{gsb,vt}, results:[{target, gsb:boolean, vt:{malicious,suspicious,harmless}|null}] }
 * หมายเหตุ: ส่งเฉพาะ URL (ตัด query ออกแล้ว) และ hash ไม่ส่งเนื้อหาไฟล์หรือข้อความ
 */
const { rateLimit, readBody, send } = require('./_utils');

const GSB_KEY = () => process.env.GOOGLE_SAFE_BROWSING_KEY;
const VT_KEY = () => process.env.VIRUSTOTAL_API_KEY;
const stripQuery = (u) => String(u).split(/[?#]/)[0];
const withScheme = (u) => (/^https?:\/\//i.test(u) ? u : 'http://' + u);

async function safeBrowsing(urls) {
  const body = {
    client: { clientId: 'scam-checker-student-project', clientVersion: '1.0' },
    threatInfo: {
      threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: urls.map((url) => ({ url }))
    }
  };
  const r = await fetch('https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' + encodeURIComponent(GSB_KEY()), {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body)
  });
  if (!r.ok) throw new Error('gsb ' + r.status);
  const data = await r.json();
  return new Set((data.matches || []).map((m) => m.threat && m.threat.url));
}

async function virusTotal(kind, id) {
  const r = await fetch(`https://www.virustotal.com/api/v3/${kind}/${id}`, { headers: { 'x-apikey': VT_KEY() } });
  if (r.status === 404) return null; // VirusTotal ไม่เคยเห็นรายการนี้
  if (!r.ok) throw new Error('vt ' + r.status);
  const stats = (await r.json()).data?.attributes?.last_analysis_stats;
  return stats ? { malicious: stats.malicious || 0, suspicious: stats.suspicious || 0, harmless: stats.harmless || 0 } : null;
}

const vtUrlId = (url) => Buffer.from(url).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return send(res, 405, { error: 'method_not_allowed' });
  if (!rateLimit(req, 15)) return send(res, 429, { error: 'rate_limited' });
  const body = readBody(req);
  if (!body) return send(res, 400, { error: 'invalid_body' });

  const urls = (Array.isArray(body.urls) ? body.urls : []).filter((u) => typeof u === 'string').slice(0, 10).map((u) => withScheme(stripQuery(u)));
  const hashes = (Array.isArray(body.hashes) ? body.hashes : []).filter((h) => /^[a-f0-9]{64}$/i.test(h)).slice(0, 5);
  const configured = { gsb: !!GSB_KEY(), vt: !!VT_KEY() };
  if (!configured.gsb && !configured.vt) return send(res, 200, { configured, results: [] });

  const results = urls.map((u) => ({ target: u, gsb: false, vt: null }));
  try {
    if (configured.gsb && urls.length) {
      const bad = await safeBrowsing(urls);
      results.forEach((r) => { r.gsb = bad.has(r.target); });
    }
    if (configured.vt) {
      for (const r of results) r.vt = await virusTotal('urls', vtUrlId(r.target)).catch(() => null);
      for (const h of hashes) results.push({ target: 'sha256:' + h.slice(0, 12), gsb: false, vt: await virusTotal('files', h).catch(() => null) });
    }
  } catch (e) {
    return send(res, 502, { error: 'upstream_error' });
  }
  return send(res, 200, { configured, results });
};
