/**
 * anonymize.js — ปิดบังข้อมูลส่วนบุคคล (PII) ก่อนส่งข้อความให้ AI ภายนอก
 * ทำงานในเบราว์เซอร์เท่านั้น ข้อความต้นฉบับไม่ถูกส่งออกไปไหน
 *
 * ครอบคลุม: ลิงก์ (ค่า query), อีเมล, เลขบัตรประชาชน, เลขบัตรเครดิต,
 *           เลขบัญชี (เมื่อมีคำนำหน้าเช่น "เลขบัญชี"), เบอร์โทร, LINE ID, ชื่อที่มีคำนำหน้า
 * ข้อจำกัด: การจับชื่อเป็น heuristic จึงมีทั้งพลาดและจับเกิน ให้ผู้ใช้ตรวจ "ตัวอย่างข้อความที่จะส่ง" ก่อนเสมอ
 */
(function (root) {
  'use strict';
  const isNode = typeof module !== 'undefined' && module.exports;

  const NAME_EXCLUDE = /^(ลูกค้า|ผู้|สมาชิก|หน้า|จ้าง|ทุน|ธนาคาร|เจ้า|ทุกท่าน|ท่าน|ภาพ|สมบัติ|ธรรม|วุฒิ|แบบ|ฟ้า|ทหาร|กรัฐมนตรี|กฯ)/;

  // ใช้ร่วมกับ tools.js เพื่อดึงเบอร์โทรจากข้อความ
  const PHONE_RE = /(?<!\d)(?:\+66[- ]?[1-9]\d?|0\d{1,2})[- ]?\d{3}[- ]?\d{3,4}(?!\d)/g;

  function anonymize(input) {
    const map = [];
    const seen = new Map();
    const counts = {};
    const put = (type, original) => {
      const key = type + '|' + original;
      if (seen.has(key)) return seen.get(key);
      counts[type] = (counts[type] || 0) + 1;
      const placeholder = '[' + type + '_' + counts[type] + ']';
      seen.set(key, placeholder);
      map.push({ placeholder, type, original });
      return placeholder;
    };

    let t = String(input == null ? '' : input);

    // 1) ค่าใน query string ของลิงก์ (อาจมี token / id / อีเมล)
    t = t.replace(/(https?:\/\/[^\s<>"'?#]+)\?([^\s<>"'#]*)/gi, (m, base, q) => {
      const masked = q.replace(/=([^&\s]*)/g, (mm, v) => (v ? '=[REDACTED]' : '='));
      return base + '?' + masked;
    });
    // 2) อีเมล
    t = t.replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, (m) => put('EMAIL', m));
    // 3) เลขบัตรประชาชน 13 หลัก
    t = t.replace(/(?<!\d)\d[- ]?\d{4}[- ]?\d{5}[- ]?\d{2}[- ]?\d(?!\d)/g, (m) => put('THAI_ID', m));
    // 4) เลขบัตรเครดิต 16 หลัก
    t = t.replace(/(?<!\d)(?:\d{4}[- ]?){3}\d{4}(?!\d)/g, (m) => put('CARD', m));
    // 5) เลขบัญชี (ต้องมีคำนำหน้า เพื่อไม่ให้ชนกับเบอร์โทร)
    t = t.replace(
      /((?:เลขที่บัญชี|เลขบัญชี|บัญชี|account|acc|a\/c|พร้อมเพย์|promptpay)[^\d\n]{0,15})((?:\d[- ]?){9,14}\d)/gi,
      (m, pre, num) => pre + put('ACCOUNT', num.replace(/\D/g, ''))
    );
    // 6) เบอร์โทร
    t = t.replace(PHONE_RE, (m) => put('PHONE', m));
    // 7) LINE ID
    t = t.replace(/((?:line\s?id|ไอดีไลน์|ไลน์ไอดี|ไลน์)\s?[:：]\s?)@?[A-Za-z0-9._-]{3,30}/gi, (m, pre) => pre + put('LINE_ID', m));
    // 8) ชื่อที่มีคำนำหน้า
    t = t.replace(/(คุณ|นางสาว|นาย|นาง|น\.ส\.)([ก-๙]{2,30})/g, (m, title, name) => (NAME_EXCLUDE.test(name) ? m : title + put('NAME', name)));
    t = t.replace(/\b(Mr|Mrs|Ms|Miss)\.?\s([A-Z][a-z]{1,30})/g, (m, title, name) => title + ' ' + put('NAME', name));

    const total = map.length;
    return { text: t, map, counts, total };
  }

  const api = { anonymize, PHONE_RE };
  if (isNode) module.exports = api;
  else (root.ScamChecker = root.ScamChecker || {}).Anonymize = api;
})(typeof window !== 'undefined' ? window : globalThis);
