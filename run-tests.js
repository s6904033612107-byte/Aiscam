/**
 * ทดสอบระบบกฎ + RAG + Anonymize แบบ offline (ไม่เรียก API)
 * รัน:  node tests/run-tests.js
 */
const fs = require('fs');
const path = require('path');
const { runAgent } = require('../js/agent.js');
const { KnowledgeBase } = require('../js/rag.js');
const { anonymize } = require('../js/anonymize.js');
const Tools = require('../js/tools.js');

const read = (f) => JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', f), 'utf8'));
const kb = new KnowledgeBase(read('knowledge-base.json').docs);
const blacklist = read('blacklist.json');
const rules = read('url-rules.json');
const samples = read('samples.json').samples;

let failed = 0;
const check = (name, ok, detail) => {
  if (!ok) failed++;
  console.log((ok ? 'PASS ' : 'FAIL ') + name + (detail ? '  ' + detail : ''));
};

(async () => {
  console.log('--- 1) คะแนนความเสี่ยงของข้อความตัวอย่าง ---');
  for (const s of samples) {
    const r = await runAgent({ text: s.text }, { kb, blacklist, rules, config: { offline: true } });
    const ok = r.risk_score >= s.expect.min && r.risk_score <= s.expect.max;
    check(s.id.padEnd(18), ok, `score=${String(r.risk_score).padStart(3)} expect ${s.expect.min}-${s.expect.max} level=${r.risk_level}`);
  }

  console.log('--- 2) Anonymize ---');
  const a = anonymize('คุณสมชาย โทร 081-234-5678 อีเมล a.b@mail.com บัญชี 123-4-56789-0 บัตร 1-2345-67890-12-3 เข้า http://x.top/p?token=abc123');
  check('เบอร์โทรถูกปิดบัง', !/081-234-5678/.test(a.text) && /\[PHONE_1\]/.test(a.text));
  check('อีเมลถูกปิดบัง', !/a\.b@mail\.com/.test(a.text));
  check('เลขบัญชีถูกปิดบัง', !/123-4-56789-0/.test(a.text) && /\[ACCOUNT_1\]/.test(a.text));
  check('เลขบัตรประชาชนถูกปิดบัง', !/1-2345-67890-12-3/.test(a.text));
  check('ค่า token ในลิงก์ถูกปิดบัง', !/abc123/.test(a.text));

  console.log('--- 3) ลิงก์ ---');
  const u1 = Tools.inspectUrl('https://www.scb.co.th/th/personal', rules);
  check('โดเมนทางการไม่ถูกตีว่าเสี่ยง', u1.official && u1.risk === 0);
  const u2 = Tools.inspectUrl('https://scb.co.th.secure-login.top/verify', rules);
  check('โดเมนปลอมที่ซ่อนชื่อแบรนด์ถูกจับ', !u2.official && u2.risk >= 0.7, 'risk=' + u2.risk.toFixed(2));
  check('ดึงลิงก์ที่ไม่มี http ได้', Tools.extractUrls('เข้า bit.ly/abc123 ด่วน', rules).includes('bit.ly/abc123'));
  check('ไม่ดึงโดเมนจากอีเมล', Tools.extractUrls('ส่งมาที่ me@example.com', rules).length === 0);

  console.log('--- 4) ไฟล์ ---');
  const f1 = Tools.analyzeFile({ name: 'invoice.pdf.exe', size: 1000, head: [0x4d, 0x5a] });
  check('จับไฟล์ปลอมนามสกุลซ้อน', f1.risk >= 0.8, 'risk=' + f1.risk.toFixed(2));
  const f2 = Tools.analyzeFile({ name: 'photo.jpg', size: 1000, head: [0xff, 0xd8] });
  check('ไฟล์รูปปกติไม่ถูกตีว่าเสี่ยง', f2.risk === 0);
  const r3 = await runAgent({ text: 'ส่งไฟล์ให้แล้ว', files: [{ name: 'empty.txt', size: 0, head: [], sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' }] }, { kb, blacklist, rules, config: { offline: true } });
  check('hash ไฟล์ใน blacklist ถูกจับ', r3.risk_score >= 85, 'score=' + r3.risk_score);

  console.log('--- 5) ความสม่ำเสมอ (รันซ้ำ 5 ครั้งต้องได้คะแนนเท่ากัน) ---');
  const scores = new Set();
  for (let i = 0; i < 5; i++) scores.add((await runAgent({ text: samples[0].text }, { kb, blacklist, rules, config: { offline: true } })).risk_score);
  check('deterministic', scores.size === 1, [...scores].join(','));

  console.log(failed ? `\nล้มเหลว ${failed} รายการ` : '\nผ่านทั้งหมด');
  process.exit(failed ? 1 : 0);
})();
