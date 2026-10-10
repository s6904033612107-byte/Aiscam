/**
 * tools.js — เครื่องมือที่ Agent เรียกใช้ (แต่ละฟังก์ชันทำหน้าที่เดียว ทดสอบแยกได้)
 *   extractUrls / extractPhones / extractAccounts
 *   inspectUrl        ตรวจลิงก์ด้วยกฎ (โดเมนปลอมแบรนด์, TLD เสี่ยง, ลิงก์ย่อ, IP, punycode ฯลฯ)
 *   checkBlacklist    เทียบกับ data/blacklist.json
 *   analyzeFile       ตรวจชื่อ/นามสกุล/magic bytes ของไฟล์ + hash (SHA-256)
 *   defang            แปลงลิงก์ให้กดไม่ได้ (hxxp://example[.]com) เพื่อกันเผลอคลิก
 */
(function (root) {
  'use strict';
  const isNode = typeof module !== 'undefined' && module.exports;
  const Anonymize = isNode ? require('./anonymize.js') : root.ScamChecker.Anonymize;

  const noisyOr = (ws) => 1 - ws.reduce((p, w) => p * (1 - Math.min(0.99, Math.max(0, w))), 1);

  /* ---------- ดึงข้อมูลจากข้อความ ---------- */

  function extractUrls(text, rules) {
    const src = String(text || '');
    const out = [];
    const push = (u) => {
      const clean = u.replace(/[.,;:!?)\]]+$/, '');
      if (clean && !out.includes(clean)) out.push(clean);
    };
    (src.match(/https?:\/\/[^\s<>"'()（）]+/gi) || []).forEach(push);
    const tlds = ((rules && rules.bare_domain_tlds) || ['com', 'net', 'org', 'th']).join('|');
    const re = new RegExp('(?<![@\\w./-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:' + tlds + ')(?![a-z0-9-])(?:[/?#][^\\s<>"\']*)?', 'gi');
    let m;
    while ((m = re.exec(src)) !== null) {
      const hit = m[0].replace(/[.,;:!?)\]]+$/, '');
      if (!out.some((u) => u.includes(hit))) push(hit);
    }
    return out;
  }

  const normalizePhone = (s) => {
    let d = String(s).replace(/\D/g, '');
    if (d.startsWith('66') && d.length >= 11) d = '0' + d.slice(2);
    return d;
  };

  function extractPhones(text) {
    const found = String(text || '').match(Anonymize.PHONE_RE) || [];
    return [...new Set(found.map(normalizePhone))];
  }

  function extractAccounts(text) {
    const re = /(?:เลขที่บัญชี|เลขบัญชี|บัญชี|account|acc|a\/c|พร้อมเพย์|promptpay)[^\d\n]{0,15}((?:\d[- ]?){9,14}\d)/gi;
    const out = [];
    let m;
    while ((m = re.exec(String(text || ''))) !== null) out.push(m[1].replace(/\D/g, ''));
    return [...new Set(out)];
  }

  /* ---------- ตรวจลิงก์ ---------- */

  const isOfficialHost = (host, official) => official.some((o) => host === o || host.endsWith('.' + o));

  function inspectUrl(raw, rules) {
    rules = rules || {};
    const hasScheme = /^https?:\/\//i.test(raw);
    let u;
    try {
      u = new URL(hasScheme ? raw : 'http://' + raw);
    } catch (e) {
      return { url: raw, host: '', hasScheme, official: false, signals: [{ id: 'unparsable', label: 'รูปแบบลิงก์ผิดปกติ', weight: 0.3 }], risk: 0.3 };
    }
    const host = u.hostname.toLowerCase();
    const labels = host.split('.');
    const hostTokens = host.split(/[.\-_]/);
    const signals = [];
    const add = (id, label, weight) => signals.push({ id, label, weight });

    // 1) ตรวจแบรนด์: ถ้าเป็นโดเมนทางการ -> ปลอดภัย / ถ้าแอบอ้างชื่อ -> เสี่ยงสูง
    for (const b of rules.brands || []) {
      const matched = b.tokens.some((t) => (t.length <= 4 ? hostTokens.includes(t) : host.includes(t)));
      if (!matched) continue;
      if (isOfficialHost(host, b.official)) {
        return { url: raw, host, hasScheme, official: true, brand: b.name, signals: [], risk: 0 };
      }
      add('brand_impersonation', 'ชื่อโดเมนคล้ายแบรนด์ ' + b.name + ' แต่ไม่ใช่โดเมนทางการ', 0.6);
      break;
    }

    if (/\bgov\b|gov-th|govth/.test(host) && !host.endsWith('.go.th')) add('fake_gov', 'ทำตัวเหมือนเว็บหน่วยงานรัฐแต่ไม่ใช่ .go.th', 0.4);
    if (hasScheme && u.protocol === 'http:') add('no_https', 'ไม่ใช้ HTTPS', 0.15);
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) add('ip_host', 'ใช้ที่อยู่ IP แทนชื่อเว็บ', 0.6);
    if (host.includes('xn--')) add('punycode', 'ชื่อโดเมนใช้อักขระพิเศษที่อาจปลอมตัวอักษร (punycode)', 0.5);
    if (u.username || u.password) add('userinfo', 'ลิงก์มี @ หรือรหัสผ่านนำหน้าโดเมน เพื่อหลอกให้เห็นเป็นเว็บอื่น', 0.6);
    if ((rules.shorteners || []).includes(host)) add('shortener', 'ลิงก์ย่อ มองไม่เห็นปลายทางจริง', 0.35);
    const tld = labels[labels.length - 1];
    const tldWeight = (rules.suspicious_tlds || {})[tld];
    if (tldWeight) add('suspicious_tld', 'นามสกุลโดเมน .' + tld + ' ถูกใช้ในเว็บหลอกลวงบ่อย', tldWeight);
    if (labels.length >= 5) add('many_subdomains', 'มีโดเมนย่อยซ้อนหลายชั้น', 0.2);
    const hyphens = (host.match(/-/g) || []).length;
    if (hyphens >= 3) add('many_hyphens', 'ชื่อโดเมนมีขีดหลายตัว', 0.2);
    else if (hyphens === 2) add('hyphens', 'ชื่อโดเมนมีขีดหลายตัว', 0.1);

    const hay = (host + u.pathname + u.search).toLowerCase();
    const kws = (rules.path_keywords || []).filter((k) => hay.includes(k));
    if (kws.length) add('phishing_keywords', 'ลิงก์มีคำที่พบบ่อยใน phishing: ' + kws.slice(0, 3).join(', '), Math.min(0.3, 0.12 * kws.length));
    if (/\.(apk|exe|scr|bat|msi|jar|vbs|ps1|dmg)$/i.test(u.pathname)) add('download_executable', 'ลิงก์ดาวน์โหลดไฟล์ติดตั้ง/โปรแกรมโดยตรง', 0.6);
    if (/(otp|pass|pwd|pin|cvv|card)=/i.test(u.search)) add('sensitive_query', 'ลิงก์ส่งค่าที่ดูเป็นรหัส/ข้อมูลบัตรผ่าน URL', 0.4);
    if (raw.length > 120) add('long_url', 'ลิงก์ยาวผิดปกติ', 0.1);

    return { url: raw, host, hasScheme, official: false, signals, risk: noisyOr(signals.map((s) => s.weight)) };
  }

  const defang = (url) => String(url).replace(/^http/i, 'hxxp').replace(/\./g, '[.]');

  /* ---------- Blacklist ---------- */

  function checkBlacklist({ hosts = [], phones = [], accounts = [], hashes = [] }, bl) {
    bl = bl || {};
    const hits = [];
    const note = (e, extra) => ({ type: e.type, source: e.source, note: e.note, demo: !!e.demo, ...extra });
    for (const h of hosts) {
      const e = (bl.domains || []).find((d) => h === d.value || h.endsWith('.' + d.value));
      if (e) hits.push(note(e, { kind: 'domain', value: h }));
    }
    for (const p of phones) {
      const e = (bl.phones || []).find((x) => normalizePhone(x.value) === p);
      if (e) hits.push(note(e, { kind: 'phone', value: p }));
    }
    for (const a of accounts) {
      const e = (bl.accounts || []).find((x) => String(x.value).replace(/\D/g, '') === a);
      if (e) hits.push(note(e, { kind: 'account', value: a }));
    }
    for (const h of hashes) {
      const e = (bl.file_hashes || []).find((x) => x.value.toLowerCase() === h.toLowerCase());
      if (e) hits.push(note(e, { kind: 'file_hash', value: h }));
    }
    return hits;
  }

  /* ---------- ตรวจไฟล์ ---------- */

  const EXEC_EXT = ['exe', 'apk', 'scr', 'bat', 'cmd', 'msi', 'jar', 'vbs', 'js', 'ps1', 'dmg', 'com', 'pif'];
  const MACRO_EXT = ['docm', 'xlsm', 'pptm'];
  const ARCHIVE_EXT = ['zip', 'rar', '7z', 'iso'];
  const SAFE_EXT = ['pdf', 'png', 'jpg', 'jpeg', 'gif', 'txt', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'csv'];

  function sniff(head) {
    const b = head || [];
    if (b[0] === 0x4d && b[1] === 0x5a) return 'exe';
    if (b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) return 'elf';
    if (b[0] === 0x50 && b[1] === 0x4b) return 'zip';
    if (b[0] === 0x25 && b[1] === 0x50 && b[2] === 0x44 && b[3] === 0x46) return 'pdf';
    if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return 'png';
    if (b[0] === 0xff && b[1] === 0xd8) return 'jpg';
    if (b[0] === 0xd0 && b[1] === 0xcf && b[2] === 0x11 && b[3] === 0xe0) return 'ole';
    if (b[0] === 0x23 && b[1] === 0x21) return 'script';
    return 'unknown';
  }

  function analyzeFile(f) {
    const name = String(f.name || '');
    const parts = name.toLowerCase().split('.');
    const ext = parts.length > 1 ? parts[parts.length - 1] : '';
    const prevExt = parts.length > 2 ? parts[parts.length - 2] : '';
    const kind = sniff(f.head);
    const signals = [];
    const add = (id, label, weight) => signals.push({ id, label, weight });
    if (EXEC_EXT.includes(ext)) add('executable_ext', 'ไฟล์ประเภทโปรแกรม/ติดตั้ง (.' + ext + ')', ext === 'apk' ? 0.6 : 0.5);
    if (EXEC_EXT.includes(ext) && SAFE_EXT.includes(prevExt)) add('double_extension', 'ปลอมนามสกุลซ้อน (.' + prevExt + '.' + ext + ')', 0.6);
    if ((kind === 'exe' || kind === 'elf') && !EXEC_EXT.includes(ext)) add('disguised_executable', 'เนื้อไฟล์เป็นโปรแกรมแต่ตั้งชื่อเป็นไฟล์ทั่วไป', 0.8);
    if (MACRO_EXT.includes(ext)) add('macro_document', 'เอกสารที่มี Macro (.' + ext + ')', 0.35);
    if (ARCHIVE_EXT.includes(ext)) add('archive', 'ไฟล์บีบอัด ซ่อนเนื้อหาข้างในได้', 0.15);
    if (ext === 'lnk') add('shortcut', 'ไฟล์ shortcut (.lnk) ใช้รันคำสั่งแฝง', 0.5);
    return { name, size: f.size || 0, ext, detected_type: kind, sha256: f.sha256 || null, signals, risk: noisyOr(signals.map((s) => s.weight)) };
  }

  async function sha256Hex(arrayBuffer) {
    const subtle = (root.crypto && root.crypto.subtle) || require('crypto').webcrypto.subtle;
    const buf = await subtle.digest('SHA-256', arrayBuffer);
    return [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, '0')).join('');
  }

  const api = { extractUrls, extractPhones, extractAccounts, normalizePhone, inspectUrl, defang, checkBlacklist, analyzeFile, sniff, sha256Hex, noisyOr };
  if (isNode) module.exports = api;
  else (root.ScamChecker = root.ScamChecker || {}).Tools = api;
})(typeof window !== 'undefined' ? window : globalThis);
