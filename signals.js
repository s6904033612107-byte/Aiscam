/**
 * signals.js — ตรวจ "สัญญาณ Scam" ในข้อความด้วยกฎ (rule-based)
 * แต่ละสัญญาณมี weight (0-1) = ความน่าสงสัยเมื่อพบสัญญาณนี้เดี่ยว ๆ
 * การรวมคะแนนอยู่ใน scoring.js
 * unless = ถ้าพบคำปฏิเสธใกล้ ๆ (เช่น "ห้ามบอก OTP") จะไม่นับเป็นสัญญาณ
 */
(function (root) {
  'use strict';
  const isNode = typeof module !== 'undefined' && module.exports;

  const NEG = /(ห้าม|อย่า|ไม่เคย|ไม่ขอ|ไม่มี)|do not|don't|never/i;

  const PATTERNS = [
    { id: 'urgency', category: 'urgency', label: 'เร่งรัดให้รีบทำ/จำกัดเวลา', weight: 0.25,
      re: /ด่วน|ภายใน\s?\d+\s?(ชั่วโมง|ชม\.?|นาที|วัน)|ทันที|หมดเวลา|ระงับ|อายัด|ถูกล็อก|ล็อค|ปิดบัญชี|within\s\d+\s?(hours?|minutes?)|immediately|urgent|suspended/i,
      reason: 'ข้อความเร่งให้ตัดสินใจเร็วหรือขู่ว่าจะเสียสิทธิ์ เป็นวิธีที่มิจฉาชีพใช้เพื่อไม่ให้เหยื่อมีเวลาคิด' },
    { id: 'otp_request', category: 'otp', label: 'ขอรหัส OTP / PIN / CVV / รหัสผ่าน', weight: 0.5, unless: NEG,
      re: /(บอก|แจ้ง|ส่ง|ให้|กรอก|ยืนยัน|ขอ|เปิดเผย)\s?(รหัส\s?)?(otp|pin|cvv|รหัสผ่าน|รหัสยืนยัน|รหัสครั้งเดียว|รหัสหลังบัตร)|(send|share|provide|tell|enter)\s(me\s)?(the\s|your\s)?(otp|pin|cvv|password|code)/i,
      reason: 'มีการขอรหัสที่ใช้ยืนยันธุรกรรมหรือเข้าบัญชี ซึ่งหน่วยงานจริงไม่ขอจากลูกค้า' },
    { id: 'money_transfer', category: 'money', label: 'ให้โอนเงิน/จ่ายค่าธรรมเนียม', weight: 0.2,
      re: /โอนเงิน|โอนเข้า|ชำระ|ค่าธรรมเนียม|ค่าประกัน|ค่าดำเนินการ|มัดจำ|เงินประกัน|ค่าส่ง|ค่าภาษี|เติมเงิน|ฝากเงิน|ค่าศุลกากร|deposit|transfer|fee/i,
      reason: 'มีการให้โอนเงินหรือจ่ายค่าใช้จ่ายล่วงหน้า ซึ่งเป็นรูปแบบหลักของการหลอกลวงทางการเงิน' },
    { id: 'advance_fee', category: 'money', label: 'ต้องจ่ายก่อนจึงจะได้รับเงิน/รางวัล/งาน', weight: 0.35,
      re: /(โอน|จ่าย|ชำระ)(ก่อน|เงินก่อน)|ค่าธรรมเนียม(รับรางวัล|ปลดล็อก|อนุมัติ)|ค่า(มัดจำ|ประกัน)(เริ่มงาน|สินเชื่อ|การกู้)/i,
      reason: 'ต้องจ่ายเงินก่อนได้รับสิ่งที่สัญญาไว้ (advance-fee fraud)' },
    { id: 'authority', category: 'authority', label: 'แอบอ้างเจ้าหน้าที่รัฐ/ตำรวจ/คดี', weight: 0.35,
      re: /ตำรวจ|ดีเอสไอ|\bdsi\b|ป\.?ป\.?ง|ศาล|หมายจับ|หมายเรียก|กรมสรรพากร|สรรพากร|ศุลกากร|ฟอกเงิน|คดี|ยาเสพติด/i,
      reason: 'อ้างชื่อหน่วยงานรัฐหรือกล่าวถึงคดีเพื่อสร้างความกลัวและความน่าเชื่อถือ' },
    { id: 'bank_mention', category: 'bank', label: 'อ้างชื่อธนาคาร/บริการการเงิน', weight: 0.1,
      re: /ธนาคาร|เจ้าหน้าที่ธนาคาร|บัญชีของท่าน|บัญชีของคุณ|บัตรเครดิต|kbank|\bscb\b|กรุงไทย|กสิกร|ไทยพาณิชย์|ออมสิน|truemoney|พร้อมเพย์/i,
      reason: 'ข้อความอ้างถึงธนาคารหรือบริการการเงิน ต้องตรวจว่ามาจากช่องทางทางการจริงหรือไม่' },
    { id: 'parcel', category: 'parcel', label: 'พัสดุตกค้าง/จัดส่งไม่สำเร็จ', weight: 0.25,
      re: /พัสดุ|ติดตามพัสดุ|ตกค้าง|จัดส่งไม่สำเร็จ|ที่อยู่ไม่ครบ|ยืนยันที่อยู่|kerry|flash express|ไปรษณีย์|j&t/i,
      reason: 'รูปแบบข้อความพัสดุตกค้างเป็น phishing ที่พบบ่อย มักแนบลิงก์ให้กรอกข้อมูลบัตร' },
    { id: 'prize', category: 'prize', label: 'แจ้งว่าได้รับรางวัล/ของแจก', weight: 0.4,
      re: /ยินดีด้วย|ได้รับรางวัล|ผู้โชคดี|ถูกรางวัล|แจก(เงิน|ฟรี)|ลุ้นรางวัล|\bwinner\b|lottery|claim your/i,
      reason: 'แจ้งว่าถูกรางวัลโดยที่คุณอาจไม่ได้ร่วมกิจกรรม มักจบด้วยการขอข้อมูลหรือเงิน' },
    { id: 'job_easy_income', category: 'job', label: 'งานง่าย รายได้สูง', weight: 0.35,
      re: /งานออนไลน์|งานง่าย|รายได้\s?(วันละ|ต่อวัน)|ได้เงินจริง|งานเสริม|ทำที่บ้าน|กดไลค์|กดแชร์|รีวิวสินค้า|ไม่ต้องมีประสบการณ์|part[- ]?time|work from home/i,
      reason: 'งานที่ให้ผลตอบแทนสูงเกินงานที่ทำ เป็นรูปแบบของการหลอกให้โอนเงินทำภารกิจ' },
    { id: 'investment', category: 'investment', label: 'ชวนลงทุน/ผลตอบแทนสูง', weight: 0.3,
      re: /ลงทุน|กำไร|ปันผล|ผลตอบแทน|คริปโต|crypto|forex|ทีมวิเคราะห์|เทรด|\d+\s?%\s?(ต่อ|\/)\s?(วัน|สัปดาห์|เดือน)/i,
      reason: 'ชวนลงทุนด้วยผลตอบแทนที่ระบุตัวเลขชัดเจน ควรตรวจสอบผู้ให้บริการกับหน่วยงานกำกับดูแล' },
    { id: 'guaranteed_return', category: 'investment', label: 'การันตีกำไร/ไม่มีความเสี่ยง', weight: 0.4,
      re: /การันตี|รับประกัน(กำไร|ผลตอบแทน)|ไม่มีความเสี่ยง|กำไรแน่นอน|ได้เงินแน่นอน|ไม่มีขาดทุน/i,
      reason: 'การลงทุนจริงไม่มีใครรับประกันกำไรโดยไม่มีความเสี่ยงได้' },
    { id: 'loan', category: 'loan', label: 'สินเชื่อ/เงินกู้อนุมัติง่าย', weight: 0.3,
      re: /สินเชื่อ|กู้เงิน|อนุมัติ(ทันที|ไว)|ไม่เช็คเครดิต|ไม่ต้องค้ำ|ปล่อยกู้|ดอกเบี้ย\s?0|\bloan\b/i,
      reason: 'เสนอสินเชื่อง่ายผิดปกติ มักตามด้วยการเก็บค่าธรรมเนียมก่อนอนุมัติ' },
    { id: 'romance_help', category: 'romance', label: 'ขอความช่วยเหลือทางการเงินจากคนที่เพิ่งรู้จัก', weight: 0.3,
      re: /ที่รัก|ส่งของขวัญ|ติดค่าศุลกากร|ช่วยโอนเงิน|ติดปัญหาเรื่องเงิน|ขอยืมเงิน|แพทย์ทหาร|ทหารต่างประเทศ/i,
      reason: 'เข้าข่าย romance scam คือสร้างความสนิทสนมแล้วขอให้ช่วยจ่ายเงิน' },
    { id: 'known_person', category: 'known_person', label: 'แอบอ้างเป็นคนรู้จัก/เบอร์ใหม่', weight: 0.3,
      re: /เบอร์ใหม่|เปลี่ยนเบอร์|นี่(ผม|ฉัน|หนู)เอง|จำได้ไหม/i,
      reason: 'อ้างเป็นคนรู้จักจากเบอร์ใหม่ ควรโทรกลับเบอร์เดิมเพื่อยืนยัน' },
    { id: 'secrecy', category: 'secrecy', label: 'ห้ามบอกใคร/ห้ามวางสาย', weight: 0.4,
      re: /(อย่า|ห้าม)บอก(ใคร|ญาติ|คนอื่น|ธนาคาร|เจ้าหน้าที่)|เป็นความลับ|ห้ามวางสาย|ห้ามติดต่อ|do not tell/i,
      reason: 'พยายามตัดเหยื่อออกจากคนที่อาจช่วยเตือน เป็นสัญญาณของแก๊งคอลเซ็นเตอร์' },
    { id: 'install_app', category: 'app', label: 'ให้ติดตั้งแอป/ไฟล์/โปรแกรมรีโมต', weight: 0.4,
      re: /ติดตั้งแอป|ดาวน์โหลดแอป|\.apk|anydesk|teamviewer|ควบคุมหน้าจอ|สแกน\s?qr|สแกนคิวอาร์|แอปพลิเคชันใหม่/i,
      reason: 'ให้ติดตั้งแอปหรือไฟล์นอกร้านค้าทางการ ซึ่งอาจเป็นมัลแวร์ที่ควบคุมเครื่อง' },
    { id: 'personal_info', category: 'personal', label: 'ขอข้อมูลส่วนตัว/เอกสารยืนยันตัวตน', weight: 0.3,
      re: /เลขบัตรประชาชน|หน้าบัตร|สำเนาบัตร|ถ่ายรูปคู่บัตร|เลขบัตรเครดิต|รหัส\s?atm|ข้อมูลส่วนตัว|เซลฟี่|ยืนยันตัวตน/i,
      reason: 'ขอข้อมูลส่วนตัวที่นำไปสวมรอยหรือเปิดบัญชีได้' },
    { id: 'account_rental', category: 'rental', label: 'รับซื้อ/เช่าบัญชีหรือซิม', weight: 0.5,
      re: /เช่าบัญชี|ยืมบัญชี|ขายบัญชี|รับซื้อบัญชี|เปิดบัญชีให้|รับซื้อซิม/i,
      reason: 'การให้ผู้อื่นใช้บัญชีหรือซิมเสี่ยงต่อการถูกดำเนินคดีฐานเกี่ยวข้องกับการฟอกเงิน' },
    { id: 'gambling', category: 'gambling', label: 'โฆษณาพนันออนไลน์', weight: 0.35,
      re: /บาคาร่า|สล็อต|เว็บพนัน|แทงบอล|ufabet|pg\s?slot|คาสิโน|casino/i,
      reason: 'เว็บพนันออนไลน์ผิดกฎหมายและมักโกงเงินฝาก' },
    { id: 'click_cta', category: 'click', label: 'ให้กด/เข้าสู่ระบบผ่านลิงก์', weight: 0.15,
      re: /คลิก|กดลิงก์|กดที่ลิงก์|แตะลิงก์|click (here|the link)|กดยืนยัน|เข้าสู่ระบบ/i,
      reason: 'ชักชวนให้กดลิงก์ในข้อความ ซึ่งเป็นช่องทางหลักของ phishing' },
    { id: 'threat', category: 'threat', label: 'ข่มขู่ดำเนินคดี/ยึดทรัพย์', weight: 0.3,
      re: /ดำเนินคดี|ฟ้องร้อง|จับกุม|ยึดทรัพย์|จำคุก|legal action|arrest/i,
      reason: 'ใช้ความกลัวเพื่อกดดันให้ทำตามโดยไม่ตรวจสอบ' },
    { id: 'too_good', category: 'too_good', label: 'ข้อเสนอดีเกินจริง/จำนวนจำกัด', weight: 0.15,
      re: /ไม่ต้องลงทุน|รวยเร็ว|รับสิทธิ์|สิทธิ์พิเศษ|จำนวนจำกัด|เหลือเพียง|วันนี้เท่านั้น|100\s?%/i,
      reason: 'ข้อเสนอที่ดีเกินจริงพร้อมการจำกัดจำนวนเพื่อเร่งการตัดสินใจ' },
    { id: 'off_platform', category: 'offplatform', label: 'ชวนไปคุยต่อทางไลน์/เทเลแกรม', weight: 0.2,
      re: /ทักไลน์|แอดไลน์|add line|เพิ่มเพื่อน|ติดต่อทางไลน์|เทเลแกรม|telegram|whatsapp|line\.me|lin\.ee|t\.me/i,
      reason: 'ชวนย้ายไปคุยช่องทางส่วนตัว ทำให้ตรวจสอบและติดตามได้ยาก' }
  ];

  // สัญญาณที่ช่วยลดความเสี่ยง (เช่น ประกาศเตือนภัยจริง)
  const REDUCERS = [
    { id: 'official_warning', label: 'เป็นข้อความเตือนภัย (ห้ามบอก OTP / ไม่เคยขอรหัส)', weight: 0.25,
      re: /(ห้าม|อย่า)(บอก|แจ้ง|เปิดเผย|ให้)(รหัส)?\s?otp|ไม่เคย(โทร|ขอ|ส่ง)|never (ask|share|call)/i }
  ];

  function windowAround(text, index, len) {
    return text.slice(Math.max(0, index - 30), index + len + 30);
  }

  function detectSignals(text) {
    const src = String(text || '');
    const found = [];
    for (const p of PATTERNS) {
      const re = new RegExp(p.re.source, p.re.flags.includes('g') ? p.re.flags : p.re.flags + 'g');
      const matches = [];
      let m;
      while ((m = re.exec(src)) !== null && matches.length < 3) {
        if (m[0] === '') { re.lastIndex++; continue; }
        if (p.unless && p.unless.test(windowAround(src, m.index, m[0].length))) continue;
        matches.push(m[0]);
      }
      if (matches.length) {
        found.push({ id: p.id, category: p.category, label: p.label, weight: p.weight, reason: p.reason, matches, source: 'text' });
      }
    }
    const reducers = REDUCERS.filter((r) => r.re.test(src)).map((r) => ({ id: r.id, label: r.label, weight: r.weight }));
    return { signals: found, reducers };
  }

  const api = { PATTERNS, REDUCERS, detectSignals };
  if (isNode) module.exports = api;
  else (root.ScamChecker = root.ScamChecker || {}).Signals = api;
})(typeof window !== 'undefined' ? window : globalThis);
