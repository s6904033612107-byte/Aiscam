/**
 * scoring.js — รวมหลักฐานทั้งหมดเป็นคะแนน 0-100 พร้อมเหตุผล สัญญาณ และคำแนะนำ
 *
 * หลักคิด: ใช้ noisy-OR  score = 1 - Π(1 - wᵢ)
 *   - แต่ละสัญญาณที่พบเพิ่มความเสี่ยงทีละน้อย สัญญาณหลายตัวรวมกันสูงขึ้นเร็ว แต่ไม่เกิน 100
 *   - สัญญาณที่ช่วยลดความเสี่ยง (เช่น ประกาศเตือนภัย) หักออกสูงสุด 40%
 *   - ถูกพบใน blacklist/รายงานมัลแวร์ -> คะแนนขั้นต่ำ 85
 *   - ถ้า Claude ช่วยวิเคราะห์ -> ถ่วงน้ำหนัก 60% ระบบกฎ + 40% Claude และบอกผู้ใช้เมื่อสองฝั่งไม่ตรงกัน
 */
(function (root) {
  'use strict';
  const isNode = typeof module !== 'undefined' && module.exports;
  const Tools = isNode ? require('./tools.js') : root.ScamChecker.Tools;

  const LEVELS = [
    { key: 'low', min: 0, label: 'ความเสี่ยงต่ำ' },
    { key: 'medium', min: 25, label: 'ควรระวัง' },
    { key: 'high', min: 50, label: 'เสี่ยงสูง' },
    { key: 'critical', min: 75, label: 'อันตรายมาก' }
  ];
  const levelOf = (score) => [...LEVELS].reverse().find((l) => score >= l.min);

  const CATEGORY_ADVICE = {
    otp: 'อย่าบอกรหัส OTP / PIN / CVV แก่ใคร แม้ผู้ขออ้างว่าเป็นธนาคารหรือเจ้าหน้าที่',
    money: 'อย่าโอนเงินหรือจ่ายค่าธรรมเนียมล่วงหน้า จนกว่าจะยืนยันตัวตนผู้ขอผ่านช่องทางทางการที่คุณค้นหาเอง',
    authority: 'เจ้าหน้าที่รัฐไม่โทรให้โอนเงินเพื่อพิสูจน์ตัวเอง ให้วางสายแล้วโทรกลับเบอร์ทางการที่ค้นหาเอง',
    app: 'ไม่ติดตั้งแอปหรือไฟล์ที่ได้รับทางข้อความ และไม่ให้ใครควบคุมเครื่องจากระยะไกล',
    personal: 'อย่าส่งรูปบัตรประชาชน เซลฟี่คู่บัตร หรือข้อมูลส่วนตัวให้ผู้ที่ติดต่อมาเอง',
    secrecy: 'ถ้าถูกห้ามบอกคนอื่น ให้บอกคนที่ไว้ใจทันที เพราะนี่คือสัญญาณของแก๊งหลอกลวง',
    job: 'งานจริงไม่เก็บเงินจากผู้สมัคร ตรวจสอบบริษัทจากแหล่งทางการก่อนติดต่อ',
    investment: 'ตรวจสอบรายชื่อผู้ให้บริการกับ ก.ล.ต. และอย่าเชื่อการรับประกันผลตอบแทน',
    parcel: 'ตรวจสถานะพัสดุจากแอปหรือเว็บของขนส่งโดยพิมพ์ที่อยู่เว็บเอง',
    rental: 'ห้ามให้เช่า/ขายบัญชีหรือซิม เพราะเจ้าของบัญชีอาจต้องรับผิดทางกฎหมาย'
  };

  function defaultRecommendations(levelKey) {
    if (levelKey === 'critical' || levelKey === 'high') {
      return [
        'ห้ามคลิกลิงก์ ห้ามโทรกลับเบอร์ในข้อความ และห้ามกรอกข้อมูลส่วนตัว',
        'หยุดการสนทนากับผู้ส่ง แล้วบล็อกเบอร์หรือบัญชีนั้น',
        'ถ้าเผลอโอนเงินหรือให้ข้อมูลไปแล้ว ให้โทร 1441 และแจ้งธนาคารเพื่ออายัดทันที',
        'เก็บภาพหน้าจอเป็นหลักฐาน และแจ้งความออนไลน์ที่ thaipoliceonline.go.th'
      ];
    }
    if (levelKey === 'medium') {
      return [
        'ตรวจสอบกับต้นทางผ่านช่องทางที่คุณหาเอง (เบอร์หลังบัตร หรือเว็บไซต์ทางการที่พิมพ์เอง) อย่าใช้เบอร์หรือลิงก์ในข้อความ',
        'ยังไม่ควรโอนเงินหรือให้ข้อมูลส่วนตัว',
        'ปรึกษาคนที่ไว้ใจก่อนตัดสินใจ'
      ];
    }
    return ['ยังไม่พบสัญญาณชัดเจน แต่ระบบรับรองความปลอดภัยไม่ได้ 100% หากถูกขอเงิน รหัส หรือข้อมูลส่วนตัว ให้หยุดและตรวจสอบก่อน'];
  }

  /** ตรวจผลจาก Claude ก่อนนำไปใช้ (ป้องกัน output ผิดรูปแบบ / อ้างลิงก์ที่ไม่มีในอินพุต) */
  function validateLLM(out, allowedHosts) {
    if (!out || typeof out !== 'object') return null;
    const score = Number(out.risk_score);
    if (!Number.isFinite(score)) return null;
    const strArr = (a, n) => (Array.isArray(a) ? a.filter((x) => typeof x === 'string').map((x) => x.slice(0, 300)).slice(0, n) : []);
    const urls = Array.isArray(out.suspicious_urls) ? out.suspicious_urls : [];
    const okUrls = urls
      .map((u) => (typeof u === 'string' ? u : u && u.url))
      .filter((u) => typeof u === 'string' && allowedHosts.some((h) => u.toLowerCase().includes(h)))
      .slice(0, 10);
    return {
      risk_score: Math.max(0, Math.min(100, Math.round(score))),
      is_scam: !!out.is_scam,
      confidence: Math.max(0, Math.min(1, Number(out.confidence) || 0.5)),
      reasons: strArr(out.reasons, 6),
      signals: strArr(out.signals, 8),
      recommendations: strArr(out.recommendations, 6),
      suspicious_urls: okUrls
    };
  }

  function finalize(ev) {
    const evidence = [];
    const push = (e) => evidence.push(e);

    ev.signals.forEach((s) => push({ ...s, source: 'text' }));
    ev.urlFindings.forEach((u) => {
      if (u.risk > 0) {
        const top = [...u.signals].sort((a, b) => b.weight - a.weight).slice(0, 3);
        push({
          id: 'url:' + u.host, category: 'url', source: 'url', weight: u.risk * 0.9,
          label: 'ลิงก์น่าสงสัย: ' + Tools.defang(u.host),
          reason: 'ลิงก์ ' + Tools.defang(u.host) + ' — ' + top.map((s) => s.label).join('; ')
        });
      }
    });
    ev.blacklistHits.forEach((h) => push({
      id: 'blacklist:' + h.kind, category: 'blacklist', source: 'blacklist', weight: 0.92,
      label: 'พบใน blacklist (' + h.kind + ')',
      reason: 'พบ ' + h.kind + ' นี้ในรายการเฝ้าระวัง' + (h.demo ? ' (ข้อมูลตัวอย่าง)' : '') + (h.note ? ' — ' + h.note : '')
    }));
    ev.fileFindings.forEach((f) => {
      if (f.risk > 0) {
        push({ id: 'file:' + f.name, category: 'file', source: 'file', weight: f.risk * 0.9, label: 'ไฟล์เสี่ยง: ' + f.name, reason: 'ไฟล์ ' + f.name + ' — ' + f.signals.map((s) => s.label).join('; ') });
      }
    });
    (ev.reputation || []).forEach((r) => {
      if (r.gsb) push({ id: 'gsb', category: 'reputation', source: 'reputation', weight: 0.9, label: 'Google Safe Browsing แจ้งว่าอันตราย', reason: 'Google Safe Browsing ระบุว่า ' + Tools.defang(r.target) + ' เป็นเว็บอันตราย' });
      if (r.vt && r.vt.malicious >= 3) push({ id: 'vt', category: 'reputation', source: 'reputation', weight: 0.85, label: 'VirusTotal พบการตรวจจับ', reason: 'VirusTotal: ' + r.vt.malicious + ' เอนจินระบุว่าอันตราย' });
      else if (r.vt && r.vt.malicious > 0) push({ id: 'vt-low', category: 'reputation', source: 'reputation', weight: 0.5, label: 'VirusTotal พบการตรวจจับบางส่วน', reason: 'VirusTotal: ' + r.vt.malicious + ' เอนจินระบุว่าอันตราย' });
    });

    const base = Tools.noisyOr(evidence.map((e) => e.weight));
    const reduction = Math.min(0.4, ev.reducers.reduce((s, r) => s + r.weight, 0));
    let local = Math.round(base * (1 - reduction) * 100);
    const hardHit = evidence.some((e) => e.source === 'blacklist' || e.source === 'reputation');
    if (hardHit) local = Math.max(local, 85);

    let score = local;
    let llm = null;
    let disagreement = false;
    if (ev.llm) {
      llm = ev.llm;
      score = Math.round(0.6 * local + 0.4 * llm.risk_score);
      if (hardHit) score = Math.max(score, 85);
      disagreement = Math.abs(local - llm.risk_score) >= 40;
    }
    score = Math.max(0, Math.min(100, score));
    const level = levelOf(score);

    const sorted = [...evidence].sort((a, b) => b.weight - a.weight);
    const reasons = sorted.slice(0, 6).map((e) => e.reason || e.label);
    if (llm) llm.reasons.forEach((r) => { if (reasons.length < 8 && !reasons.includes(r)) reasons.push(r + ' (Claude)'); });
    if (!reasons.length) reasons.push('ไม่พบสัญญาณ Scam ที่ระบบรู้จักในข้อความนี้');
    ev.reducers.forEach((r) => reasons.push('ปัจจัยที่ช่วยลดความเสี่ยง: ' + r.label));

    const recs = [];
    const addRec = (r) => { if (r && !recs.includes(r) && recs.length < 9) recs.push(r); };
    defaultRecommendations(level.key).forEach(addRec);
    const cats = new Set(evidence.map((e) => e.category));
    Object.keys(CATEGORY_ADVICE).forEach((c) => { if (cats.has(c)) addRec(CATEGORY_ADVICE[c]); });
    (ev.knowledge || []).slice(0, 2).forEach((k) => addRec(k.advice));
    if (llm) llm.recommendations.forEach(addRec);

    const suspiciousUrls = ev.urlFindings
      .filter((u) => u.risk >= 0.3 || ev.blacklistHits.some((h) => h.kind === 'domain' && h.value === u.host))
      .map((u) => ({
        url_defanged: Tools.defang(u.url),
        host: Tools.defang(u.host),
        risk: Math.round(u.risk * 100),
        reasons: u.signals.map((s) => s.label),
        blacklisted: ev.blacklistHits.some((h) => h.kind === 'domain' && h.value === u.host),
        warning: 'ไม่ควรคลิกลิงก์นี้ และอย่ากรอกข้อมูลส่วนตัว รหัสผ่าน หรือ OTP'
      }));

    const strongEvidence = evidence.filter((e) => e.weight >= 0.3).length;
    const confidence = Math.min(0.95, 0.45 + 0.1 * evidence.length + 0.05 * strongEvidence + (llm ? 0.1 : 0));

    return {
      is_scam: score >= 50,
      verdict: score >= 50 ? 'scam_likely' : score >= 25 ? 'uncertain' : 'likely_safe',
      verdict_label: score >= 50 ? 'น่าจะเป็น Scam' : score >= 25 ? 'ไม่แน่ใจ ควรตรวจสอบเพิ่ม' : 'ยังไม่พบสัญญาณ Scam ชัดเจน',
      risk_score: score,
      risk_level: level.key,
      risk_level_label: level.label,
      confidence: Math.round(confidence * 100) / 100,
      reasons,
      signals: sorted.map((e) => ({ id: e.id, label: e.label, category: e.category, source: e.source, weight: Math.round(e.weight * 100) / 100, matches: e.matches || [] })),
      recommendations: recs,
      suspicious_urls: suspiciousUrls,
      blacklist_hits: ev.blacklistHits,
      file_findings: ev.fileFindings,
      knowledge_refs: (ev.knowledge || []).map((k) => ({ id: k.id, title: k.title, matched_keywords: k.matched_keywords })),
      engine: { version: '1.0', local_score: local, llm_score: llm ? llm.risk_score : null, llm_used: !!llm, disagreement }
    };
  }

  const api = { finalize, validateLLM, levelOf, LEVELS };
  if (isNode) module.exports = api;
  else (root.ScamChecker = root.ScamChecker || {}).Scoring = api;
})(typeof window !== 'undefined' ? window : globalThis);
