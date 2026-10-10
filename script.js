/**
 * script.js — ตัวเชื่อมหน้าเว็บทุกหน้า (UI + Memory แบบ JSON ใน localStorage)
 * หน้าที่ถูกเลือกจาก <body data-page="home|check|result|report|admin">
 * ความปลอดภัย: ข้อความจากผู้ใช้ถูกแสดงด้วย textContent เท่านั้น (กัน XSS)
 */
(function () {
  'use strict';
  const SC = window.ScamChecker;

  /* ===== ตั้งค่า ===== */
  const CONFIG = {
    llmEndpoint: '/api/analyze',               // Vercel serverless (เรียก Claude) — ถ้าไม่มีจะข้ามอัตโนมัติ
    reputationEndpoint: '/api/url-reputation', // Google Safe Browsing / VirusTotal (ไม่บังคับ)
    sheetWebhook: '',                          // URL ของ Google Apps Script (ดู docs/google-apps-script.gs) เว้นว่างถ้าไม่ใช้
    maxFileBytes: 25 * 1024 * 1024
  };
  const KEY_MEM = 'scamchecker.memory.v1';
  const KEY_LAST = 'scamchecker.lastResult';

  const $ = (sel) => document.querySelector(sel);
  const page = document.body.dataset.page;

  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([k, v]) => {
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else n.setAttribute(k, v);
    });
    kids.flat().forEach((k) => n.append(k instanceof Node ? k : document.createTextNode(String(k))));
    return n;
  }
  const clear = (n) => { while (n.firstChild) n.removeChild(n.firstChild); };
  const fmtTime = (iso) => new Date(iso).toLocaleString('th-TH', { dateStyle: 'short', timeStyle: 'short' });

  function toast(msg) {
    const t = el('div', { class: 'toast', role: 'status', text: msg });
    document.body.append(t);
    setTimeout(() => t.remove(), 2200);
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      toast('คัดลอกแล้ว');
    } catch (e) {
      const ta = el('textarea', { 'aria-label': 'ข้อความสำหรับคัดลอก' });
      ta.value = text;
      document.body.append(ta);
      ta.select();
      try { document.execCommand('copy'); toast('คัดลอกแล้ว'); } catch (e2) { toast('คัดลอกไม่ได้ กรุณาเลือกข้อความเอง'); }
      ta.remove();
    }
  }

  /* ===== Memory แบบ JSON (localStorage) ===== */
  const Memory = {
    load() {
      try {
        const m = JSON.parse(localStorage.getItem(KEY_MEM));
        if (m && m.version === 1) return m;
      } catch (e) { /* ใช้ค่าเริ่มต้น */ }
      return { version: 1, settings: { useClaude: true }, history: [], reports: [] };
    },
    save(m) {
      try { localStorage.setItem(KEY_MEM, JSON.stringify(m)); } catch (e) { /* โหมดส่วนตัวอาจเขียนไม่ได้ */ }
    },
    addHistory(rec) {
      const m = Memory.load();
      m.history.unshift(rec);
      m.history = m.history.slice(0, 200);
      Memory.save(m);
    }
  };

  async function postToSheet(record) {
    if (!CONFIG.sheetWebhook) return;
    try {
      await fetch(CONFIG.sheetWebhook, { method: 'POST', mode: 'no-cors', headers: { 'Content-Type': 'text/plain' }, body: JSON.stringify(record) });
    } catch (e) { /* ไม่ให้กระทบผู้ใช้ */ }
  }

  /* ===== โหลดข้อมูล (RAG / blacklist / กฎลิงก์) ===== */
  async function loadData() {
    const get = (f) => fetch(f).then((r) => { if (!r.ok) throw new Error(f); return r.json(); });
    const [kbJson, blacklist, rules] = await Promise.all([get('data/knowledge-base.json'), get('data/blacklist.json'), get('data/url-rules.json')]);
    // รวมรายงานของผู้ใช้ในเครื่องเข้ากับ blacklist
    const mem = Memory.load();
    mem.reports.forEach((r) => {
      const list = r.type === 'domain' ? blacklist.domains : r.type === 'phone' ? blacklist.phones : blacklist.accounts;
      list.push({ value: r.value, type: 'user-report', source: 'local-report', note: r.note || '' });
    });
    return { kb: new SC.Rag.KnowledgeBase(kbJson.docs), blacklist, rules };
  }

  /* ===== หน้าแรก ===== */
  async function initHome() {
    const box = $('#sample-links');
    try {
      const data = await fetch('data/samples.json').then((r) => r.json());
      data.samples.forEach((s) => box.append(el('a', { href: 'check.html?sample=' + encodeURIComponent(s.id), text: s.label })));
    } catch (e) {
      box.textContent = 'โหลดตัวอย่างไม่ได้ (ถ้าเปิดไฟล์โดยตรง ให้รันผ่านเซิร์ฟเวอร์ เช่น npx serve)';
    }
  }

  /* ===== หน้าตรวจสอบ ===== */
  async function initCheck() {
    const textEl = $('#text');
    const preview = $('#preview');
    const traceEl = $('#trace');
    const errEl = $('#error');
    const useClaude = $('#use-claude');

    useClaude.checked = Memory.load().settings.useClaude !== false;
    useClaude.addEventListener('change', () => {
      const m = Memory.load();
      m.settings.useClaude = useClaude.checked;
      Memory.save(m);
    });

    const showError = (msg) => { errEl.textContent = msg; errEl.hidden = !msg; };

    function updatePreview() {
      $('#count').textContent = textEl.value.length;
      if (!textEl.value.trim()) { preview.textContent = '(ยังไม่มีข้อความ)'; $('#mask-summary').textContent = ''; return; }
      const a = SC.Anonymize.anonymize(textEl.value);
      preview.textContent = a.text;
      $('#mask-summary').textContent = a.total ? 'ปิดบัง ' + a.total + ' รายการ: ' + Object.entries(a.counts).map(([k, v]) => k + ' ×' + v).join(', ') : 'ไม่พบข้อมูลส่วนตัวที่ต้องปิดบัง';
    }
    let timer;
    textEl.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(updatePreview, 150); });

    const sampleId = new URLSearchParams(location.search).get('sample');
    if (sampleId) {
      try {
        const data = await fetch('data/samples.json').then((r) => r.json());
        const s = data.samples.find((x) => x.id === sampleId);
        if (s) textEl.value = s.text;
      } catch (e) { /* ไม่เป็นไร */ }
    }
    const prefill = sessionStorage.getItem('scamchecker.prefill');
    if (prefill && !textEl.value) { textEl.value = prefill; sessionStorage.removeItem('scamchecker.prefill'); }
    updatePreview();

    $('#clear').addEventListener('click', () => {
      $('#check-form').reset();
      useClaude.checked = Memory.load().settings.useClaude !== false;
      clear(traceEl);
      showError('');
      updatePreview();
    });

    $('#check-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      showError('');
      const text = textEl.value.trim();
      const phone = $('#phone').value.trim();
      const account = $('#account').value.trim();
      const fileList = [...$('#files').files];
      if (!text && !phone && !account && !fileList.length) { showError('กรุณาใส่ข้อความ ลิงก์ เบอร์ เลขบัญชี หรือแนบไฟล์อย่างน้อยหนึ่งอย่าง'); return; }

      const btn = $('#run');
      btn.disabled = true;
      clear(traceEl);

      try {
        const files = [];
        for (const f of fileList) {
          if (f.size > CONFIG.maxFileBytes) { showError('ไฟล์ ' + f.name + ' ใหญ่เกิน 25 MB จึงข้ามไฟล์นี้'); continue; }
          const buf = await f.arrayBuffer();
          files.push({ name: f.name, size: f.size, head: [...new Uint8Array(buf.slice(0, 16))], sha256: await SC.Tools.sha256Hex(buf) });
        }
        const data = await loadData();
        const rowFor = new Map();
        const ctx = {
          ...data,
          config: { useLLM: useClaude.checked, llmEndpoint: CONFIG.llmEndpoint, reputationEndpoint: CONFIG.reputationEndpoint },
          onStep(s, phase) {
            let li = rowFor.get(s);
            if (!li) {
              li = el('li', {}, el('span', { class: 'dot' }), el('span', {}, el('b', { text: s.label }), el('div', { class: 'sum' })), el('span', { class: 'ms' }));
              rowFor.set(s, li);
              traceEl.append(li);
            }
            li.className = s.status;
            li.querySelector('.sum').textContent = s.summary;
            li.querySelector('.ms').textContent = phase === 'end' ? s.ms + ' ms' : '…';
          }
        };
        const result = await SC.Agent.runAgent({ text, phone, account, files }, ctx);
        sessionStorage.setItem(KEY_LAST, JSON.stringify(result));
        Memory.addHistory({
          id: String(Date.now()), ts: result.created_at, score: result.risk_score, level: result.risk_level, verdict: result.verdict,
          signals: result.signals.map((s) => s.id), preview: result.privacy.preview
        });
        postToSheet({ ts: result.created_at, score: result.risk_score, level: result.risk_level, verdict: result.verdict, signals: result.signals.map((s) => s.id), masked: result.privacy.masked_counts });
        location.href = 'result.html';
      } catch (e) {
        showError('เกิดข้อผิดพลาด: ' + (e && e.message ? e.message : e) + ' (ถ้าเปิดไฟล์ด้วย file:// ให้รันผ่านเซิร์ฟเวอร์ เช่น npx serve)');
        btn.disabled = false;
      }
    });
  }

  /* ===== หน้าผลลัพธ์ ===== */
  function renderGauge(score) {
    const r = 54, c = 2 * Math.PI * r;
    const off = c * (1 - score / 100);
    $('#gauge').innerHTML =
      '<svg viewBox="0 0 132 132" aria-hidden="true"><circle class="track" cx="66" cy="66" r="' + r + '" fill="none" stroke-width="12"/>' +
      '<circle class="bar" cx="66" cy="66" r="' + r + '" fill="none" stroke-width="12" stroke-linecap="round" stroke-dasharray="' + c.toFixed(1) + '" stroke-dashoffset="' + off.toFixed(1) + '"/></svg>' +
      '<div class="num"><span>' + Number(score) + '</span><small>/ 100</small></div>';
    $('#gauge').setAttribute('aria-label', 'คะแนนความเสี่ยง ' + score + ' จาก 100');
  }

  function warningMessage(r) {
    const lines = ['⚠️ เตือนภัย: ข้อความ/ลิงก์ที่ฉันได้รับถูกประเมินความเสี่ยง ' + r.risk_score + '/100 (' + r.risk_level_label + ')'];
    r.reasons.slice(0, 3).forEach((x) => lines.push('• ' + x));
    lines.push('อย่ากดลิงก์ อย่าโอนเงิน และอย่าบอกรหัส OTP หากเผลอทำไปแล้ว โทร 1441 และแจ้งธนาคารทันที');
    return lines.join('\n');
  }

  function initResult() {
    let r = null;
    try { r = JSON.parse(sessionStorage.getItem(KEY_LAST)); } catch (e) { /* ไม่มีผล */ }
    if (!r) { $('#empty').hidden = false; return; }

    const v = $('#verdict');
    v.hidden = false;
    v.classList.add(r.risk_level);
    renderGauge(r.risk_score);
    $('#level-badge').textContent = r.risk_level_label;
    $('#verdict-title').textContent = r.verdict_label;
    $('#verdict-sub').textContent = 'ความมั่นใจของระบบ ' + Math.round(r.confidence * 100) + '% • ' + (r.engine.llm_used ? 'วิเคราะห์ด้วยกฎ + RAG + Claude' : 'วิเคราะห์ด้วยกฎ + RAG ในเครื่อง');
    $('#disagree').hidden = !r.engine.disagreement;

    if (r.suspicious_urls.length) {
      $('#url-warnings').hidden = false;
      const box = $('#url-list');
      r.suspicious_urls.forEach((u) => {
        box.append(el('div', { class: 'url-card' },
          el('div', { class: 'u', text: u.url_defanged }),
          el('div', { class: 'warn', text: u.warning }),
          el('div', { class: 'hint', text: 'ความเสี่ยงของลิงก์ ' + u.risk + '/100' + (u.blacklisted ? ' • อยู่ใน blacklist' : '') }),
          el('ul', { class: 'list' }, u.reasons.map((x) => el('li', { text: x })))));
      });
      box.append(el('p', { class: 'hint', text: 'ลิงก์ถูกแสดงในรูปที่กดไม่ได้ (hxxp, [.]) เพื่อกันการเผลอคลิก' }));
    }

    $('#details').hidden = false;
    r.reasons.forEach((x) => $('#reasons').append(el('li', { text: x })));
    r.recommendations.forEach((x) => $('#recs').append(el('li', { text: x })));
    if (!r.signals.length) $('#signals').append(el('li', { class: 'chip', text: 'ไม่พบสัญญาณ' }));
    r.signals.forEach((s) => $('#signals').append(el('li', { class: 'chip' }, s.label, el('span', { class: 'w', text: s.weight.toFixed(2) }))));
    if (!r.knowledge_refs.length) $('#kb').append(el('li', { text: 'ไม่พบเอกสารที่เกี่ยวข้องในฐานความรู้' }));
    r.knowledge_refs.forEach((k) => $('#kb').append(el('li', { text: k.title + ' (คำที่ตรง: ' + k.matched_keywords.join(', ') + ')' })));

    if (r.blacklist_hits.length || r.file_findings.length) {
      $('#extras').hidden = false;
      const body = $('#extras-body');
      r.blacklist_hits.forEach((h) => body.append(el('p', { text: 'blacklist (' + h.kind + '): ' + (h.kind === 'domain' ? r.suspicious_urls.find((u) => u.blacklisted)?.host || h.value : h.value) + (h.demo ? ' [ข้อมูลตัวอย่าง]' : '') })));
      r.file_findings.forEach((f) => body.append(el('p', { text: 'ไฟล์ ' + f.name + ' • ประเภทจริง: ' + f.detected_type + ' • ' + (f.signals.length ? f.signals.map((s) => s.label).join('; ') : 'ไม่พบสัญญาณเสี่ยงจากชื่อ/ประเภทไฟล์') + (f.sha256 ? ' • SHA-256: ' + f.sha256.slice(0, 16) + '…' : '') })));
    }

    $('#privacy').hidden = false;
    $('#privacy-text').textContent = r.privacy.masked_total
      ? 'ปิดบังข้อมูลส่วนตัว ' + r.privacy.masked_total + ' รายการก่อนประมวลผลด้วย AI ' + (r.privacy.sent_to_ai ? '(ส่งให้ Claude เฉพาะข้อความที่ปิดบังแล้ว)' : '(ครั้งนี้ไม่ได้ส่งข้อความออกจากเครื่อง)')
      : 'ไม่พบข้อมูลส่วนตัวที่ต้องปิดบัง ' + (r.privacy.sent_to_ai ? '(ส่งข้อความให้ Claude)' : '(ครั้งนี้ไม่ได้ส่งข้อความออกจากเครื่อง)');
    $('#privacy-preview').textContent = r.privacy.preview;

    $('#trace-panel').hidden = false;
    r.trace.forEach((t) => $('#trace').append(el('li', { class: t.status }, el('span', { class: 'dot' }), el('span', {}, el('b', { text: t.label }), el('div', { class: 'sum', text: t.summary })), el('span', { class: 'ms', text: t.ms + ' ms' }))));

    $('#result-actions').hidden = false;
    $('#copy-warning').addEventListener('click', () => copyText(warningMessage(r)));
    $('#download-json').addEventListener('click', () => {
      const blob = new Blob([JSON.stringify(r, null, 2)], { type: 'application/json' });
      const a = el('a', { href: URL.createObjectURL(blob), download: 'scam-check-result.json' });
      document.body.append(a); a.click(); a.remove();
    });
  }

  /* ===== หน้าแจ้งเบาะแส ===== */
  function initReport() {
    const body = $('#report-rows');
    function render() {
      clear(body);
      const m = Memory.load();
      if (!m.reports.length) body.append(el('tr', {}, el('td', { colspan: '4', text: 'ยังไม่มีรายงาน' })));
      m.reports.forEach((r, i) => {
        const del = el('button', { class: 'btn ghost small', type: 'button', text: 'ลบ' });
        del.addEventListener('click', () => { const mm = Memory.load(); mm.reports.splice(i, 1); Memory.save(mm); render(); });
        body.append(el('tr', {}, el('td', { text: { domain: 'ลิงก์/โดเมน', phone: 'เบอร์โทร', account: 'เลขบัญชี' }[r.type] }), el('td', { class: 'mono', text: r.value }), el('td', { text: r.note || '-' }), el('td', {}, del)));
      });
    }
    render();
    $('#report-form').addEventListener('submit', (ev) => {
      ev.preventDefault();
      const type = $('#r-type').value;
      let value = $('#r-value').value.trim();
      const msg = $('#r-msg');
      if (!value) { msg.textContent = 'กรุณาใส่ค่าที่ต้องการรายงาน'; msg.hidden = false; return; }
      if (type === 'domain') {
        try { value = new URL(/^https?:\/\//i.test(value) ? value : 'http://' + value).hostname.toLowerCase(); } catch (e) { msg.textContent = 'รูปแบบลิงก์ไม่ถูกต้อง'; msg.hidden = false; return; }
      } else if (type === 'phone') value = SC.Tools.normalizePhone(value);
      else value = value.replace(/\D/g, '');
      const m = Memory.load();
      m.reports.unshift({ type, value, note: $('#r-note').value.trim().slice(0, 300), ts: new Date().toISOString() });
      Memory.save(m);
      $('#report-form').reset();
      msg.textContent = 'บันทึกแล้ว จะถูกใช้เทียบ blacklist บนเครื่องนี้';
      msg.hidden = false;
      render();
    });
    $('#export-reports').addEventListener('click', () => {
      const blob = new Blob([JSON.stringify(Memory.load().reports, null, 2)], { type: 'application/json' });
      const a = el('a', { href: URL.createObjectURL(blob), download: 'scam-reports.json' });
      document.body.append(a); a.click(); a.remove();
    });
  }

  /* ===== หน้าแอดมิน ===== */
  function initAdmin() {
    const m = Memory.load();
    const h = m.history;
    const avg = h.length ? Math.round(h.reduce((s, x) => s + x.score, 0) / h.length) : 0;
    const stat = (n, l) => el('div', { class: 'stat' }, el('div', { class: 'n', text: n }), el('div', { class: 'l', text: l }));
    $('#stats').append(stat(h.length, 'การตรวจทั้งหมด'), stat(h.filter((x) => x.score >= 50).length, 'น่าจะเป็น Scam (≥50)'), stat(avg, 'คะแนนเฉลี่ย'), stat(m.reports.length, 'รายงานเบาะแส'));

    const bars = (root, rows) => {
      const max = Math.max(1, ...rows.map((r) => r[1]));
      rows.forEach(([label, n]) => root.append(el('div', { class: 'bar-row' }, el('span', { text: label }), el('div', { class: 'bar-track' }, el('div', { class: 'bar-fill', style: 'width:' + (n / max) * 100 + '%' })), el('span', { class: 'mono', text: n }))));
      if (!rows.length) root.append(el('p', { class: 'hint', text: 'ยังไม่มีข้อมูล' }));
    };
    bars($('#level-bars'), SC.Scoring.LEVELS.map((l) => [l.label, h.filter((x) => x.level === l.key).length]));
    const counts = {};
    h.forEach((x) => x.signals.forEach((s) => { if (!s.startsWith('url:') && !s.startsWith('file:')) counts[s] = (counts[s] || 0) + 1; }));
    const labelOf = Object.fromEntries(SC.Signals.PATTERNS.map((p) => [p.id, p.label]));
    bars($('#signal-bars'), Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([id, n]) => [labelOf[id] || id, n]));

    const body = $('#history-rows');
    if (!h.length) body.append(el('tr', {}, el('td', { colspan: '4', text: 'ยังไม่มีประวัติการตรวจ' })));
    h.slice(0, 50).forEach((x) => body.append(el('tr', {}, el('td', { text: fmtTime(x.ts) }), el('td', { class: 'mono', text: x.score }), el('td', { text: (SC.Scoring.LEVELS.find((l) => l.key === x.level) || {}).label || x.level }), el('td', { text: x.preview }))));

    $('#export-all').addEventListener('click', () => {
      const blob = new Blob([JSON.stringify(Memory.load(), null, 2)], { type: 'application/json' });
      const a = el('a', { href: URL.createObjectURL(blob), download: 'scamchecker-memory.json' });
      document.body.append(a); a.click(); a.remove();
    });
    $('#clear-all').addEventListener('click', () => { $('#confirm-box').hidden = false; });
    $('#confirm-no').addEventListener('click', () => { $('#confirm-box').hidden = true; });
    $('#confirm-yes').addEventListener('click', () => { try { localStorage.removeItem(KEY_MEM); sessionStorage.removeItem(KEY_LAST); } catch (e) { /* ignore */ } location.reload(); });
  }

  const init = { home: initHome, check: initCheck, result: initResult, report: initReport, admin: initAdmin }[page];
  if (init) init();
})();
