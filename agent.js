/**
 * agent.js — Agentic loop ของ Scam Checker
 *
 * Agent ทำงานเป็นลำดับ "เครื่องมือ" (tool) ทีละขั้น บันทึก trace ทุกขั้นเพื่อให้ผู้ใช้/อาจารย์ตรวจสอบได้
 *   1 anonymize        ปิดบังข้อมูลส่วนตัว (ก่อนส่งอะไรออกจากเครื่อง)
 *   2 extract          ดึง URL / เบอร์โทร / เลขบัญชี
 *   3 inspect_urls     ตรวจลิงก์ด้วยกฎ
 *   4 check_blacklist  เทียบ blacklist
 *   5 detect_signals   ตรวจสัญญาณ Scam ในข้อความ
 *   6 retrieve_kb      RAG ดึงความรู้ที่เกี่ยวข้อง
 *   7 inspect_files    ตรวจไฟล์ที่แนบ
 *   8 url_reputation   (เสริม) Google Safe Browsing / VirusTotal ผ่าน /api/url-reputation
 *   9 llm_review       (เสริม) ให้ Claude สรุปเหตุผลผ่าน /api/analyze โดยส่งเฉพาะข้อความที่ anonymize แล้ว
 *  10 aggregate        รวมคะแนน 0-100 + เหตุผล + คำแนะนำ
 * ขั้น 8-9 ข้ามอัตโนมัติถ้าไม่ได้ตั้งค่า (เช่น รันบน GitHub Pages) ระบบยังทำงานได้ด้วยกฎในเครื่อง
 */
(function (root) {
  'use strict';
  const isNode = typeof module !== 'undefined' && module.exports;
  const dep = (name, file) => (isNode ? require(file) : root.ScamChecker[name]);
  const Anonymize = dep('Anonymize', './anonymize.js');
  const Signals = dep('Signals', './signals.js');
  const Tools = dep('Tools', './tools.js');
  const Scoring = dep('Scoring', './scoring.js');

  const MAX_STEPS = 12;
  const MAX_TEXT = 6000;

  async function postJSON(url, body, timeoutMs, fetchImpl) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await (fetchImpl || fetch)(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: ctrl.signal
      });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      return await res.json();
    } finally {
      clearTimeout(timer);
    }
  }

  const stripQuery = (u) => String(u).split(/[?#]/)[0];

  /**
   * @param input {text, phone, account, files:[{name,size,head,sha256}]}
   * @param ctx   {kb, blacklist, rules, config:{offline,useLLM,llmEndpoint,reputationEndpoint}, onStep}
   */
  async function runAgent(input, ctx) {
    const cfg = ctx.config || {};
    const trace = [];
    let steps = 0;

    async function step(tool, label, fn) {
      if (++steps > MAX_STEPS) throw new Error('เกินจำนวนขั้นตอนสูงสุดของ Agent');
      const s = { tool, label, status: 'running', ms: 0, summary: '' };
      trace.push(s);
      if (ctx.onStep) ctx.onStep(s, 'start');
      const t0 = Date.now();
      let out = null;
      try {
        out = await fn();
        s.status = out && out.skipped ? 'skipped' : 'ok';
        s.summary = (out && out.summary) || '';
      } catch (e) {
        s.status = 'error';
        s.summary = String((e && e.message) || e);
      }
      s.ms = Date.now() - t0;
      if (ctx.onStep) ctx.onStep(s, 'end');
      return out && out.value !== undefined ? out.value : null;
    }

    const rawText = String(input.text || '').slice(0, MAX_TEXT);
    const manualPhone = input.phone ? Tools.normalizePhone(input.phone) : '';
    const manualAccount = input.account ? String(input.account).replace(/\D/g, '') : '';
    const files = input.files || [];

    // 1) anonymize
    const anon = await step('anonymize', 'ปิดบังข้อมูลส่วนตัว', async () => {
      const a = Anonymize.anonymize(rawText);
      return { value: a, summary: a.total ? 'ปิดบัง ' + a.total + ' รายการ (' + Object.keys(a.counts).join(', ') + ')' : 'ไม่พบข้อมูลส่วนตัวที่ต้องปิดบัง' };
    }) || { text: '', map: [], counts: {}, total: 0 };

    // 2) extract
    const extracted = await step('extract', 'ดึงลิงก์ เบอร์โทร และเลขบัญชี', async () => {
      const urls = Tools.extractUrls(rawText, ctx.rules);
      const phones = Tools.extractPhones(rawText);
      if (manualPhone && !phones.includes(manualPhone)) phones.push(manualPhone);
      const accounts = Tools.extractAccounts(rawText);
      if (manualAccount && !accounts.includes(manualAccount)) accounts.push(manualAccount);
      return { value: { urls, phones, accounts }, summary: urls.length + ' ลิงก์, ' + phones.length + ' เบอร์, ' + accounts.length + ' บัญชี' };
    }) || { urls: [], phones: [], accounts: [] };

    // 3) inspect urls
    const urlFindings = await step('inspect_urls', 'ตรวจลิงก์', async () => {
      if (!extracted.urls.length) return { skipped: true, value: [], summary: 'ไม่พบลิงก์' };
      const res = extracted.urls.map((u) => Tools.inspectUrl(u, ctx.rules));
      const bad = res.filter((r) => r.risk >= 0.3).length;
      return { value: res, summary: 'ตรวจ ' + res.length + ' ลิงก์ น่าสงสัย ' + bad };
    }) || [];

    // 4) blacklist
    const fileHashes = files.map((f) => f.sha256).filter(Boolean);
    const blacklistHits = await step('check_blacklist', 'เทียบ blacklist', async () => {
      const hits = Tools.checkBlacklist({ hosts: urlFindings.map((u) => u.host).filter(Boolean), phones: extracted.phones, accounts: extracted.accounts, hashes: fileHashes }, ctx.blacklist);
      return { value: hits, summary: hits.length ? 'พบ ' + hits.length + ' รายการ' : 'ไม่พบใน blacklist' };
    }) || [];

    // 5) signals
    const sig = await step('detect_signals', 'ตรวจสัญญาณ Scam', async () => {
      const r = Signals.detectSignals(rawText);
      return { value: r, summary: 'พบ ' + r.signals.length + ' สัญญาณ' };
    }) || { signals: [], reducers: [] };

    // 6) RAG
    const knowledge = await step('retrieve_kb', 'RAG: ค้นความรู้ที่เกี่ยวข้อง', async () => {
      if (!ctx.kb) return { skipped: true, value: [], summary: 'ไม่ได้โหลดฐานความรู้' };
      const docs = ctx.kb.retrieve(rawText, 3);
      return { value: docs, summary: docs.length ? docs.map((d) => d.title).join(' | ') : 'ไม่พบเอกสารที่เกี่ยวข้อง' };
    }) || [];

    // 7) files
    const fileFindings = await step('inspect_files', 'ตรวจไฟล์ที่แนบ', async () => {
      if (!files.length) return { skipped: true, value: [], summary: 'ไม่มีไฟล์' };
      const res = files.map((f) => Tools.analyzeFile(f));
      return { value: res, summary: 'ตรวจ ' + res.length + ' ไฟล์ เสี่ยง ' + res.filter((r) => r.risk > 0).length };
    }) || [];

    // 8) reputation (optional)
    const reputation = await step('url_reputation', 'Google Safe Browsing / VirusTotal', async () => {
      if (cfg.offline || !cfg.reputationEndpoint || (!extracted.urls.length && !fileHashes.length)) {
        return { skipped: true, value: [], summary: 'ข้าม (ไม่ได้ตั้งค่า API หรือไม่มีลิงก์/ไฟล์)' };
      }
      const data = await postJSON(cfg.reputationEndpoint, { urls: extracted.urls.slice(0, 10), hashes: fileHashes.slice(0, 5) }, 15000, ctx.fetch);
      if (!data || !data.configured || (!data.configured.gsb && !data.configured.vt)) return { skipped: true, value: [], summary: 'เซิร์ฟเวอร์ยังไม่ได้ใส่ API key' };
      return { value: data.results || [], summary: 'ตรวจ ' + (data.results || []).length + ' รายการ' };
    }) || [];

    // ผลระหว่างทาง (ใช้ส่งให้ Claude เป็นบริบท และใช้เป็นคะแนนฝั่งกฎ)
    const interim = Scoring.finalize({ signals: sig.signals, reducers: sig.reducers, urlFindings, blacklistHits, fileFindings, reputation, knowledge, llm: null });

    // 9) LLM (optional)
    const llm = await step('llm_review', 'Claude: วิเคราะห์และสรุปเหตุผล', async () => {
      if (cfg.offline || !cfg.useLLM || !cfg.llmEndpoint) return { skipped: true, value: null, summary: 'ข้าม (ใช้ผลวิเคราะห์ในเครื่อง)' };
      const payload = {
        text: anon.text.slice(0, 4000),
        urls: extracted.urls.slice(0, 10).map(stripQuery),
        local: { score: interim.risk_score, signals: interim.signals.slice(0, 8).map((s) => ({ id: s.id, label: s.label, weight: s.weight })) },
        knowledge: knowledge.map((k) => ({ id: k.id, title: k.title, description: k.description, indicators: k.indicators, advice: k.advice }))
      };
      const data = await postJSON(cfg.llmEndpoint, payload, 30000, ctx.fetch);
      const allowedHosts = urlFindings.map((u) => u.host).filter(Boolean);
      const valid = Scoring.validateLLM(data && data.result, allowedHosts);
      if (!valid) throw new Error('ผลจาก Claude ไม่อยู่ในรูปแบบที่กำหนด จึงไม่นำมาใช้');
      return { value: valid, summary: 'ได้คะแนน ' + valid.risk_score + '/100 จาก Claude' };
    });

    // 10) aggregate
    const result = await step('aggregate', 'รวมคะแนนและสรุปผล', async () => {
      const r = Scoring.finalize({ signals: sig.signals, reducers: sig.reducers, urlFindings, blacklistHits, fileFindings, reputation, knowledge, llm });
      return { value: r, summary: 'คะแนน ' + r.risk_score + '/100 (' + r.risk_level_label + ')' };
    });

    const finalResult = result || interim;
    return {
      ...finalResult,
      privacy: { anonymized: true, masked_total: anon.total, masked_counts: anon.counts, sent_to_ai: !!(llm && cfg.useLLM), preview: anon.text.slice(0, 300) },
      trace: trace.map((t) => ({ tool: t.tool, label: t.label, status: t.status, ms: t.ms, summary: t.summary })),
      created_at: new Date().toISOString()
    };
  }

  const api = { runAgent };
  if (isNode) module.exports = api;
  else (root.ScamChecker = root.ScamChecker || {}).Agent = api;
})(typeof window !== 'undefined' ? window : globalThis);
