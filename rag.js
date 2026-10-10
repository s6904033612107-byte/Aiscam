/**
 * rag.js — RAG แบบเบา ทำงานในเบราว์เซอร์ (ไม่ต้องใช้ vector database)
 * Retrieve: คะแนน = keyword ที่ตรง + ความคล้ายแบบ character-trigram cosine (เหมาะกับภาษาไทยที่ไม่มีช่องว่างคั่นคำ)
 * Augment : ผลลัพธ์ (title / description / advice) ถูกส่งให้ Claude เป็น <retrieved_knowledge> เพื่อลดการเดา (hallucination)
 * ข้อมูลอยู่ใน data/knowledge-base.json — เพิ่มเอกสารใหม่ได้โดยไม่ต้องแก้โค้ด
 */
(function (root) {
  'use strict';
  const isNode = typeof module !== 'undefined' && module.exports;

  const normalize = (s) => String(s || '').normalize('NFKC').toLowerCase().replace(/[​-‍﻿]/g, '').replace(/\s+/g, ' ').trim();

  function trigrams(s) {
    const t = normalize(s);
    const m = new Map();
    for (let i = 0; i <= t.length - 3; i++) {
      const g = t.slice(i, i + 3);
      m.set(g, (m.get(g) || 0) + 1);
    }
    return m;
  }

  function cosine(a, b) {
    let dot = 0, na = 0, nb = 0;
    for (const [, v] of a) na += v * v;
    for (const [, v] of b) nb += v * v;
    for (const [k, v] of a) if (b.has(k)) dot += v * b.get(k);
    return na && nb ? dot / Math.sqrt(na * nb) : 0;
  }

  class KnowledgeBase {
    constructor(docs) {
      this.docs = (docs || []).map((d) => ({
        ...d,
        _vec: trigrams([d.title, d.description, (d.keywords || []).join(' '), (d.indicators || []).join(' ')].join(' '))
      }));
    }

    retrieve(text, k = 3, minScore = 1.2) {
      const q = normalize(text);
      if (!q) return [];
      const qv = trigrams(q);
      const scored = this.docs.map((d) => {
        const hits = [];
        let kw = 0;
        for (const word of d.keywords || []) {
          const w = normalize(word);
          if (w && q.includes(w)) {
            hits.push(word);
            kw += Math.min(3, Math.max(1, w.length / 4));
          }
        }
        const sim = cosine(qv, d._vec);
        return { doc: d, hits, score: kw + sim * 3 };
      });
      return scored
        .filter((s) => s.hits.length > 0 && s.score >= minScore)
        .sort((a, b) => b.score - a.score)
        .slice(0, k)
        .map((s) => ({
          id: s.doc.id,
          title: s.doc.title,
          category: s.doc.category,
          description: s.doc.description,
          indicators: s.doc.indicators,
          advice: s.doc.advice,
          matched_keywords: s.hits,
          score: Math.round(s.score * 100) / 100
        }));
    }
  }

  const api = { KnowledgeBase, normalize };
  if (isNode) module.exports = api;
  else (root.ScamChecker = root.ScamChecker || {}).Rag = api;
})(typeof window !== 'undefined' ? window : globalThis);
