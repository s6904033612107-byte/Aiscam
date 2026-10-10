# Scam Checker — เว็บตรวจจับและป้องกันสแกมเมอร์

โปรเจกต์วิชา **ปัญญาประดิษฐ์กับวิถีชีวิตใหม่ (040603005)** รูปแบบผลงาน Web (UI & Dashboard) ที่ใช้ **RAG + Agent + Skill**

ผู้ใช้วางข้อความ ลิงก์ เบอร์ เลขบัญชี หรือแนบไฟล์ แล้วได้ 6 อย่าง
1. ข้อความนี้เป็น Scam หรือไม่
2. คะแนนความเสี่ยง 0-100
3. เหตุผลที่ทำให้เสี่ยง
4. สัญญาณ Scam ที่ตรวจพบ
5. สิ่งที่ควรทำ
6. คำเตือนเมื่อพบลิงก์หรือข้อมูลน่าสงสัย (ไม่ควรคลิก ไม่ควรให้ข้อมูลส่วนตัว)

---

## โครงสร้างโฟลเดอร์และหน้าที่ของแต่ละไฟล์

```
scam-checker/
├── index.html            หน้าแรก: แนะนำระบบ ตัวอย่างข้อความให้ลอง
├── check.html            หน้าตรวจสอบ: กรอกข้อความ/เบอร์/บัญชี/แนบไฟล์ ดูตัวอย่างข้อความที่ปิดบังแล้ว และดูขั้นตอน Agent สด
├── result.html           หน้าผลลัพธ์: คะแนน เหตุผล สัญญาณ คำแนะนำ คำเตือนลิงก์ ปุ่มคัดลอกข้อความเตือน/ดาวน์โหลด JSON
├── report.html           หน้าแจ้งเบาะแสมิจฉาชีพ (เก็บในเครื่อง ใช้เทียบ blacklist รอบต่อไป)
├── admin.html            แดชบอร์ดหลังบ้าน: สถิติ ประวัติ ส่งออก/ล้าง Memory
├── style.css             ธีมทั้งเว็บ (รองรับโหมดมืด)
├── script.js             ตัวเชื่อม UI ทุกหน้า + Memory แบบ JSON (localStorage) + ส่งผลไป Google Sheet (ไม่บังคับ)
│
├── js/                   ตรรกะหลัก (รันได้ทั้งเบราว์เซอร์และ Node)
│   ├── anonymize.js      ปิดบังข้อมูลส่วนตัวก่อนส่งให้ AI
│   ├── signals.js        กฎตรวจสัญญาณ Scam ในข้อความ (23 สัญญาณ)
│   ├── rag.js            RAG: ค้นฐานความรู้ด้วย keyword + trigram
│   ├── tools.js          เครื่องมือของ Agent: ดึง URL, ตรวจลิงก์, blacklist, ตรวจไฟล์ + SHA-256, defang
│   ├── scoring.js        รวมหลักฐานเป็นคะแนน 0-100, เหตุผล, คำแนะนำ, ตรวจผลจาก Claude
│   └── agent.js          Agentic loop 10 ขั้น พร้อม trace
│
├── api/                  Vercel serverless (key อยู่ฝั่งเซิร์ฟเวอร์)
│   ├── analyze.js        เรียก Claude API ด้วย System Prompt + RAG + ผลจากกฎ
│   ├── url-reputation.js Google Safe Browsing / VirusTotal (ไม่บังคับ)
│   └── _utils.js         rate limit และฟังก์ชันช่วย
│
├── data/
│   ├── knowledge-base.json   ฐานความรู้ RAG (รูปแบบการหลอกลวงในไทย)
│   ├── blacklist.json        รายการเฝ้าระวัง (ตอนนี้เป็นข้อมูลตัวอย่าง demo)
│   ├── url-rules.json        กฎตรวจลิงก์: แบรนด์/โดเมนทางการ ลิงก์ย่อ TLD เสี่ยง
│   └── samples.json          ข้อความตัวอย่างสมมติ + ช่วงคะแนนที่คาดหวัง
│
├── prompts/
│   ├── system-prompt.md      ★ System Prompt ที่ใช้จริง (RCTF + XML tags)
│   └── prompt-iterations.md  บันทึกการปรับ Prompt, Context Window, กัน Hallucination
├── skills/
│   ├── scam-triage/SKILL.md
│   ├── url-inspector/SKILL.md
│   └── privacy-anonymizer/SKILL.md
├── CLAUDE.md             ★ ไฟล์ควบคุม Agent/Project ใน Claude
├── docs/
│   ├── proposal.md       ★ Midterm Proposal (สัปดาห์ 9)
│   └── google-apps-script.gs   (ไม่บังคับ) รับผลตรวจลง Google Sheet
├── tests/run-tests.js    ทดสอบ: npm test
├── vercel.json  package.json  .env.example  .gitignore
```

> ที่เทียบกับเทมเพลตเดิม: `products.json` → `data/*.json`, `product.html` → `check.html`, `order.html` + `thankyou.html` → `result.html`, `admin.html` เหมือนเดิม, `images/` ยังไม่จำเป็น (เพิ่มโฟลเดอร์ไว้ใส่โลโก้/ภาพประกอบภายหลังได้)

---

## รันในเครื่อง

```bash
npm test          # ทดสอบระบบตรวจ (ไม่ต้องใช้ API key)
npm run dev       # เปิดเว็บ (npx serve .) แล้วเข้า http://localhost:3000
```
ต้องเปิดผ่านเซิร์ฟเวอร์ ห้ามดับเบิลคลิกเปิดไฟล์ เพราะหน้าเว็บโหลดไฟล์ JSON ด้วย fetch

## Deploy

**A) GitHub Pages (ง่ายสุด ใช้กฎ + RAG + blacklist ในเครื่อง)**
1. สร้าง repo แล้ว push ทั้งโฟลเดอร์
2. Settings → Pages → Deploy from branch → `main` / root
3. ฟีเจอร์ Claude และ Safe Browsing/VirusTotal จะถูกข้ามอัตโนมัติ (หน้าแสดงสถานะ "ข้าม" ในขั้นตอนของ Agent)

**B) Vercel (ใช้ Claude ได้ครบ)**
1. push ขึ้น GitHub แล้ว Import project ใน Vercel (ไม่ต้องตั้ง Build command)
2. Settings → Environment Variables ใส่ `ANTHROPIC_API_KEY` (และ `ANTHROPIC_MODEL` ถ้าต้องการเปลี่ยนรุ่น)
3. ใส่ `GOOGLE_SAFE_BROWSING_KEY` / `VIRUSTOTAL_API_KEY` ถ้าต้องการตรวจลิงก์/ไฟล์กับบริการภายนอก
4. Redeploy

อย่า commit key ขึ้น GitHub และอย่าใส่ key ในไฟล์ฝั่งหน้าเว็บ

---

## วิธีทำงาน (สำหรับนำเสนอ)

```
ข้อความ/ลิงก์/ไฟล์
   │
   ▼
[Agent ในเบราว์เซอร์]  1 anonymize → 2 ดึง URL/เบอร์/บัญชี → 3 ตรวจลิงก์ → 4 blacklist
                       → 5 ตรวจสัญญาณ → 6 RAG → 7 ตรวจไฟล์ → 8 Safe Browsing/VirusTotal*
   │                                                          → 9 Claude* → 10 รวมคะแนน
   ▼
ผลลัพธ์ JSON → หน้า result.html
(* ทำงานเมื่อ deploy บน Vercel และตั้ง key เท่านั้น)
```

- **คะแนน**: รวมแบบ noisy-OR (สัญญาณหลายตัวรวมกันสูงขึ้นแต่ไม่เกิน 100) หักสัญญาณลดความเสี่ยงสูงสุด 40% พบ blacklist/มัลแวร์ล็อกขั้นต่ำ 85
- **เมื่อมี Claude**: ถ่วงน้ำหนัก 60% กฎ + 40% Claude ถ้าสองฝั่งต่างกัน ≥40 คะแนนจะเตือนผู้ใช้ให้ตรวจเพิ่ม
- **ระดับ**: 0-24 ต่ำ • 25-49 ควรระวัง • 50-74 เสี่ยงสูง • 75-100 อันตรายมาก

## ให้ตรงเกณฑ์อาจารย์ (30 คะแนน)

| หัวข้อ | หลักฐานในโปรเจกต์ |
|---|---|
| วิเคราะห์ปัญหา (3) | `docs/proposal.md` ข้อ 1 |
| เลือกใช้เครื่องมือ (3) | `docs/proposal.md` ข้อ 2 (Artifacts/Web, Agent, RAG, Skill, Memory JSON, MCP แผนต่อยอด) |
| ออกแบบ Prompt RCTF + XML (4) | `docs/proposal.md` ข้อ 3 และ `prompts/system-prompt.md` |
| ความสมบูรณ์ของระบบ (9) | ทั้งเว็บ ใช้งานได้จริง สาธิตผ่าน `check.html` → `result.html` พร้อมแสดง trace ของ Agent |
| คุณภาพของ Prompt (6) | `prompts/prompt-iterations.md` (ต้องกรอกผลทดสอบ Claude จริงในหัวข้อ 4 ก่อนส่ง) + `validateLLM` ใน `js/scoring.js` |
| จริยธรรมข้อมูล (2) | `js/anonymize.js`, ช่อง "ข้อความที่จะถูกส่งให้ AI" ใน `check.html`, ส่วน "ความเป็นส่วนตัว" ใน `result.html` |
| ไฟล์แนบ & นำเสนอ (3) | `prompts/system-prompt.md`, `CLAUDE.md`, `skills/` |

**สิ่งที่ต้องทำเองก่อนส่ง**: รันกับ Claude API จริงแล้วกรอกตารางผลทดสอบ, ตรวจรายชื่อโดเมนทางการใน `data/url-rules.json`, เปลี่ยนข้อมูลใน `data/blacklist.json` เป็นข้อมูลจริงจากแหล่งที่เชื่อถือได้

## ฟีเจอร์เสริมที่ทำให้แล้ว
- **ดูตัวอย่างข้อความก่อนส่งให้ AI** (โปร่งใสเรื่องข้อมูลส่วนตัว)
- **แสดงลิงก์แบบ defang** (`hxxp://x[.]top`) กันเผลอคลิก
- **ตรวจไฟล์**: นามสกุลซ้อน (`.pdf.exe`), ไฟล์ที่เนื้อในเป็นโปรแกรมแต่ตั้งชื่อเป็นรูป (magic bytes), SHA-256 เทียบ blacklist
- **คัดลอกข้อความเตือน** ส่งให้ญาติ/เพื่อน
- **แจ้งเบาะแส** เก็บในเครื่องและใช้เทียบตอนตรวจครั้งถัดไป
- **แดชบอร์ด** สถิติ สัญญาณที่พบบ่อย ส่งออก JSON
- **Google Sheet** (ไม่บังคับ) บันทึกเฉพาะคะแนนและสัญญาณ ไม่มีข้อความ

## ไอเดียต่อยอด (ยังไม่ได้ทำ)
- อ่านภาพแชต/สลิป/QR ด้วย Claude vision (ต้องระวังข้อมูลส่วนตัวในภาพ)
- ต่อ blacklist กลางผ่าน **MCP server** หรือฐานข้อมูล (Supabase) เพื่อให้รายงานใช้ร่วมกันหลายคน
- LINE bot / Chrome extension ให้ตรวจได้ทันทีโดยไม่ต้องคัดลอก
- โหมดฝึกจับ Scam (แบบทดสอบจากข้อความตัวอย่าง) สำหรับผู้สูงอายุ
- เพิ่มระบบล็อกอินให้หน้า admin เมื่อใช้ข้อมูลหลายผู้ใช้

## ข้อจำกัดที่ควรบอกในการนำเสนอ
- เป็นระบบประเมินความเสี่ยง ไม่ใช่การตัดสินทางกฎหมาย และรับรองว่าปลอดภัย 100% ไม่ได้
- กฎตรวจจับตามรูปแบบที่รู้จัก มิจฉาชีพรูปแบบใหม่อาจหลุด จึงมี RAG และ Claude เป็นชั้นเสริม
- การปิดบังชื่อบุคคลเป็น heuristic อาจพลาดหรือจับเกิน
- ข้อมูล blacklist ในรีโปเป็นตัวอย่าง ยังไม่ใช่ข้อมูลจริง
- หน้า admin และ Memory อยู่ใน localStorage ของเบราว์เซอร์ ไม่ใช่ฐานข้อมูลกลาง
