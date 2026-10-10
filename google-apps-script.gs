/**
 * (ไม่บังคับ) บันทึกผลตรวจที่ "ไม่มีข้อความต้นฉบับ" ลง Google Sheet
 * วิธีใช้: เปิด Google Sheet > ส่วนขยาย > Apps Script > วางโค้ดนี้ > Deploy เป็น Web app
 *         (Execute as: Me, Who has access: Anyone) แล้วนำ URL ไปใส่ CONFIG.sheetWebhook ใน script.js
 * หัวคอลัมน์ที่แนะนำในแถวแรก: ts | score | level | verdict | signals | masked
 * ข้อมูลที่ส่งมามีเฉพาะ: เวลา คะแนน ระดับ สัญญาณ จำนวนข้อมูลที่ถูกปิดบัง (ไม่มีข้อความ ลิงก์ เบอร์ หรือเลขบัญชี)
 */
function doPost(e) {
  var sheet = SpreadsheetApp.getActiveSpreadsheet().getActiveSheet();
  var d = JSON.parse(e.postData.contents);
  sheet.appendRow([
    d.ts, d.score, d.level, d.verdict,
    (d.signals || []).join(','),
    JSON.stringify(d.masked || {})
  ]);
  return ContentService.createTextOutput('ok');
}
