#include <SPI.h>
#include <MFRC522.h>
#include <TFT_eSPI.h>
#include <XPT2046_Touchscreen.h>
#include <Preferences.h>
#include <string.h>
#include <ctype.h>

// SPI المشترك: CLK=18, MISO=19, MOSI=23؛ خرج SDO للشاشة مفصول.
#define RFID_CS 21
#define RFID_RST 22
#define TFT_CS_PIN 27
#define TOUCH_CS_PIN 33

// ================== 02 - كائنات العتاد والتخزين ==================
MFRC522 rfid(RFID_CS, RFID_RST);   // قارئ MIFARE/ISO14443-A
TFT_eSPI tft = TFT_eSPI();         // شاشة ILI9488 حسب إعداد User_Setup.h
XPT2046_Touchscreen touch(TOUCH_CS_PIN);
Preferences cards;                 // nfc_cards: السجلات الأصلية
Preferences goodReads;             // nfc_good: آخر قراءة مؤكدة لكل UID محفوظ
Preferences touchPrefs;            // touch_ui: المعايرة المثبتة سابقًا
Preferences backupPrefs;           // test_backup: نسخة أولى + آخر نسخة قبل كتابة
MFRC522::MIFARE_Key keyA;

// ================== 03 - حالات الواجهة والمتغيرات ==================
enum Page {
  HOME, READ_CARD, MEMORY, ANALYZE, SAVED_LIST, SAVED_DETAIL,
  SETTINGS, DEMO, ACTION_CONFIRM, ACTION_WAIT, ACTION_RESULT
};
Page page = HOME;
Page returnPage = HOME;
int cardCount = 0;
int savedPage = 0;
int selectedRecord = -1;
int demoStep = 0;
byte selectedBlock = 4;            // نقرأ كتل بيانات Sector 1 فقط
byte firmware = 0;
byte lastSAK = 0;
byte lastUidSize = 0;
String lastATQA = "-";
String lastUID = "";
String lastType = "";
String lastHex = "-";
String lastStatus = "WAITING";
String actionStatus = "";
bool detailOriginal = false;       // تبديل العرض: الأصل أو آخر قراءة مؤكدة
bool restoring = false;            // false = كتابة / true = استعادة
bool cardRemovedAfterConfirm = false;
bool wasTouched = false;
unsigned long lastTap = 0;
unsigned long lastScan = 0;
int rx0 = 0, ry0 = 0, rx1 = 0, ry1 = 0;

// ================== 04 - بطاقة الاختبار الوحيدة المسموح بالكتابة عليها ==================
// هذه هوية بطاقة تدريب شخصية؛ UID ليس إثبات ملكية أو وسيلة أمان.
const byte trainingUID[4] = {0x49, 0x09, 0x7E, 0x29};
const byte trainingData[16] = {
  'N','F','C',' ','T','E','S','T',' ','2','0','2','6',0,0,0
};

// ================== 05 - دوال مساعدة: SPI، النصوص، السجلات ==================
void idleSPI() {
  digitalWrite(RFID_CS, HIGH);
  digitalWrite(TFT_CS_PIN, HIGH);
  digitalWrite(TOUCH_CS_PIN, HIGH);
}

String toHex(const byte *data, byte count) {
  String value = "";
  for (byte i = 0; i < count; i++) {
    if (data[i] < 16) value += "0";
    value += String(data[i], HEX);
  }
  value.toUpperCase();
  return value;
}

// بيانات Hex إلى نص ASCII للعرض فقط؛ النقاط تعني بايتات غير مطبوعة.
String hexAsText(const String &hex) {
  String result = "";
  for (int i = 0; i + 1 < (int)hex.length(); i += 2) {
    char c = (char)strtoul(hex.substring(i, i + 2).c_str(), nullptr, 16);
    result += (c >= 32 && c <= 126) ? c : '.';
  }
  return result;
}

// تحليل 16 بايت Hex للتحقق من أن النسخة الاحتياطية ليست بيانات تالفة.
bool decode16(const String &hex, byte *out) {
  if (hex.length() != 32) return false;
  for (int i = 0; i < 16; i++) {
    char a = hex[i * 2], b = hex[i * 2 + 1];
    if (!isxdigit((unsigned char)a) || !isxdigit((unsigned char)b)) return false;
    out[i] = (byte)strtoul(hex.substring(2 * i, 2 * i + 2).c_str(), nullptr, 16);
  }
  return true;
}

// استخراج حقل من سجل UID|TYPE|DATA|STATUS مع دعم السجلات القديمة ذات 3 حقول.
String fieldAt(const String &record, int part) {
  int begin = 0;
  for (int i = 0; i < part; i++) {
    int bar = record.indexOf('|', begin);
    if (bar < 0) return "";
    begin = bar + 1;
  }
  int end = record.indexOf('|', begin);
  return end < 0 ? record.substring(begin) : record.substring(begin, end);
}

String recordKey(int index) { return "card" + String(index); }
String goodKey(int index) { return "ok" + String(index); }
String originalRecord(int index) {
  if (index < 0 || index >= cardCount) return "";
  String key = recordKey(index);
  return cards.getString(key.c_str(), "");
}
String verifiedRecord(int index) {
  String key = goodKey(index);
  String newer = goodReads.getString(key.c_str(), "");
  String original = originalRecord(index);
  // لا نقبل ترقية تنتمي إلى UID مختلف أو بيانات ليست 16 بايت.
  if (newer.length() && fieldAt(newer, 0) == fieldAt(original, 0) &&
      fieldAt(newer, 2).length() == 32 && fieldAt(newer, 3) == "READ_OK") {
    return newer;
  }
  return original;
}

// ================== 06 - الرسم: أزرار واضحة وكتابة صغيرة لا تخرج من الشاشة ==================
void button(int x, int y, int w, int h, const char *label, uint16_t color) {
  digitalWrite(RFID_CS, HIGH);
  digitalWrite(TOUCH_CS_PIN, HIGH);
  tft.fillRoundRect(x, y, w, h, 7, color);
  tft.setTextColor(TFT_WHITE, color);
  tft.drawCentreString(label, x + w / 2, y + (h - 16) / 2, 2);
}

bool inside(int x, int y, int bx, int by, int bw, int bh) {
  return x >= bx && x < bx + bw && y >= by && y < by + bh;
}

void textLine(int y, const String &label, const String &value) {
  tft.setCursor(16, y);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.print(label);
  tft.println(value.substring(0, 33));
}

void hexLines(int y, const String &hex) {
  if (hex.length() != 32) return;
  textLine(y, "HEX: ", hex.substring(0, 16));
  textLine(y + 22, "     ", hex.substring(16));
  textLine(y + 44, "ASCII: ", hexAsText(hex));
}

// ================== 07 - رسم صفحة واحدة حسب حالة البرنامج ==================
void drawPage() {
  digitalWrite(RFID_CS, HIGH);
  digitalWrite(TOUCH_CS_PIN, HIGH);
  tft.fillScreen(TFT_BLACK);
  tft.setTextFont(2);
  tft.setTextSize(1);
  tft.setTextColor(TFT_CYAN, TFT_BLACK);
  tft.drawCentreString("NFC SECURITY FLIPPER", 240, 12, 2);
  tft.drawFastHLine(10, 40, 460, TFT_DARKGREY);

  if (page == HOME) {
    button(16, 54, 215, 60, "READ CARD", TFT_DARKCYAN);
    button(249, 54, 215, 60, "SAVED CARDS", TFT_DARKCYAN);
    button(16, 126, 215, 60, "MEMORY", TFT_DARKGREEN);
    button(249, 126, 215, 60, "ANALYZE", TFT_DARKGREEN);
    button(16, 198, 215, 60, "EMULATION DEMO", TFT_DARKGREY);
    button(249, 198, 215, 60, "SETTINGS", TFT_DARKGREY);
    textLine(282, "Reader/Writer only", "");
    return;
  }

  if (page == READ_CARD) {
    textLine(60, "READ CARD: ", "Present a test card");
    textLine(91, "UID: ", lastUID.length() ? lastUID : "WAITING");
    textLine(119, "TYPE: ", lastType);
    textLine(147, "BLOCK 4: ", lastStatus);
    hexLines(176, lastHex);
  }
  else if (page == MEMORY) {
    textLine(52, "SECTOR 1: ", "Choose data block");
    button(16, 82, 102, 38, "BLOCK 4", selectedBlock == 4 ? TFT_DARKGREEN : TFT_DARKGREY);
    button(127, 82, 102, 38, "BLOCK 5", selectedBlock == 5 ? TFT_DARKGREEN : TFT_DARKGREY);
    button(238, 82, 102, 38, "BLOCK 6", selectedBlock == 6 ? TFT_DARKGREEN : TFT_DARKGREY);
    textLine(125, "UID: ", lastUID.length() ? lastUID : "WAITING");
    textLine(148, "STATUS: ", lastStatus);
    hexLines(171, lastHex);
    button(245, 246, 103, 30, "WRITE TEST", TFT_MAROON);
    button(358, 246, 106, 30, "RESTORE", TFT_DARKGREY);
  }
  else if (page == ANALYZE) {
    textLine(54, "CARD ANALYSIS", "");
    textLine(80, "UID: ", lastUID.length() ? lastUID : "Scan in READ");
    textLine(105, "TYPE: ", lastType);
    textLine(130, "UID BYTES: ", String(lastUidSize));
    textLine(155, "SAK: 0x", String(lastSAK, HEX));
    textLine(180, "ATQA: ", lastATQA);
    textLine(205, "LAST READ: ", lastStatus);
    textLine(232, "INFO: ", "Block read != full card dump");
  }
  else if (page == SAVED_LIST) {
    textLine(52, "SAVED: ", String(cardCount) + "  PAGE: " + String(savedPage + 1));
    for (int i = savedPage * 5; i < cardCount && i < savedPage * 5 + 5; i++) {
      String entry = originalRecord(i);
      int y = 83 + (i - savedPage * 5) * 32;
      button(16, y, 448, 29, (String(i + 1) + ". " + fieldAt(entry, 0)).c_str(), TFT_DARKGREY);
    }
    button(158, 249, 115, 32, "PREV", TFT_DARKGREY);
    button(290, 249, 115, 32, "NEXT", TFT_DARKGREY);
  }
  else if (page == SAVED_DETAIL) {
    String rec = detailOriginal ? originalRecord(selectedRecord) : verifiedRecord(selectedRecord);
    textLine(55, "RECORD #", String(selectedRecord + 1));
    textLine(80, "VIEW: ", detailOriginal ? "ORIGINAL HISTORY" : "BEST VERIFIED / ORIGINAL");
    textLine(105, "UID: ", fieldAt(rec, 0));
    textLine(130, "TYPE: ", fieldAt(rec, 1));
    String status = fieldAt(rec, 3);
    textLine(155, "STATUS: ", status.length() ? status : "OLD FORMAT");
    hexLines(179, fieldAt(rec, 2));
    button(267, 246, 195, 30, "TOGGLE HISTORY", TFT_DARKCYAN);
  }
  else if (page == SETTINGS) {
    textLine(56, "DEVICE SETTINGS", "");
    textLine(88, "RC522 FIRMWARE: 0x", String(firmware, HEX));
    textLine(116, "SAVED RECORDS: ", String(cardCount));
    textLine(144, "GPIO: ", "SPI 18/19/23 | CS 21/27/33");
    button(18, 195, 213, 55, "EXPORT SERIAL", TFT_DARKCYAN);
    button(249, 195, 213, 55, "CALIBRATE", TFT_DARKGREY);
  }
  else if (page == DEMO) {
    textLine(54, "EMULATION DEMO", "");
    textLine(83, "Software Simulation Only", "");
    textLine(105, "NOT REAL NFC CARD EMULATION", "");
    String uid = lastUID.length() ? lastUID : (cardCount ? fieldAt(originalRecord(0), 0) : "NO CARD DATA");
    textLine(135, "DEMO UID: ", uid);
    const char *steps[] = {
      "1/4 Load stored UID",
      "2/4 Virtual reader requests tag",
      "3/4 Software displays UID",
      "4/4 No RF transmission occurs"
    };
    textLine(176, "STEP: ", steps[demoStep]);
    button(254, 227, 208, 48, "NEXT DEMO STEP", TFT_DARKCYAN);
  }
  else if (page == ACTION_CONFIRM) {
    textLine(60, restoring ? "RESTORE BACKUP" : "WRITE TRAINING DATA", "");
    textLine(94, "CARD UID: ", "49097E29 ONLY");
    textLine(126, "TARGET: ", "SECTOR 1 / BLOCK 4");
    textLine(159, "CHANGES DATA ON REAL TAG", "");
    button(244, 216, 218, 50, restoring ? "CONFIRM RESTORE" : "CONFIRM WRITE", TFT_MAROON);
  }
  else if (page == ACTION_WAIT) {
    textLine(60, restoring ? "RESTORE ARMED" : "WRITE ARMED", "");
    textLine(95, "REMOVE ALL CARDS FIRST", "");
    textLine(125, "THEN PRESENT UID 49097E29", "");
    textLine(172, "STATUS: ", actionStatus);
    textLine(210, "HOME cancels before action", "");
  }
  else if (page == ACTION_RESULT) {
    textLine(68, restoring ? "RESTORE RESULT" : "WRITE RESULT", "");
    textLine(110, "STATUS: ", actionStatus);
    hexLines(151, lastHex);
  }

  button(12, 280, 124, 36, "BACK", TFT_BLUE);
}

// ================== 08 - معايرة اللمس: نفس نقطتي Core V3 مع مهلة آمنة ==================
void drawCalibrationMark(int x, int y) {
  digitalWrite(RFID_CS, HIGH);
  digitalWrite(TOUCH_CS_PIN, HIGH);
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setCursor(25, 148);
  tft.println("Touch the magenta cross");
  tft.drawFastHLine(x - 15, y, 31, TFT_MAGENTA);
  tft.drawFastVLine(x, y - 15, 31, TFT_MAGENTA);
  tft.drawCircle(x, y, 19, TFT_MAGENTA);
}

bool takeCalibrationPoint(TS_Point &point) {
  unsigned long started = millis();
  digitalWrite(RFID_CS, HIGH);
  digitalWrite(TFT_CS_PIN, HIGH);
  while (touch.touched() && millis() - started < 25000) delay(15);
  while (!touch.touched() && millis() - started < 25000) delay(15);
  if (millis() - started >= 25000) return false;
  delay(65);
  point = touch.getPoint();
  while (touch.touched() && millis() - started < 25000) delay(15);
  Serial.print("CAL RAW X: "); Serial.print(point.x);
  Serial.print(" Y: "); Serial.println(point.y);
  return true;
}

bool calibrateTouch() {
  drawCalibrationMark(35, 35);
  TS_Point a, b;
  if (!takeCalibrationPoint(a)) return false;
  drawCalibrationMark(445, 285);
  if (!takeCalibrationPoint(b)) return false;
  if (abs(b.x - a.x) < 400 || abs(b.y - a.y) < 400) return false;

  // valid يُكتب أخيرًا: لا نعلن نجاح حفظ المعايرة حتى نتأكد من القيم.
  touchPrefs.putBool("valid", false);
  bool saved = touchPrefs.putInt("rx0", a.x) == 4 &&
               touchPrefs.putInt("ry0", a.y) == 4 &&
               touchPrefs.putInt("rx1", b.x) == 4 &&
               touchPrefs.putInt("ry1", b.y) == 4;
  if (!saved) return false;
  rx0 = a.x; ry0 = a.y; rx1 = b.x; ry1 = b.y;
  bool ok = touchPrefs.putBool("valid", true) == 1;
  Serial.println(ok ? "CALIBRATION SAVED" : "CALIBRATION SAVE FAILED");
  return ok;
}

// ================== 09 - حفظ سجل جديد مع الحفاظ على السجلات التاريخية ==================
// nfc_cards لا يُستبدل عندما يكون UID مكررًا؛ نستخدم nfc_good لآخر قراءة ناجحة.
void saveScan(const String &uid, const String &type, const String &hex, const String &status) {
  String current = uid + "|" + type + "|" + hex + "|" + status;
  for (int i = 0; i < cardCount; i++) {
    if (fieldAt(originalRecord(i), 0) != uid) continue;
    if (status == "READ_OK" && hex.length() == 32) {
      String key = goodKey(i);
      if (goodReads.getString(key.c_str(), "") != current) {
        if (goodReads.putString(key.c_str(), current) == current.length()) {
          Serial.println("LATEST VERIFIED READ SAVED");
        } else Serial.println("LATEST READ SAVE FAILED");
      }
    }
    Serial.println("EXISTING UID - ORIGINAL RECORD PRESERVED");
    return;
  }

  if (cardCount >= 10) { Serial.println("NVS RECORD LIMIT: 10"); return; }
  String key = recordKey(cardCount);
  if (cards.putString(key.c_str(), current) != current.length()) {
    Serial.println("NEW CARD SAVE FAILED");
    return;
  }
  cardCount++;
  if (cards.putUInt("count", cardCount) != 4) Serial.println("COUNT SAVE WARNING");
  Serial.println("NEW CARD SAVED");
}

// ================== 10 - قراءة بيانات MIFARE Classic 1K بعد المصادقة ==================
String readBlock(byte block, String &status) {
  if (rfid.PICC_GetType(rfid.uid.sak) != MFRC522::PICC_TYPE_MIFARE_1K) {
    status = "UNSUPPORTED_TYPE";
    return "-";
  }
  MFRC522::StatusCode rc = rfid.PCD_Authenticate(
    MFRC522::PICC_CMD_MF_AUTH_KEY_A, 7, &keyA, &rfid.uid
  );
  if (rc != MFRC522::STATUS_OK) { status = "AUTH_FAILED"; return "-"; }
  byte bytes[18];  // 16 بيانات + 2 CRC حسب واجهة المكتبة
  byte size = sizeof(bytes);
  rc = rfid.MIFARE_Read(block, bytes, &size);
  if (rc != MFRC522::STATUS_OK || size < 16) { status = "READ_FAILED"; return "-"; }
  status = "READ_OK";
  return toHex(bytes, 16);
}

// ================== 11 - النسخ الاحتياطي قبل الكتابة (NVS فقط) ==================
// أول نسخة محفوظة لا نستبدلها؛ النسخة الأخيرة تُحدّث قبل كل كتابة جديدة.
bool hasBackup(const char *key) {
  byte ignored[16];
  return decode16(backupPrefs.getString(key, ""), ignored);
}

bool storePrewriteBackup(const String &oldHex) {
  byte ignored[16];
  if (!decode16(oldHex, ignored)) return false;

  // احترام النسخة الأولى الموجودة من الإصدار السابق إذا كانت سليمة.
  bool firstValid = backupPrefs.getBool("ok", false) &&
                    backupPrefs.getString("uid", "") == "49097E29" &&
                    hasBackup("data");
  if (!firstValid) {
    backupPrefs.putBool("ok", false);
    if (backupPrefs.putString("uid", "49097E29") != 8 ||
        backupPrefs.putString("data", oldHex) != 32 ||
        backupPrefs.getString("data", "") != oldHex ||
        backupPrefs.putBool("ok", true) != 1) return false;
  }

  backupPrefs.putBool("lastOK", false);
  if (backupPrefs.putString("last", oldHex) != 32 ||
      backupPrefs.getString("last", "") != oldHex ||
      backupPrefs.putBool("lastOK", true) != 1) return false;
  return backupPrefs.getBool("lastOK", false) &&
         backupPrefs.getString("last", "") == oldHex;
}

// ================== 12 - كتابة/استعادة على بطاقة التدريب فقط وبعد تأكيد المستخدم ==================
void performTrainingAction() {
  lastHex = "-";
  if (rfid.uid.size != 4 || memcmp(rfid.uid.uidByte, trainingUID, 4) != 0 ||
      rfid.PICC_GetType(rfid.uid.sak) != MFRC522::PICC_TYPE_MIFARE_1K) {
    actionStatus = "WRONG CARD - NOT WRITTEN";
    Serial.println(actionStatus);
    return; // ما زلنا ننتظر بطاقة التدريب؛ لا نكتب شيئًا.
  }
  page = ACTION_RESULT; // إجراء واحد فقط لكل تأكيد، حتى لو بقيت البطاقة فوق الهوائي.
  byte payload[16];
  if (restoring) {
    if (!backupPrefs.getBool("lastOK", false) ||
        !decode16(backupPrefs.getString("last", ""), payload)) {
      actionStatus = "NO VERIFIED BACKUP";
      Serial.println(actionStatus);
      return;
    }
  } else memcpy(payload, trainingData, 16);

  MFRC522::StatusCode rc = rfid.PCD_Authenticate(
    MFRC522::PICC_CMD_MF_AUTH_KEY_A, 7, &keyA, &rfid.uid
  );
  if (rc != MFRC522::STATUS_OK) { actionStatus = "AUTH_FAILED"; return; }
  byte oldBytes[18];
  byte size = sizeof(oldBytes);
  rc = rfid.MIFARE_Read(4, oldBytes, &size);
  if (rc != MFRC522::STATUS_OK || size < 16) {
    actionStatus = "BACKUP READ FAILED"; return;
  }
  String oldHex = toHex(oldBytes, 16);

  if (!restoring) {
    if (!storePrewriteBackup(oldHex)) {
      actionStatus = "BACKUP SAVE FAILED"; return;
    }
  } else {
    // قبل الاستعادة نحفظ الحالة الحالية في خانة مستقلة، دون إتلاف last.
    backupPrefs.putBool("restoreOK", false);
    if (backupPrefs.putString("preRestore", oldHex) != 32 ||
        backupPrefs.getString("preRestore", "") != oldHex ||
        backupPrefs.putBool("restoreOK", true) != 1) {
      actionStatus = "BACKUP SAVE FAILED"; return;
    }
  }

  Serial.print("BEFORE: "); Serial.println(oldHex);
  rc = rfid.MIFARE_Write(4, payload, 16);
  if (rc != MFRC522::STATUS_OK) { actionStatus = "WRITE_FAILED"; return; }
  byte after[18]; size = sizeof(after);
  rc = rfid.MIFARE_Read(4, after, &size);
  if (rc == MFRC522::STATUS_OK && size >= 16 && memcmp(after, payload, 16) == 0) {
    lastHex = toHex(after, 16);
    lastStatus = "READ_OK";
    actionStatus = restoring ? "RESTORE_VERIFY_OK" : "WRITE_VERIFY_OK";
    // السجل التاريخي لا يتغير؛ نحدّث فقط النسخة المؤكدة بعد إعادة القراءة.
    saveScan(lastUID, lastType, lastHex, "READ_OK");
  } else actionStatus = "WRITE_NOT_VERIFIED";
  Serial.print("ACTION RESULT: "); Serial.println(actionStatus);
}

// ================== 13 - تصدير NVS عبر Serial (ليس إلى SD) ==================
void exportSerial() {
  Serial.println("=== CARD EXPORT | ORIGINAL + BEST VERIFIED ===");
  for (int i = 0; i < cardCount; i++) {
    Serial.print("ORIGINAL "); Serial.print(i + 1); Serial.print(": ");
    Serial.println(originalRecord(i));
    Serial.print("VERIFIED "); Serial.print(i + 1); Serial.print(": ");
    Serial.println(verifiedRecord(i));
  }
  Serial.println("=== EXPORT END ===");
}

// ================== 14 - لمس الأزرار: كل زر يؤدي إلى وظيفة حقيقية ==================
void handleTap(int x, int y) {
  if (page == HOME) {
    if (inside(x, y, 16, 54, 215, 60)) {
      page = READ_CARD;
      lastUID = ""; lastType = ""; lastHex = "-"; lastStatus = "WAITING";
    }
    else if (inside(x, y, 249, 54, 215, 60)) { page = SAVED_LIST; savedPage = 0; }
    else if (inside(x, y, 16, 126, 215, 60)) {
      page = MEMORY; selectedBlock = 4;
      lastUID = ""; lastType = ""; lastHex = "-"; lastStatus = "WAITING";
    }
    else if (inside(x, y, 249, 126, 215, 60)) page = ANALYZE;
    else if (inside(x, y, 16, 198, 215, 60)) { page = DEMO; demoStep = 0; }
    else if (inside(x, y, 249, 198, 215, 60)) page = SETTINGS;
    else return;
  }
  else if (inside(x, y, 12, 280, 124, 36)) {
    if (page == SAVED_DETAIL) page = SAVED_LIST;
    else page = HOME;  // BACK يلغي انتظار الكتابة قبل عرض البطاقة.
  }
  else if (page == SAVED_LIST) {
    if (inside(x, y, 158, 249, 115, 32) && savedPage > 0) savedPage--;
    else if (inside(x, y, 290, 249, 115, 32) && (savedPage + 1) * 5 < cardCount) savedPage++;
    else if (x >= 16 && x < 464 && y >= 83 && y < 243) {
      int row = (y - 83) / 32;
      int index = savedPage * 5 + row;
      if (index < cardCount) { selectedRecord = index; detailOriginal = false; page = SAVED_DETAIL; }
      else return;
    } else return;
  }
  else if (page == SAVED_DETAIL) {
    if (inside(x, y, 267, 246, 195, 30)) detailOriginal = !detailOriginal;
    else return;
  }
  else if (page == MEMORY) {
    if (inside(x, y, 16, 82, 102, 38)) selectedBlock = 4;
    else if (inside(x, y, 127, 82, 102, 38)) selectedBlock = 5;
    else if (inside(x, y, 238, 82, 102, 38)) selectedBlock = 6;
    else if (inside(x, y, 245, 246, 103, 30)) { restoring = false; page = ACTION_CONFIRM; }
    else if (inside(x, y, 358, 246, 106, 30)) { restoring = true; page = ACTION_CONFIRM; }
    else return;
    lastHex = "-"; lastStatus = "SCAN AGAIN";
  }
  else if (page == ACTION_CONFIRM) {
    if (inside(x, y, 244, 216, 218, 50)) {
      page = ACTION_WAIT;
      actionStatus = "REMOVE CARD FIRST";
      cardRemovedAfterConfirm = false;
    } else return;
  }
  else if (page == SETTINGS) {
    if (inside(x, y, 18, 195, 213, 55)) exportSerial();
    else if (inside(x, y, 249, 195, 213, 55)) {
      bool calibrated = calibrateTouch();
      Serial.println(calibrated ? "CALIBRATION OK" : "CALIBRATION FAILED");
      page = HOME;
    } else return;
  }
  else if (page == DEMO) {
    if (inside(x, y, 254, 227, 208, 48)) demoStep = (demoStep + 1) % 4;
    else return;
  }
  else return;
  drawPage();
}

// ================== 15 - setup: بدء القطع بالترتيب الذي أثبت نجاحه ==================
void setup() {
  Serial.begin(115200);
  delay(500);
  pinMode(RFID_CS, OUTPUT);
  pinMode(TFT_CS_PIN, OUTPUT);
  pinMode(TOUCH_CS_PIN, OUTPUT);
  idleSPI();
  SPI.begin(18, 19, 23);
  tft.init();
  tft.setRotation(1);
  touch.begin();
  touch.setRotation(1);
  idleSPI();
  rfid.PCD_Init();
  delay(100);
  rfid.PCD_AntennaOn();
  firmware = rfid.PCD_ReadRegister(MFRC522::VersionReg);
  for (byte i = 0; i < 6; i++) keyA.keyByte[i] = 0xFF;

  cards.begin("nfc_cards", false);
  goodReads.begin("nfc_good", false);
  touchPrefs.begin("touch_ui", false);
  backupPrefs.begin("test_backup", false);

  // استرجاع العدد من المفاتيح الفعلية عند حدوث انقطاع أثناء حفظ count.
  cardCount = 0;
  for (int i = 0; i < 10; i++) {
    String key = recordKey(i);
    if (cards.getString(key.c_str(), "").length() == 0) break;
    cardCount = i + 1;
  }
  if (cards.getUInt("count", 0) != (unsigned)cardCount) cards.putUInt("count", cardCount);

  Serial.println("=== NFC SECURITY FLIPPER / FINAL ===");
  Serial.print("RC522 FW: 0x"); Serial.println(firmware, HEX);
  Serial.print("SAVED RECORDS: "); Serial.println(cardCount);
  Serial.println("CARD EMULATION: NOT SUPPORTED BY HARDWARE");

  if (touchPrefs.getBool("valid", false)) {
    rx0 = touchPrefs.getInt("rx0", 0);
    ry0 = touchPrefs.getInt("ry0", 0);
    rx1 = touchPrefs.getInt("rx1", 0);
    ry1 = touchPrefs.getInt("ry1", 0);
  }
  if (abs(rx1 - rx0) < 400 || abs(ry1 - ry0) < 400) {
    if (!calibrateTouch()) Serial.println("TOUCH CALIBRATION REQUIRED");
  }
  drawPage();
}

// ================== 16 - loop: لمس، بحث، قراءة/كتابة؛ بدون حجز طويل ==================
void loop() {
  digitalWrite(RFID_CS, HIGH);
  digitalWrite(TFT_CS_PIN, HIGH);
  bool nowTouched = touch.touched();
  if (nowTouched && !wasTouched && millis() - lastTap >= 260) {
    TS_Point p = touch.getPoint();
    if (abs(rx1 - rx0) >= 400 && abs(ry1 - ry0) >= 400) {
      int x = constrain(map(p.x, rx0, rx1, 35, 445), 0L, 479L);
      int y = constrain(map(p.y, ry0, ry1, 35, 285), 0L, 319L);
      handleTap(x, y);
    }
    lastTap = millis();
  }
  wasTouched = nowTouched;

  if (page != READ_CARD && page != MEMORY && page != ACTION_WAIT) return;
  if (millis() - lastScan < 160) return;
  lastScan = millis();
  digitalWrite(TFT_CS_PIN, HIGH);
  digitalWrite(TOUCH_CS_PIN, HIGH);

  byte atqa[2]; byte atqaSize = sizeof(atqa);
  MFRC522::StatusCode request = rfid.PICC_RequestA(atqa, &atqaSize);
  if (request != MFRC522::STATUS_OK) {
    if (page == ACTION_WAIT && !cardRemovedAfterConfirm) {
      cardRemovedAfterConfirm = true;
      actionStatus = "PLACE TRAINING TAG";
      drawPage();
    }
    return;
  }
  if (!rfid.PICC_ReadCardSerial()) return;
  lastUID = toHex(rfid.uid.uidByte, rfid.uid.size);
  lastType = rfid.PICC_GetTypeName(rfid.PICC_GetType(rfid.uid.sak));
  lastUidSize = rfid.uid.size;
  lastSAK = rfid.uid.sak;
  lastATQA = toHex(atqa, atqaSize);

  if (page == ACTION_WAIT) {
    if (cardRemovedAfterConfirm) performTrainingAction();
    else actionStatus = "REMOVE CARD FIRST";
    rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();
    drawPage();
    return;
  }

  byte block = page == READ_CARD ? 4 : selectedBlock;
  String status = "WAITING";
  String data = readBlock(block, status);
  lastHex = data;
  lastStatus = status;

  Serial.print("UID: "); Serial.println(lastUID);
  Serial.print("TYPE: "); Serial.println(lastType);
  Serial.print("BLOCK: "); Serial.print(block);
  Serial.print(" STATUS: "); Serial.println(status);
  if (status == "READ_OK") { Serial.print("HEX: "); Serial.println(data); }
  // قاعدة تنسيق NVS: الحقل الثالث هو Block 4، لا نحفظ Block 5 أو 6 مكانه.
  if (block == 4) saveScan(lastUID, lastType, data, status);

  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1();
  drawPage();
}
