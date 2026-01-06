
/*  =====================  GATEWAY_FRIOMAMUT_MQTT.ino  =====================
    Basado en TU último código “funciona de perlas”.
    Cambios: SOLO remodelación del submenú CONFIG (y su plumbing) SIN romper nada.
    + Añadido:
      - Factory reset de configuración (NVS namespace "gwcfg") con botón BOOT (GPIO0) por pulsación larga.
      - LED integrado como STATUS (patrones para ventana de reset y estado WiFi/MQTT).
      - NO borra firmware/particiones. Solo limpia configuración del gateway.

    Requisito: types.h (el tuyo) en el mismo folder.
*/

#include "types.h"

#include <WiFi.h>
#include <WebServer.h>
#include <Preferences.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>

#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

#include <Crypto.h>
#include <AES.h>
#include <EAX.h>

#include "esp_system.h"
#include "nvs_flash.h"   // para nvs (Arduino-ESP32)

// ===================== Botón + LED (STATUS + Factory reset) =====================
// En ESP32-S3, el botón BOOT suele estar en GPIO0.
#define BOOT_PIN 0

// AJUSTA LED_PIN si tu placa usa otro GPIO para el LED integrado.
// En muchos "ESP32-S3 Super Mini" chinos suele ser 21, pero puede variar.
#ifndef LED_PIN
  #define LED_PIN 21  //21
#endif

// Algunos LEDs integrados son activos en LOW. Si ves el LED invertido, cambia:
#ifndef LED_ON
  #define LED_ON  LOW
  #define LED_OFF HIGH
#endif

// Pulsación larga para factory reset (ms)
static const uint32_t FACTORY_HOLD_MS   = 3000;
// Ventana tras arranque para aceptar factory reset (ms)
static const uint32_t FACTORY_WINDOW_MS = 6000;

// Estado interno LED (no bloqueante)

// Forward declaration (mqtt se declara más abajo)
extern PubSubClient mqtt;

static uint32_t led_next_ms = 0;
static uint8_t  led_phase = 0;
static bool     led_enabled = true;

// Patrones LED:
// - Durante ventana factory reset: parpadeo lento.
// - Detectado hold: parpadeo rápido.
// - Normal:
//    * WiFi NO conectado: blink lento.
//    * WiFi conectado, MQTT NO: doble blink periódico.
//    * WiFi conectado, MQTT SI: blink corto periódico.
static void ledWrite(bool on) {
  digitalWrite(LED_PIN, on ? LED_ON : LED_OFF);
}

static void ledBlinkBlocking(int times, int on_ms, int off_ms) {
  for (int i = 0; i < times; i++) {
    ledWrite(true);  delay(on_ms);
    ledWrite(false); delay(off_ms);
  }
}

static void clearGatewayConfigNamespace() {
  // Limpia SOLO el namespace de este proyecto (gwcfg)
  Preferences p;
  if (p.begin("gwcfg", false)) {
    p.clear();
    p.end();
  }
}

// Se llama muy temprano en setup, antes de loadConfig()
static void checkFactoryResetAtBoot() {
  pinMode(BOOT_PIN, INPUT_PULLUP);

  uint32_t t0 = millis();
  // Ventana corta para detectar intención del usuario.
  while (millis() - t0 < FACTORY_WINDOW_MS) {
    // Parpadeo lento (ventana activa)
    ledWrite(true);  delay(120);
    ledWrite(false); delay(380);

    if (digitalRead(BOOT_PIN) == LOW) {
      uint32_t tHold = millis();

      // Mientras lo mantenga, indica "armado" con parpadeo más rápido
      while (digitalRead(BOOT_PIN) == LOW) {
        ledWrite(true);  delay(70);
        ledWrite(false); delay(70);

        if (millis() - tHold >= FACTORY_HOLD_MS) {
          // Confirmación visual: LED fijo breve
          ledWrite(true); delay(600);
          ledWrite(false);

          // Reset de fábrica de configuración
          clearGatewayConfigNamespace();

          // Señal "hecho": 3 destellos
          ledBlinkBlocking(3, 120, 120);

          // Reboot limpio
          ESP.restart();
        }
      }
    }
  }

  // Fin de ventana: destello corto de “arranque OK”
  ledBlinkBlocking(1, 180, 120);
}

// LED de estado NO bloqueante (llamar en loop)
static void statusLedTick() {
  if (!led_enabled) return;
  uint32_t now = millis();
  if ((int32_t)(now - led_next_ms) < 0) return;

  bool wifi_ok = (WiFi.status() == WL_CONNECTED);
  bool mqtt_ok = mqtt.connected();

  if (!wifi_ok) {
    // blink lento: ON 120ms / OFF 880ms
    if (led_phase == 0) { ledWrite(true);  led_next_ms = now + 120; led_phase = 1; }
    else                { ledWrite(false); led_next_ms = now + 880; led_phase = 0; }
    return;
  }

  if (wifi_ok && !mqtt_ok) {
    // doble blink cada ~2s: ON 80 / OFF 120 / ON 80 / OFF 1720
    switch (led_phase) {
      case 0: ledWrite(true);  led_next_ms = now + 80;  led_phase = 1; break;
      case 1: ledWrite(false); led_next_ms = now + 120; led_phase = 2; break;
      case 2: ledWrite(true);  led_next_ms = now + 80;  led_phase = 3; break;
      default: ledWrite(false); led_next_ms = now + 1720; led_phase = 0; break;
    }
    return;
  }

  // wifi_ok && mqtt_ok
  // blink corto cada ~2s: ON 60 / OFF 1940
  if (led_phase == 0) { ledWrite(true);  led_next_ms = now + 60;   led_phase = 1; }
  else                { ledWrite(false); led_next_ms = now + 1940; led_phase = 0; }
}

// ===================== Protocolo nodo =====================
static const uint8_t PROTO_VER = 0x01;

// Clave de grupo AES-128 (igual en nodos)
static const uint8_t GROUP_KEY[16] = {
  0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
  0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10
};

// ===================== Tamaños =====================
static const uint8_t SLOT_COUNT = 16;
static const uint8_t ADV_LEN    = 23;

// ===================== AP (gestión) =====================
static const char* AP_SSID = "BLE-GW";
static const char* AP_PASS = "";

// ===================== Defaults MQTT =====================
static const char* MQTT_HOST_DEFAULT = "192.168.0.200";
static const uint16_t MQTT_PORT_DEFAULT = 1883;
static const char* MQTT_BASE_DEFAULT = "mp/tunel_01";
static const char* MQTT_USER_DEFAULT = "";
static const char* MQTT_PASS_DEFAULT = "";

// ===================== Logger circular =====================
static char logbuf[4096];
static volatile size_t log_head = 0;

static void logln(const char* s) {
  while (*s) {
    logbuf[log_head] = *s++;
    log_head = (log_head + 1) % sizeof(logbuf);
  }
  logbuf[log_head] = '\n';
  log_head = (log_head + 1) % sizeof(logbuf);
}

static String getLogString() {
  String out;
  out.reserve(sizeof(logbuf) + 32);
  size_t start = log_head;
  for (size_t i = 0; i < sizeof(logbuf); i++) {
    char c = logbuf[(start + i) % sizeof(logbuf)];
    if (c == 0) continue;
    out += c;
  }
  return out;
}

// ===================== Diagnóstico =====================
static volatile uint32_t cnt_adv_raw         = 0;
static volatile uint32_t cnt_dec_ok          = 0;
static volatile uint32_t cnt_dec_fail        = 0;
static volatile uint32_t cnt_replay_drop     = 0;
static volatile uint32_t cnt_pub_ok          = 0;
static volatile uint32_t cnt_pub_fail        = 0;
static volatile uint32_t cnt_mqtt_conn_ok    = 0;
static volatile uint32_t cnt_mqtt_conn_fail  = 0;
static volatile uint32_t cnt_unassigned_drop = 0;

// ===================== Globales =====================
WebServer server(80);
Preferences prefs;

WiFiClient espClient;
PubSubClient mqtt(espClient);

EAX<AES128> eax;

static QueueHandle_t advQ;
static BLEScan* pScan = nullptr;

// Config (NVS)
static String wifiSsid;
static String wifiPass;

static String mqttHost;
static uint16_t mqttPort;
static String mqttBase;
static String mqttUser;
static String mqttPasswd;

// Slots (16)
static SlotState slots[SLOT_COUNT];

// ===================== Helpers UI =====================
static void noCacheHeaders() {
  server.sendHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
  server.sendHeader("Pragma", "no-cache");
  server.sendHeader("Expires", "0");
}

static String htmlEscape(const String& s) {
  String o; o.reserve(s.length() + 16);
  for (auto c : s) {
    switch (c) {
      case '&': o += "&amp;"; break;
      case '<': o += "&lt;"; break;
      case '>': o += "&gt;"; break;
      case '"': o += "&quot;"; break;
      default:  o += c; break;
    }
  }
  return o;
}

static String navBtn(const char* href, const char* label, bool active, bool primary=false) {
  String s;
  s += "<a href='"; s += href; s += "' style='padding:8px 12px;border:1px solid #ccc;border-radius:12px;";
  s += "text-decoration:none;";
  if (active) s += "background:#111;color:#fff;border-color:#111;font-weight:600;";
  else if (primary) s += "background:#f7f7f7;color:#111;font-weight:600;";
  else s += "background:#f7f7f7;color:#111;";
  s += "'>"; s += label; s += "</a>";
  return s;
}

static String navBar(const String& active) {
  String h;
  h += "<div style='display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:0 0 14px 0'>";
  h += navBtn("/",        "Home",   active=="home",   true);
  h += navBtn("/devices", "Devices",active=="devices");
  h += navBtn("/stat.html","Stat",   active=="stat");
  h += navBtn("/log.html", "Log",    active=="log");
  h += navBtn("/info.html","Info",   active=="info");
  h += navBtn("/config",  "Config", active=="config");
  h += "</div>";
  return h;
}

static String pageWrap(const String& title, const String& active, const String& bodyHtml, uint32_t refreshMs=0) {
  String h;
  h += "<!doctype html><html><head><meta charset='utf-8'>"
       "<meta name='viewport' content='width=device-width,initial-scale=1'>"
       "<title>" + title + "</title>"
       "<style>"
       "body{font-family:system-ui;margin:20px;max-width:980px}"
       "h2{margin:0 0 12px 0}"
       ".card{border:1px solid #ddd;border-radius:16px;padding:14px;background:#fff;box-shadow:0 1px 2px rgba(0,0,0,.05);margin:12px 0}"
       ".muted{opacity:.75}"
       ".ok{background:#e9f7ee;border-color:#bfe6c9}"
       ".warn{background:#fff5e6;border-color:#ffe0a6}"
       ".bad{background:#ffecec;border-color:#ffbfbf}"
       "pre{padding:12px;border:1px solid #ddd;border-radius:12px;background:#fafafa;overflow:auto}"
       "code{background:#f2f2f2;padding:2px 6px;border-radius:6px}"
       "input,textarea{width:100%;padding:10px;border:1px solid #ccc;border-radius:12px;box-sizing:border-box}"
       "button{padding:10px 14px;border:1px solid #ccc;border-radius:12px;background:#111;color:#fff;cursor:pointer}"
       ".btn2{padding:10px 14px;border:1px solid #ccc;border-radius:12px;background:#f7f7f7;color:#111;text-decoration:none;display:inline-block}"
       "table{width:100%;border-collapse:separate;border-spacing:0}"
       "th,td{padding:10px;border-bottom:1px solid #eee;text-align:left}"
       "th{position:sticky;top:0;background:#fff}"
       ".badge{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid #ddd;background:#f7f7f7;font-size:12px}"
       "</style>"
       "</head><body>";
  h += navBar(active);
  h += bodyHtml;
  if (refreshMs) {
    h += "<script>(function(){setTimeout(function(){location.reload();},";
    h += String(refreshMs);
    h += ");})();</script>";
  }
  h += "</body></html>";
  return h;
}

static String badge(const String& t, const char* cls=nullptr) {
  String s = "<span class='badge";
  if (cls) { s += " "; s += cls; }
  s += "'>";
  s += htmlEscape(t);
  s += "</span>";
  return s;
}

static String fmt2(float v, int decimals) {
  char b[24];
  dtostrf(v, 0, decimals, b);
  return String(b);
}

// ===================== Helpers =====================
static int slotIndexForDev(uint16_t dev_id) {
  if (dev_id == 0) return -1;
  for (int i = 0; i < SLOT_COUNT; i++) {
    if (slots[i].dev_id == dev_id) return i;
  }
  return -1;
}

static bool antiReplayOK(SlotState& s, uint32_t boot_id, uint32_t ctr24) {
  if (boot_id > s.last_boot_id) { s.last_boot_id = boot_id; s.last_ctr24 = ctr24; return true; }
  if (boot_id == s.last_boot_id && ctr24 > s.last_ctr24) { s.last_ctr24 = ctr24; return true; }
  return false;
}

// ===================== Config (NVS) =====================
static void loadSlotsFromNVS() {
  prefs.begin("gwcfg", true);
  String map = prefs.getString("slots", "");
  prefs.end();

  for (int i = 0; i < SLOT_COUNT; i++) slots[i].dev_id = 0;
  if (map.length() == 0) return;

  int idx = 0;
  int start = 0;
  while (idx < SLOT_COUNT) {
    int comma = map.indexOf(',', start);
    String token = (comma >= 0) ? map.substring(start, comma) : map.substring(start);
    token.trim();
    slots[idx].dev_id = (uint16_t) token.toInt();
    idx++;
    if (comma < 0) break;
    start = comma + 1;
  }
}

static String slotsToCSV() {
  String s;
  for (int i = 0; i < SLOT_COUNT; i++) {
    if (i) s += ",";
    s += String((unsigned)slots[i].dev_id);
  }
  return s;
}

static void loadConfig() {
  prefs.begin("gwcfg", true);
  wifiSsid   = prefs.getString("ssid", "");
  wifiPass   = prefs.getString("pass", "");
  mqttHost   = prefs.getString("mhost", MQTT_HOST_DEFAULT);
  mqttPort   = prefs.getUShort("mport", MQTT_PORT_DEFAULT);
  mqttBase   = prefs.getString("mbase", MQTT_BASE_DEFAULT);
  mqttUser   = prefs.getString("muser", MQTT_USER_DEFAULT);
  mqttPasswd = prefs.getString("mpass", MQTT_PASS_DEFAULT);
  prefs.end();

  loadSlotsFromNVS();
}

static void saveConfigAndSlots(const String& slotsCsv) {
  prefs.begin("gwcfg", false);
  prefs.putString("ssid", wifiSsid);
  prefs.putString("pass", wifiPass);
  prefs.putString("mhost", mqttHost);
  prefs.putUShort("mport", mqttPort);
  prefs.putString("mbase", mqttBase);
  prefs.putString("muser", mqttUser);
  prefs.putString("mpass", mqttPasswd);
  prefs.putString("slots", slotsCsv);
  prefs.end();
}

static void mqttApplyConfig() {
  mqtt.setServer(mqttHost.c_str(), mqttPort);
}

static void mqttEnsureNonBlocking() {
  if (mqtt.connected()) return;
  if (WiFi.status() != WL_CONNECTED) return;

  static uint32_t lastTry = 0;
  if (millis() - lastTry < 1000) return;
  lastTry = millis();

  String cid = "ble-gw-" + String((uint32_t)ESP.getEfuseMac(), HEX);

  bool ok;
  if (mqttUser.length() > 0) ok = mqtt.connect(cid.c_str(), mqttUser.c_str(), mqttPasswd.c_str());
  else ok = mqtt.connect(cid.c_str());

  if (ok) { cnt_mqtt_conn_ok++; logln("MQTT: connected"); }
  else    { cnt_mqtt_conn_fail++; logln("MQTT: connect failed"); }
}

// ===================== WiFi AP+STA =====================
static void wifiBoot() {
  WiFi.mode(WIFI_AP_STA);

  bool apok = (strlen(AP_PASS) == 0) ? WiFi.softAP(AP_SSID) : WiFi.softAP(AP_SSID, AP_PASS);
  if (apok) logln("WIFI: AP started");
  else      logln("WIFI: AP FAIL");

  if (wifiSsid.length() == 0) {
    logln("WIFI: no STA creds");
    return;
  }

  WiFi.setSleep(false);
  WiFi.begin(wifiSsid.c_str(), wifiPass.c_str());
  logln("WIFI: trying STA...");

  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && (millis() - t0) < 15000) delay(200);

  if (WiFi.status() == WL_CONNECTED) logln("WIFI: STA connected");
  else logln("WIFI: STA failed (AP still up)");
}

// ===================== Hot reconnect (CONFIG) =====================
static bool tryWiFiSTAHot(uint32_t timeoutMs) {
  if (wifiSsid.length() == 0) return false;

  WiFi.mode(WIFI_AP_STA);
  WiFi.setSleep(false);

  WiFi.disconnect(false, true);
  delay(80);
  WiFi.begin(wifiSsid.c_str(), wifiPass.c_str());

  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && (millis() - t0) < timeoutMs) delay(150);
  return (WiFi.status() == WL_CONNECTED);
}

static bool tryMQTTHot(uint32_t timeoutMs) {
  if (WiFi.status() != WL_CONNECTED) return false;

  mqttApplyConfig();

  uint32_t t0 = millis();
  while (!mqtt.connected() && (millis() - t0) < timeoutMs) {
    String cid = "ble-gw-" + String((uint32_t)ESP.getEfuseMac(), HEX);

    bool ok;
    if (mqttUser.length() > 0) ok = mqtt.connect(cid.c_str(), mqttUser.c_str(), mqttPasswd.c_str());
    else ok = mqtt.connect(cid.c_str());

    if (ok) { cnt_mqtt_conn_ok++; return true; }
    cnt_mqtt_conn_fail++;
    delay(250);
  }
  return mqtt.connected();
}

// ===================== Decrypt =====================
static bool decryptAndParse(const uint8_t *p, size_t len, Telemetry &out) {
  if (len != ADV_LEN) return false;
  if (p[0] != PROTO_VER) return false;

  out.dev_id  = (uint16_t)p[1] | ((uint16_t)p[2] << 8);
  out.boot_id = (uint32_t)p[3] | ((uint32_t)p[4] << 8) | ((uint32_t)p[5] << 16) | ((uint32_t)p[6] << 24);
  out.ctr24   = (uint32_t)p[7] | ((uint32_t)p[8] << 8) | ((uint32_t)p[9] << 16);

  uint8_t iv[16] = {0};
  iv[0] = p[1]; iv[1] = p[2];
  memcpy(&iv[2], &p[3], 4);
  memcpy(&iv[6], &p[7], 3);
  iv[9] = PROTO_VER;

  uint8_t aad[10];
  memcpy(aad, p, sizeof(aad));

  uint8_t pt[5];

  eax.clear();
  eax.setKey(GROUP_KEY, sizeof(GROUP_KEY));
  eax.setIV(iv, sizeof(iv));
  eax.addAuthData(aad, sizeof(aad));

  eax.decrypt(pt, &p[10], 5);
  if (!eax.checkTag(&p[15], 8)) return false;

  out.temp_x100 = (int16_t)((uint16_t)pt[0] | ((uint16_t)pt[1] << 8));
  out.vin_mv    = (uint16_t)pt[2] | ((uint16_t)pt[3] << 8);
  out.flags     = pt[4];
  return true;
}

// ===================== BLE callbacks =====================
class MyCallbacks : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice dev) override {
    String mfg = dev.getManufacturerData();
    if (mfg.length() != ADV_LEN) return;

    RawAdvMsg msg;
    memcpy(msg.mfg, mfg.c_str(), ADV_LEN);
    msg.rssi = (int8_t)dev.getRSSI();

    cnt_adv_raw++;
    (void)xQueueSend(advQ, &msg, 0);
  }
};
static MyCallbacks* cb = nullptr;

static void scanTask(void*) {
  pScan = BLEDevice::getScan();
  cb = new MyCallbacks();
  pScan->setAdvertisedDeviceCallbacks(cb, false /* duplicates */);
  pScan->setActiveScan(false);
  pScan->setInterval(160);
  pScan->setWindow(80);

  for (;;) {
    pScan->start(2, false);
    pScan->clearResults();
    vTaskDelay(pdMS_TO_TICKS(100));
  }
}

// ===================== Web: HOME / DEVICES / STAT / LOG / INFO =====================
static void handleHome() {
  noCacheHeaders();

  String b;
  b += "<h2>BLE Gateway</h2>";

  b += "<div class='card'>";
  b += "<div><b>AP IP:</b> " + WiFi.softAPIP().toString() + "</div>";
  b += "<div><b>STA IP:</b> " + WiFi.localIP().toString() + "</div>";
  b += "<div><b>STA status:</b> " + String((int)WiFi.status()) + " (3=connected)</div>";
  b += "</div>";

  b += "<div class='card'>";
  b += "<div><b>MQTT:</b> " + htmlEscape(mqttHost) + ":" + String(mqttPort) + "</div>";
  b += "<div><b>Base:</b> " + htmlEscape(mqttBase) + "</div>";
  b += "<div><b>User:</b> " + (mqttUser.length() ? htmlEscape(mqttUser) : String("(none)")) + "</div>";
  b += "<div><b>Status:</b> " + String(mqtt.connected() ? "connected" : "disconnected") + "</div>";
  b += "</div>";

  b += "<div class='card muted'>";
  b += "Text endpoints: <a href='/stat'>/stat</a> <a href='/log'>/log</a> <a href='/info'>/info</a> | ";
  b += "HTML: <a href='/stat.html'>/stat.html</a> <a href='/log.html'>/log.html</a> <a href='/info.html'>/info.html</a>";
  b += "</div>";

  server.send(200, "text/html", pageWrap("Home", "home", b, 0));
}

static void handleDevicesHtml() {
  noCacheHeaders();

  const uint32_t now = millis();
  const uint32_t offline_ms = 5000;

  String b;
  b += "<h2>Devices</h2>";
  b += "<div class='card muted'>16 slots fijos. Offline si no hay update en &gt; " + String(offline_ms) + " ms.</div>";

  b += "<div class='card' style='padding:0'>";
  b += "<div style='overflow:auto;max-height:70vh;border-radius:16px'>";
  b += "<table><thead><tr>"
       "<th>Slot</th><th>Dev ID</th><th>Status</th><th>Temp (°C)</th><th>VIN (V)</th><th>RSSI</th><th>Last seen (ms)</th>"
       "</tr></thead><tbody>";

  for (int i = 0; i < SLOT_COUNT; i++) {
    uint16_t id = slots[i].dev_id;

    String st; const char* cls = "warn";
    if (id == 0) { st="empty"; cls="warn"; }
    else if (slots[i].last_seen_ms == 0) { st="waiting"; cls="warn"; }
    else if ((now - slots[i].last_seen_ms) > offline_ms) { st="offline"; cls="bad"; }
    else { st="online"; cls="ok"; }

    float tc = ((float)slots[i].last_temp_x100) / 100.0f;
    float vv = ((float)slots[i].last_vin_mv) / 1000.0f;

    b += "<tr>";
    b += "<td><b>" + String(i) + "</b></td>";
    b += "<td>" + String(id) + "</td>";
    b += "<td>" + badge(st, cls) + "</td>";
    b += "<td>" + (id ? fmt2(tc,2) : String("-")) + "</td>";
    b += "<td>" + (id ? fmt2(vv,3) : String("-")) + "</td>";
    b += "<td>" + (id ? String((int)slots[i].last_rssi) : String("-")) + "</td>";
    b += "<td>" + String((unsigned long)slots[i].last_seen_ms) + "</td>";
    b += "</tr>";
  }

  b += "</tbody></table></div></div>";
  b += "<div class='card muted'>JSON: <a href='/devices.json'>/devices.json</a></div>";

  server.send(200, "text/html", pageWrap("Devices", "devices", b, 2000));
}

static void handleDevicesJson() {
  StaticJsonDocument<2300> doc;
  JsonArray arr = doc.createNestedArray("slots");
  for (int i = 0; i < SLOT_COUNT; i++) {
    JsonObject o = arr.createNestedObject();
    o["slot"] = i;
    o["dev_id"] = slots[i].dev_id;
    o["temp_c"] = ((float)slots[i].last_temp_x100) / 100.0f;
    o["vin_v"]  = ((float)slots[i].last_vin_mv) / 1000.0f;
    o["flags"]  = slots[i].last_flags;
    o["rssi"]   = slots[i].last_rssi;
    o["last_seen_ms"] = slots[i].last_seen_ms;
  }
  String out;
  serializeJson(doc, out);
  server.send(200, "application/json", out);
}

// Texto original (compat)
static void handleStatText() {
  char buf[520];
  snprintf(buf, sizeof(buf),
    "adv_raw=%lu\n"
    "dec_ok=%lu\n"
    "dec_fail=%lu\n"
    "replay_drop=%lu\n"
    "unassigned_drop=%lu\n"
    "pub_ok=%lu\n"
    "pub_fail=%lu\n"
    "mqtt_conn_ok=%lu\n"
    "mqtt_conn_fail=%lu\n"
    "sta_status=%d (3=connected)\n"
    "sta_ip=%s\n",
    (unsigned long)cnt_adv_raw,
    (unsigned long)cnt_dec_ok,
    (unsigned long)cnt_dec_fail,
    (unsigned long)cnt_replay_drop,
    (unsigned long)cnt_unassigned_drop,
    (unsigned long)cnt_pub_ok,
    (unsigned long)cnt_pub_fail,
    (unsigned long)cnt_mqtt_conn_ok,
    (unsigned long)cnt_mqtt_conn_fail,
    (int)WiFi.status(),
    WiFi.localIP().toString().c_str()
  );
  server.send(200, "text/plain", buf);
}

static void handleStatHtml() {
  noCacheHeaders();
  String b;
  b += "<h2>Stat</h2><div class='card'><pre>";
  b += String(server.uri()) + "\n\n";
  b += "adv_raw=" + String((unsigned long)cnt_adv_raw) + "\n";
  b += "dec_ok=" + String((unsigned long)cnt_dec_ok) + "\n";
  b += "dec_fail=" + String((unsigned long)cnt_dec_fail) + "\n";
  b += "replay_drop=" + String((unsigned long)cnt_replay_drop) + "\n";
  b += "unassigned_drop=" + String((unsigned long)cnt_unassigned_drop) + "\n";
  b += "pub_ok=" + String((unsigned long)cnt_pub_ok) + "\n";
  b += "pub_fail=" + String((unsigned long)cnt_pub_fail) + "\n";
  b += "mqtt_conn_ok=" + String((unsigned long)cnt_mqtt_conn_ok) + "\n";
  b += "mqtt_conn_fail=" + String((unsigned long)cnt_mqtt_conn_fail) + "\n";
  b += "sta_status=" + String((int)WiFi.status()) + " (3=connected)\n";
  b += "sta_ip=" + WiFi.localIP().toString() + "\n";
  b += "</pre></div><div class='card muted'>Text: <a href='/stat'>/stat</a></div>";
  server.send(200, "text/html", pageWrap("Stat", "stat", b, 2000));
}

static void handleLogText() {
  server.send(200, "text/plain", getLogString());
}

static void handleLogHtml() {
  noCacheHeaders();
  String b;
  b += "<h2>Log</h2><div class='card'><pre style='max-height:70vh'>";
  b += htmlEscape(getLogString());
  b += "</pre></div><div class='card muted'>Text: <a href='/log'>/log</a></div>";
  server.send(200, "text/html", pageWrap("Log", "log", b, 3000));
}

static void handleInfoText() {
  String ip = (WiFi.getMode() == WIFI_AP) ? WiFi.softAPIP().toString() : WiFi.localIP().toString();
  char buf[256];
  snprintf(buf, sizeof(buf),
    "mode=%s\nip=%s\nheap_free=%u\nheap_min=%u\nreset_reason=%d\nssid=%s\nmqtt=%s:%u\n",
    (WiFi.getMode() == WIFI_AP) ? "AP" : "STA",
    ip.c_str(),
    (unsigned)ESP.getFreeHeap(),
    (unsigned)ESP.getMinFreeHeap(),
    (int)esp_reset_reason(),
    wifiSsid.c_str(),
    mqttHost.c_str(),
    (unsigned)mqttPort
  );
  server.send(200, "text/plain", buf);
}

static void handleInfoHtml() {
  noCacheHeaders();
  String b;
  b += "<h2>Info</h2><div class='card'><pre>";
  b += "ap_ip=" + WiFi.softAPIP().toString() + "\n";
  b += "sta_status=" + String((int)WiFi.status()) + " (3=connected)\n";
  b += "sta_ip=" + WiFi.localIP().toString() + "\n";
  b += "heap_free=" + String((unsigned)ESP.getFreeHeap()) + "\n";
  b += "heap_min=" + String((unsigned)ESP.getMinFreeHeap()) + "\n";
  b += "reset_reason=" + String((int)esp_reset_reason()) + "\n";
  b += "ssid=" + htmlEscape(wifiSsid) + "\n";
  b += "mqtt=" + htmlEscape(mqttHost) + ":" + String((unsigned)mqttPort) + "\n";
  b += "mqtt_user=" + (mqttUser.length() ? htmlEscape(mqttUser) : String("(none)")) + "\n";
  b += "base=" + htmlEscape(mqttBase) + "\n";
  b += "</pre></div><div class='card muted'>Text: <a href='/info'>/info</a></div>";
  server.send(200, "text/html", pageWrap("Info", "info", b, 0));
}

// ===================== CONFIG (REMODELADO) =====================
static bool cfg_last_saved = false;
static bool cfg_last_sta_ok = false;
static bool cfg_last_mqtt_ok = false;
static String cfg_last_ip = "";
static String cfg_last_msg = "";

static void renderConfigPage() {
  noCacheHeaders();

  String b;
  b += "<h2>Config WiFi + MQTT + Slots</h2>";

  // Banner estado
  if (cfg_last_saved) {
    String cls = (cfg_last_sta_ok && cfg_last_mqtt_ok) ? "ok" : (cfg_last_sta_ok ? "warn" : "bad");
    b += "<div class='card " + cls + "'>";
    b += "<b>Guardado.</b> " + htmlEscape(cfg_last_msg) + "<br>";
    b += "STA: " + String(cfg_last_sta_ok ? "CONNECTED" : "NOT CONNECTED");
    if (cfg_last_ip.length()) b += " (IP " + htmlEscape(cfg_last_ip) + ")";
    b += "<br>MQTT: " + String(cfg_last_mqtt_ok ? "CONNECTED" : "NOT CONNECTED");
    b += "</div>";
  } else {
    b += "<div class='card muted'>AP (" + String(AP_SSID) + ") siempre activo. Save intenta reconectar sin reiniciar.</div>";
  }

  // Form
  b += "<div class='card'><form method='POST' action='/config'>";

  b += "<h3>WiFi (STA)</h3>";
  b += "<label>SSID</label><br><input name='ssid' value='" + htmlEscape(wifiSsid) + "'><br><br>";
  b += "<label>Password</label><br><input name='pass' type='password' value='" + htmlEscape(wifiPass) + "'><br><br>";

  b += "<h3>MQTT</h3>";
  b += "<label>Host</label><br><input name='mhost' value='" + htmlEscape(mqttHost) + "'><br><br>";
  b += "<label>Port</label><br><input name='mport' value='" + String(mqttPort) + "'><br><br>";
  b += "<label>User</label><br><input name='muser' value='" + htmlEscape(mqttUser) + "'><br><br>";
  b += "<label>Password</label><br><input name='mpass' type='password' value='" + htmlEscape(mqttPasswd) + "'><br><br>";
  b += "<label>Topic base</label><br><input name='mbase' value='" + htmlEscape(mqttBase) + "'><br><br>";

  b += "<h3>Slots (16)</h3>";
  b += "<p class='muted'>16 valores separados por coma. 0=vacio. Ej: "
       "<code>101,102,103,0,0,0,0,0,0,0,0,0,0,0,0,0</code></p>";
  b += "<textarea name='slots' rows='3'>" + htmlEscape(slotsToCSV()) + "</textarea><br><br>";

  b += "<label><input type='checkbox' name='reboot' value='1'> Reiniciar después de guardar</label><br><br>";

  b += "<div style='display:flex;gap:10px;flex-wrap:wrap'>";
  b += "<button type='submit'>Save</button>";
  b += "<a class='btn2' href='/'>Exit</a>";
  b += "</div>";

  b += "</form></div>";

  server.send(200, "text/html", pageWrap("Config", "config", b, 0));
}

static void handleConfigGet() {
  cfg_last_saved = false;  // al entrar “limpia” banner salvo que venga de un POST
  cfg_last_msg = "";
  renderConfigPage();
}

static void handleConfigPost() {
  // leer campos
  if (server.hasArg("ssid")) wifiSsid = server.arg("ssid");
  if (server.hasArg("pass")) wifiPass = server.arg("pass");

  if (server.hasArg("mhost")) mqttHost = server.arg("mhost");
  if (server.hasArg("mport")) mqttPort = (uint16_t)server.arg("mport").toInt();
  if (server.hasArg("muser")) mqttUser = server.arg("muser");
  if (server.hasArg("mpass")) mqttPasswd = server.arg("mpass");
  if (server.hasArg("mbase")) mqttBase = server.arg("mbase");

  String slotsCsv = server.hasArg("slots") ? server.arg("slots") : slotsToCSV();

  // sanitize
  wifiSsid.trim(); wifiPass.trim();
  mqttHost.trim(); mqttUser.trim(); mqttPasswd.trim(); mqttBase.trim();
  slotsCsv.trim();

  if (mqttHost.length() == 0) mqttHost = MQTT_HOST_DEFAULT;
  if (mqttPort == 0) mqttPort = MQTT_PORT_DEFAULT;
  if (mqttBase.length() == 0) mqttBase = MQTT_BASE_DEFAULT;

  // guardar
  saveConfigAndSlots(slotsCsv);

  // aplicar slots en RAM (para que el /devices refleje el map sin reboot)
  loadSlotsFromNVS();

  // reconnect “en caliente”
  cfg_last_sta_ok = tryWiFiSTAHot(6000);
  cfg_last_ip = (WiFi.status() == WL_CONNECTED) ? WiFi.localIP().toString() : "";
  cfg_last_mqtt_ok = tryMQTTHot(2500);

  cfg_last_saved = true;
  cfg_last_msg = "Reconexión en caliente ejecutada.";

  // log
  logln("CFG: saved");
  logln(cfg_last_sta_ok ? "CFG: STA ok" : "CFG: STA fail");
  logln(cfg_last_mqtt_ok ? "CFG: MQTT ok" : "CFG: MQTT fail");

  // mostrar la misma página con banner (sin redirect)
  renderConfigPage();

  // reboot opcional (después de responder)
  if (server.hasArg("reboot") && server.arg("reboot") == "1") {
    delay(400);
    ESP.restart();
  }
}

// ===================== Web setup =====================
static void handleNotFound() {
  String m;
  m += "404\n";
  m += "uri=" + server.uri() + "\n";
  server.send(404, "text/plain", m);
}

static void webSetup() {
  server.on("/",        handleHome);

  server.on("/devices", handleDevicesHtml);
  server.on("/devices.json", handleDevicesJson);

  server.on("/stat",     handleStatText);
  server.on("/stat.html",handleStatHtml);

  server.on("/log",      handleLogText);
  server.on("/log.html", handleLogHtml);

  server.on("/info",     handleInfoText);
  server.on("/info.html",handleInfoHtml);

  // CONFIG: GET + POST (este es el punto crítico)
  server.on("/config", HTTP_GET,  handleConfigGet);
  server.on("/config", HTTP_POST, handleConfigPost);

  server.onNotFound(handleNotFound);

  server.begin();
  logln("WEB: started");
}

// ===================== setup / loop =====================
void setup() {
  pinMode(LED_PIN, OUTPUT);
  ledWrite(false);

  Serial.begin(115200);
  delay(200);

  // Ventana de factory reset (solo borra namespace "gwcfg")
  checkFactoryResetAtBoot();

  logln("BOOT: gateway start (16 slots + web pro + config remodelado + factory reset + status LED)");

  advQ = xQueueCreate(96, sizeof(RawAdvMsg));
  if (!advQ) logln("ERR: advQ alloc failed");

  loadConfig();
  mqttApplyConfig();

  wifiBoot();
  webSetup();

  BLEDevice::init("BLE-GW");
  xTaskCreatePinnedToCore(scanTask, "scanTask", 8192, nullptr, 1, nullptr, 0);
  logln("BLE: scan task started");
}

void loop() {
  server.handleClient();
  mqtt.loop();
  mqttEnsureNonBlocking();

  // LED de estado (no bloqueante)
  statusLedTick();

  // Heartbeat al log cada 5s
  static uint32_t hb = 0;
  if (millis() - hb > 5000) {
    hb = millis();
    logln("HB: alive");
  }

  // Procesamiento RAW -> decrypt -> slot -> anti-replay -> update -> mqtt
  RawAdvMsg raw;
  while (xQueueReceive(advQ, &raw, 0) == pdTRUE) {

    Telemetry t;
    if (!decryptAndParse(raw.mfg, ADV_LEN, t)) {
      cnt_dec_fail++;
      continue;
    }
    cnt_dec_ok++;

    int si = slotIndexForDev(t.dev_id);
    if (si < 0) {
      cnt_unassigned_drop++;
      continue;
    }

    SlotState& s = slots[si];
    if (!antiReplayOK(s, t.boot_id, t.ctr24)) {
      cnt_replay_drop++;
      continue;
    }

    // Update slot telemetry
    s.last_rssi      = raw.rssi;
    s.last_seen_ms   = millis();
    s.last_temp_x100 = t.temp_x100;
    s.last_vin_mv    = t.vin_mv;
    s.last_flags     = t.flags;

    // MQTT publish si conectado
    if (!mqtt.connected()) continue;

    StaticJsonDocument<256> doc;
    doc["slot"]    = si;
    doc["dev_id"]  = t.dev_id;
    doc["boot_id"] = t.boot_id;
    doc["ctr"]     = t.ctr24;
    doc["temp_c"]  = ((float)t.temp_x100) / 100.0f;
    doc["vin_v"]   = ((float)t.vin_mv) / 1000.0f;
    doc["flags"]   = t.flags;
    doc["rssi"]    = raw.rssi;
    doc["ts_ms"]   = s.last_seen_ms;

    char payload[256];
    size_t len = serializeJson(doc, payload, sizeof(payload));

    char topic[128];
    snprintf(topic, sizeof(topic), "%s/slot/%d/telemetry", mqttBase.c_str(), si);

    if (mqtt.publish(topic, payload, len)) cnt_pub_ok++;
    else cnt_pub_fail++;
  }

  delay(5);
}
