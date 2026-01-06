/*  =====================  GATEWAY_FRIOMAMUT_MQTT_PAIR_NIMBLE.ino  =====================
    ESP32-S3 Gateway BLE->MQTT + Web UI + Pair Manager (NimBLE)

    Objetivo:
    - Mantener tu gateway BLE->MQTT estable
    - Añadir "Pair Manager" para entornos con varios gateways contiguos
    - Binding real (Nivel 2): cada nodo usa una KEY AES-128 única provisionada por este gateway.
      Solo este gateway puede descifrar (si el nodo está provisionado con su key).

    Nodo (nRF52840) esperado:
    - Service UUID: 12345678-1234-5678-1234-56789abc0000
    - Char UID (read):    ...0001  (8 bytes uid64)
    - Char PROVISION (write, 22B): ...0002  [gwid(4) + key(16) + tx(int8) + flags(1)]
    - Char CTL (write 1B): ...0003  0xA5 commit
    - Char STATUS (read 8B): ...0004
    - Pairing flag en claro: Service Data UUID 0xFFF0, value 0x01 cuando pairing

    Protocolo ADV:
    - v1: 23 bytes (temp_ext + vin + flags)
    - v2: 25 bytes (temp_ext + vin + temp_mcu + flags)

    Requisitos Arduino IDE / PlatformIO:
    - ESP32 core (IDF/Arduino)
    - NimBLE-Arduino (en ESP32 core reciente suele venir como "NimBLEDevice.h")
    - Crypto (AES, EAX) como ya usas
*/

#include <WiFi.h>
#include <WebServer.h>
#include <Preferences.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>

#include <NimBLEDevice.h>
#include <string>

#include <Crypto.h>
#include <AES.h>
#include <EAX.h>

#include "esp_system.h"

// ===================== Ajustes HW =====================
#define BOOT_PIN 0

#ifndef LED_PIN
  // Ajusta según tu placa si no coincide (muchas S3 supermini usan 21/48/47)
  #define LED_PIN 21
#endif

#ifndef LED_ON
  #define LED_ON  LOW
  #define LED_OFF HIGH
#endif

static inline void ledWrite(bool on){ digitalWrite(LED_PIN, on ? LED_ON : LED_OFF); }

// ===================== Factory reset (BOOT) =====================
static const uint32_t FACTORY_HOLD_MS   = 3000;
static const uint32_t FACTORY_WINDOW_MS = 6000;

static void clearGatewayConfigNamespace(){
  Preferences p;
  if (p.begin("gwcfg", false)) {
    p.clear();
    p.end();
  }
}

static void ledBlinkBlocking(int times, int on_ms, int off_ms){
  for(int i=0;i<times;i++){ ledWrite(true); delay(on_ms); ledWrite(false); delay(off_ms); }
}

static void checkFactoryResetAtBoot(){
  pinMode(BOOT_PIN, INPUT_PULLUP);
  uint32_t t0 = millis();

  while (millis() - t0 < FACTORY_WINDOW_MS) {
    ledWrite(true);  delay(120);
    ledWrite(false); delay(380);

    if (digitalRead(BOOT_PIN) == LOW) {
      uint32_t th = millis();
      while (digitalRead(BOOT_PIN) == LOW) {
        ledWrite(true);  delay(70);
        ledWrite(false); delay(70);
        if (millis() - th >= FACTORY_HOLD_MS) {
          ledWrite(true); delay(600); ledWrite(false);
          clearGatewayConfigNamespace();
          ledBlinkBlocking(3, 120, 120);
          ESP.restart();
        }
      }
    }
  }
  ledBlinkBlocking(1, 180, 120);
}

// ===================== LED status (non-blocking) =====================
static uint32_t led_next_ms = 0;
static uint8_t  led_phase = 0;

static void statusLedTick(bool wifi_ok, bool mqtt_ok){
  uint32_t now = millis();
  if ((int32_t)(now - led_next_ms) < 0) return;

  if (!wifi_ok) {
    if (led_phase==0){ ledWrite(true);  led_next_ms=now+120; led_phase=1; }
    else            { ledWrite(false); led_next_ms=now+880; led_phase=0; }
    return;
  }

  if (wifi_ok && !mqtt_ok) {
    switch (led_phase) {
      case 0: ledWrite(true);  led_next_ms=now+80;  led_phase=1; break;
      case 1: ledWrite(false); led_next_ms=now+120; led_phase=2; break;
      case 2: ledWrite(true);  led_next_ms=now+80;  led_phase=3; break;
      default:ledWrite(false); led_next_ms=now+1720;led_phase=0; break;
    }
    return;
  }

  if (led_phase==0){ ledWrite(true);  led_next_ms=now+60;  led_phase=1; }
  else            { ledWrite(false); led_next_ms=now+1940;led_phase=0; }
}

// ===================== AP (gestión) =====================
static const char* AP_SSID = "BLE-GW";
static const char* AP_PASS = "";

// ===================== Defaults MQTT =====================
static const char* MQTT_HOST_DEFAULT = "192.168.0.200";
static const uint16_t MQTT_PORT_DEFAULT = 1883;
static const char* MQTT_BASE_DEFAULT = "mp/tunel_01";
static const char* MQTT_USER_DEFAULT = "";
static const char* MQTT_PASS_DEFAULT = "";

// ===================== Protocolo =====================
static const uint8_t PROTO_V1 = 0x01;
static const uint8_t PROTO_V2 = 0x02;

static const uint8_t ADV_LEN_V1 = 23;
static const uint8_t ADV_LEN_V2 = 25;

// Factory key (solo para nodos no provisionados)
static const uint8_t FACTORY_KEY[16] = {
  0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
  0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10
};

// Pairing flag en claro
static const uint16_t PAIR_FLAG_UUID16 = 0xFFF0;

// GATT UUIDs nodo
static NimBLEUUID SVC_UUID("12345678-1234-5678-1234-56789abc0000");
static NimBLEUUID CH_UID ("12345678-1234-5678-1234-56789abc0001");
static NimBLEUUID CH_PROV("12345678-1234-5678-1234-56789abc0002");
static NimBLEUUID CH_CTL ("12345678-1234-5678-1234-56789abc0003");
static NimBLEUUID CH_STAT("12345678-1234-5678-1234-56789abc0004");

// ===================== Slots =====================
static const uint8_t SLOT_COUNT = 16;

typedef struct {
  uint16_t dev_id=0;
  uint8_t  key[16]={0};        // all-zero => usar FACTORY_KEY
  uint32_t last_boot_id=0;
  uint32_t last_ctr24=0;

  uint32_t last_seen_ms=0;
  int8_t   last_rssi=0;
  int16_t  last_temp_x100=0;
  uint16_t last_vin_mv=0;
  int16_t  last_mcu_x100=0;
  uint8_t  last_flags=0;
} SlotState;

static SlotState slots[SLOT_COUNT];
static portMUX_TYPE slotsMux = portMUX_INITIALIZER_UNLOCKED;

// ===================== Telemetry =====================
typedef struct {
  uint8_t  proto=0;
  uint16_t dev_id=0;
  uint32_t boot_id=0;
  uint32_t ctr24=0;
  int16_t  temp_x100=0;
  uint16_t vin_mv=0;
  int16_t  mcu_x100=0;
  uint8_t  flags=0;
} Telemetry;

// ===================== Logger circular =====================
static char logbuf[4096];
static volatile size_t log_head = 0;

static void logln(const char* s) {
  while (*s) { logbuf[log_head] = *s++; log_head = (log_head + 1) % sizeof(logbuf); }
  logbuf[log_head] = '\n'; log_head = (log_head + 1) % sizeof(logbuf);
}

static String getLogString() {
  String out; out.reserve(sizeof(logbuf) + 32);
  size_t start = log_head;
  for (size_t i = 0; i < sizeof(logbuf); i++) {
    char c = logbuf[(start + i) % sizeof(logbuf)];
    if (c == 0) continue;
    out += c;
  }
  return out;
}

// ===================== Diagnóstico =====================
static volatile uint32_t cnt_adv_raw=0, cnt_dec_ok=0, cnt_dec_fail=0, cnt_replay_drop=0, cnt_pub_ok=0, cnt_pub_fail=0, cnt_mqtt_conn_ok=0, cnt_mqtt_conn_fail=0, cnt_unassigned_drop=0;

// ===================== Globales =====================
WebServer server(80);
Preferences prefs;

WiFiClient espClient;
PubSubClient mqtt(espClient);

EAX<AES128> eax;

// ===================== Config (NVS) =====================
static String wifiSsid, wifiPass;
static String mqttHost, mqttBase, mqttUser, mqttPasswd;
static uint16_t mqttPort = MQTT_PORT_DEFAULT;

static String bytesToHex(const uint8_t* b, size_t n){
  static const char* hx="0123456789ABCDEF";
  String s; s.reserve(n*2);
  for(size_t i=0;i<n;i++){ s += hx[(b[i]>>4)&0xF]; s += hx[b[i]&0xF]; }
  return s;
}
static bool hexToBytes(const String& hex, uint8_t* out, size_t n){
  if ((int)hex.length() != (int)(n*2)) return false;
  auto v = [](char c)->int{
    if (c>='0'&&c<='9') return c-'0';
    if (c>='a'&&c<='f') return c-'a'+10;
    if (c>='A'&&c<='F') return c-'A'+10;
    return -1;
  };
  for(size_t i=0;i<n;i++){
    int a=v(hex[2*i]); int b=v(hex[2*i+1]);
    if (a<0||b<0) return false;
    out[i]=(uint8_t)((a<<4)|b);
  }
  return true;
}

static String slotsToCSV() {
  String s;
  for (int i=0;i<SLOT_COUNT;i++){ if(i) s += ","; s += String((unsigned)slots[i].dev_id); }
  return s;
}

static void loadSlotsFromNVS(){
  prefs.begin("gwcfg", true);
  String map = prefs.getString("slots", "");

  for(int i=0;i<SLOT_COUNT;i++){
    String kn = "k" + String(i);
    String khex = prefs.getString(kn.c_str(), "");
    memset(slots[i].key, 0, 16);
    if (khex.length()==32) (void)hexToBytes(khex, slots[i].key, 16);
  }
  prefs.end();

  for(int i=0;i<SLOT_COUNT;i++){ slots[i].dev_id = 0; }

  if (!map.length()) return;
  int idx=0, start=0;
  while(idx < SLOT_COUNT){
    int comma = map.indexOf(',', start);
    String token = (comma>=0) ? map.substring(start, comma) : map.substring(start);
    token.trim();
    slots[idx].dev_id = (uint16_t)token.toInt();
    idx++;
    if (comma<0) break;
    start = comma+1;
  }
}

static void saveSlotsToNVS(){
  prefs.begin("gwcfg", false);
  prefs.putString("slots", slotsToCSV());
  for(int i=0;i<SLOT_COUNT;i++){
    String kn = "k" + String(i);
    bool all0=true;
    for(int j=0;j<16;j++) if (slots[i].key[j]!=0){ all0=false; break; }
    prefs.putString(kn.c_str(), all0 ? "" : bytesToHex(slots[i].key,16));
  }
  prefs.end();
}

static void loadConfig(){
  prefs.begin("gwcfg", true);
  wifiSsid   = prefs.getString("ssid","");
  wifiPass   = prefs.getString("pass","");
  mqttHost   = prefs.getString("mhost", MQTT_HOST_DEFAULT);
  mqttPort   = prefs.getUShort("mport", MQTT_PORT_DEFAULT);
  mqttBase   = prefs.getString("mbase", MQTT_BASE_DEFAULT);
  mqttUser   = prefs.getString("muser", MQTT_USER_DEFAULT);
  mqttPasswd = prefs.getString("mpass", MQTT_PASS_DEFAULT);
  prefs.end();

  loadSlotsFromNVS();
}

static void saveConfigBase(){
  prefs.begin("gwcfg", false);
  prefs.putString("ssid", wifiSsid);
  prefs.putString("pass", wifiPass);
  prefs.putString("mhost", mqttHost);
  prefs.putUShort("mport", mqttPort);
  prefs.putString("mbase", mqttBase);
  prefs.putString("muser", mqttUser);
  prefs.putString("mpass", mqttPasswd);
  prefs.end();
}

static void mqttApplyConfig(){ mqtt.setServer(mqttHost.c_str(), mqttPort); }

// ===================== WiFi AP+STA =====================
static void wifiBoot(){
  WiFi.mode(WIFI_AP_STA);
  bool apok = (strlen(AP_PASS)==0) ? WiFi.softAP(AP_SSID) : WiFi.softAP(AP_SSID, AP_PASS);
  logln(apok ? "WIFI: AP started" : "WIFI: AP FAIL");

  if (!wifiSsid.length()){ logln("WIFI: no STA creds"); return; }

  WiFi.setSleep(false);
  WiFi.begin(wifiSsid.c_str(), wifiPass.c_str());
  logln("WIFI: trying STA...");
  uint32_t t0=millis();
  while(WiFi.status()!=WL_CONNECTED && (millis()-t0)<15000) delay(200);
  logln(WiFi.status()==WL_CONNECTED ? "WIFI: STA connected" : "WIFI: STA failed (AP still up)");
}

static bool tryWiFiSTAHot(uint32_t timeoutMs){
  if (!wifiSsid.length()) return false;
  WiFi.mode(WIFI_AP_STA);
  WiFi.setSleep(false);
  WiFi.disconnect(false, true);
  delay(80);
  WiFi.begin(wifiSsid.c_str(), wifiPass.c_str());
  uint32_t t0=millis();
  while(WiFi.status()!=WL_CONNECTED && (millis()-t0)<timeoutMs) delay(150);
  return (WiFi.status()==WL_CONNECTED);
}

static bool tryMQTTHot(uint32_t timeoutMs){
  if (WiFi.status()!=WL_CONNECTED) return false;
  mqttApplyConfig();
  uint32_t t0=millis();
  while(!mqtt.connected() && (millis()-t0)<timeoutMs){
    String cid="ble-gw-"+String((uint32_t)ESP.getEfuseMac(), HEX);
    bool ok = mqttUser.length()? mqtt.connect(cid.c_str(), mqttUser.c_str(), mqttPasswd.c_str()) : mqtt.connect(cid.c_str());
    if(ok){ cnt_mqtt_conn_ok++; return true; }
    cnt_mqtt_conn_fail++;
    delay(250);
  }
  return mqtt.connected();
}

static void mqttEnsureNonBlocking(){
  if (mqtt.connected()) return;
  if (WiFi.status()!=WL_CONNECTED) return;
  static uint32_t lastTry=0;
  if (millis()-lastTry<1000) return;
  lastTry=millis();
  String cid="ble-gw-"+String((uint32_t)ESP.getEfuseMac(), HEX);
  bool ok = mqttUser.length()? mqtt.connect(cid.c_str(), mqttUser.c_str(), mqttPasswd.c_str()) : mqtt.connect(cid.c_str());
  if(ok){ cnt_mqtt_conn_ok++; logln("MQTT: connected"); }
  else  { cnt_mqtt_conn_fail++; logln("MQTT: connect failed"); }
}

// ===================== Anti-replay =====================
static bool antiReplayCheck(SlotState& s, uint32_t boot_id, uint32_t ctr24){
  if (boot_id > s.last_boot_id) { s.last_boot_id = boot_id; s.last_ctr24 = ctr24; return true; }
  if (boot_id == s.last_boot_id && ctr24 > s.last_ctr24) { s.last_ctr24 = ctr24; return true; }
  return false;
}

static int slotIndexForDev(uint16_t dev_id){
  if (!dev_id) return -1;
  for(int i=0;i<SLOT_COUNT;i++) if (slots[i].dev_id == dev_id) return i;
  return -1;
}

static const uint8_t* slotKeyOrFactory(const SlotState& s){
  for(int i=0;i<16;i++) if (s.key[i]!=0) return s.key;
  return FACTORY_KEY;
}

// ===================== Decrypt & parse =====================
static bool decryptAndParse(const uint8_t *p, size_t len, const uint8_t* key, Telemetry &out){
  if (len!=ADV_LEN_V1 && len!=ADV_LEN_V2) return false;
  if (p[0]!=PROTO_V1 && p[0]!=PROTO_V2) return false;

  out.proto = p[0];
  out.dev_id  = (uint16_t)p[1] | ((uint16_t)p[2] << 8);
  out.boot_id = (uint32_t)p[3] | ((uint32_t)p[4] << 8) | ((uint32_t)p[5] << 16) | ((uint32_t)p[6] << 24);
  out.ctr24   = (uint32_t)p[7] | ((uint32_t)p[8] << 8) | ((uint32_t)p[9] << 16);

  uint8_t iv[16] = {0};
  iv[0] = p[1]; iv[1] = p[2];
  memcpy(&iv[2], &p[3], 4);
  memcpy(&iv[6], &p[7], 3);
  iv[9] = p[0];

  uint8_t aad[10];
  memcpy(aad, p, sizeof(aad));

  eax.clear();
  eax.setKey(key, 16);
  eax.setIV(iv, sizeof(iv));
  eax.addAuthData(aad, sizeof(aad));

  if (p[0]==PROTO_V1){
    uint8_t pt[5];
    eax.decrypt(pt, &p[10], 5);
    if (!eax.checkTag(&p[15], 8)) return false;

    out.temp_x100 = (int16_t)((uint16_t)pt[0] | ((uint16_t)pt[1] << 8));
    out.vin_mv    = (uint16_t)pt[2] | ((uint16_t)pt[3] << 8);
    out.flags     = pt[4];
    out.mcu_x100  = 0;
    return true;
  } else {
    uint8_t pt[7];
    eax.decrypt(pt, &p[10], 7);
    if (!eax.checkTag(&p[17], 8)) return false;

    out.temp_x100 = (int16_t)((uint16_t)pt[0] | ((uint16_t)pt[1] << 8));
    out.vin_mv    = (uint16_t)pt[2] | ((uint16_t)pt[3] << 8);
    out.mcu_x100  = (int16_t)((uint16_t)pt[4] | ((uint16_t)pt[5] << 8));
    out.flags     = pt[6];
    return true;
  }
}

// ===================== Colas =====================
typedef struct {
  uint8_t  mfg[ADV_LEN_V2];
  uint8_t  len=0;
  int8_t   rssi=0;
  NimBLEAddress addr;
  bool pairing=false;
} AdvMsg;

typedef struct {
  char topic[128];
  char payload[256];
  size_t len;
} PubMsg;

static QueueHandle_t advQ;
static QueueHandle_t pubQ;

// ===================== Seen nodes (para /pair) =====================
typedef struct {
  uint16_t dev_id=0;
  NimBLEAddress addr;
  int8_t rssi=0;
  uint32_t last_ms=0;
  bool pairing=false;
  uint8_t proto=0;
} SeenNode;

static const int SEEN_MAX = 48;
static SeenNode seen[SEEN_MAX];

static void seenUpdate(uint16_t dev_id, const NimBLEAddress& addr, int8_t rssi, bool pairing, uint8_t proto){
  int freei=-1;
  for(int i=0;i<SEEN_MAX;i++){
    if (seen[i].dev_id==0 && freei<0) freei=i;
    if (seen[i].dev_id==dev_id || seen[i].addr == addr){
      seen[i].dev_id = dev_id;
      seen[i].addr = addr;
      seen[i].rssi = rssi;
      seen[i].last_ms = millis();
      seen[i].pairing = pairing;
      seen[i].proto = proto;
      return;
    }
  }
  if (freei>=0){
    seen[freei].dev_id = dev_id;
    seen[freei].addr = addr;
    seen[freei].rssi = rssi;
    seen[freei].last_ms = millis();
    seen[freei].pairing = pairing;
    seen[freei].proto = proto;
  }
}

static uint32_t gatewayId(){
  return (uint32_t)ESP.getEfuseMac();
}
static void randomKey16(uint8_t out[16]){
  for(int i=0;i<16;i++) out[i] = (uint8_t)esp_random();
}

// ===================== NimBLE Scan callbacks =====================
class AdvCallbacks : public NimBLEAdvertisedDeviceCallbacks {
  void onResult(NimBLEAdvertisedDevice* dev) override {
    if (!dev) return;

    if (!dev->haveManufacturerData()) return;
    std::string mfg = dev->getManufacturerData();
    if (mfg.size() != ADV_LEN_V1 && mfg.size() != ADV_LEN_V2) return;

    bool pairing = false;
    // Service data (16-bit UUID)
    if (dev->haveServiceData()) {
      // En NimBLE-Arduino normalmente solo hay un bloque principal accesible por getServiceDataUUID()
      NimBLEUUID su = dev->getServiceDataUUID();
      if (su.bitSize() == 16 && su.getNative()->u16.value == PAIR_FLAG_UUID16) {
        std::string sd = dev->getServiceData();
        if (sd.size() >= 1) pairing = (uint8_t)sd[0] == 0x01;
      }
    }

    AdvMsg msg;
    msg.len = (uint8_t)mfg.size();
    memcpy(msg.mfg, mfg.data(), msg.len);
    msg.rssi = (int8_t)dev->getRSSI();
    msg.addr = dev->getAddress();
    msg.pairing = pairing;

    cnt_adv_raw++;
    (void)xQueueSend(advQ, &msg, 0);
  }
};

static NimBLEScan* pScan = nullptr;
static AdvCallbacks advCb;

// ===================== Tasks =====================
static void scanTask(void*) {
  NimBLEDevice::init("BLE-GW");
  NimBLEDevice::setPower(ESP_PWR_LVL_P9); // máximo RX
  pScan = NimBLEDevice::getScan();
  pScan->setAdvertisedDeviceCallbacks(&advCb, false);
  pScan->setActiveScan(false);
  pScan->setInterval(160);
  pScan->setWindow(80);

  logln("BLE(NimBLE): scan started");
  pScan->start(0, true); // duration=0 => continuo, isContinue=true (NimBLE-Arduino)

  for(;;) vTaskDelay(pdMS_TO_TICKS(1000));
}

static void procTask(void*) {
  AdvMsg raw;
  for(;;){
    if (xQueueReceive(advQ, &raw, pdMS_TO_TICKS(250)) != pdTRUE) {
      vTaskDelay(pdMS_TO_TICKS(5));
      continue;
    }

    uint16_t dev_id = (uint16_t)raw.mfg[1] | ((uint16_t)raw.mfg[2]<<8);
    uint8_t proto = raw.mfg[0];
    seenUpdate(dev_id, raw.addr, raw.rssi, raw.pairing, proto);

    int si = slotIndexForDev(dev_id);
    if (si < 0) { cnt_unassigned_drop++; continue; }

    const uint8_t* key;
    portENTER_CRITICAL(&slotsMux);
    key = slotKeyOrFactory(slots[si]);
    portEXIT_CRITICAL(&slotsMux);

    Telemetry t;
    if (!decryptAndParse(raw.mfg, raw.len, key, t)) { cnt_dec_fail++; continue; }
    cnt_dec_ok++;

    bool ok_replay=false;
    uint32_t ts=0;
    int16_t mcu=0;
    portENTER_CRITICAL(&slotsMux);
    SlotState& s = slots[si];
    ok_replay = antiReplayCheck(s, t.boot_id, t.ctr24);
    if (ok_replay) {
      s.last_rssi = raw.rssi;
      s.last_seen_ms = millis();
      s.last_temp_x100 = t.temp_x100;
      s.last_vin_mv = t.vin_mv;
      s.last_mcu_x100 = t.mcu_x100;
      s.last_flags = t.flags;
      ts = s.last_seen_ms;
      mcu = s.last_mcu_x100;
    }
    portEXIT_CRITICAL(&slotsMux);

    if (!ok_replay) { cnt_replay_drop++; continue; }

    if (!mqtt.connected()) continue;

    PubMsg pm;
    StaticJsonDocument<256> doc;
    doc["slot"] = si;
    doc["dev_id"] = t.dev_id;
    doc["proto"] = t.proto;
    doc["boot_id"] = t.boot_id;
    doc["ctr"] = t.ctr24;
    doc["temp_c"] = ((float)t.temp_x100)/100.0f;
    doc["vin_v"]  = ((float)t.vin_mv)/1000.0f;
    if (t.proto==PROTO_V2) doc["mcu_c"] = ((float)mcu)/100.0f;
    doc["flags"] = t.flags;
    doc["rssi"]  = raw.rssi;
    doc["ts_ms"] = ts;

    pm.len = serializeJson(doc, pm.payload, sizeof(pm.payload));
    snprintf(pm.topic, sizeof(pm.topic), "%s/slot/%d/telemetry", mqttBase.c_str(), si);

    if (xQueueSend(pubQ, &pm, 0) != pdTRUE) cnt_pub_fail++;
  }
}

// ===================== Web UI helpers =====================
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
  s += "<a href='"; s += href; s += "' style='padding:8px 12px;border:1px solid #ccc;border-radius:12px;text-decoration:none;";
  if (active) s += "background:#111;color:#fff;border-color:#111;font-weight:600;";
  else if (primary) s += "background:#f7f7f7;color:#111;font-weight:600;";
  else s += "background:#f7f7f7;color:#111;";
  s += "'>"; s += label; s += "</a>";
  return s;
}

static String navBar(const String& active) {
  String h;
  h += "<div style='display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:0 0 14px 0'>";
  h += navBtn("/",         "Home",   active=="home",   true);
  h += navBtn("/devices",  "Devices",active=="devices");
  h += navBtn("/pair",     "Pair",   active=="pair");
  h += navBtn("/stat.html","Stat",   active=="stat");
  h += navBtn("/log.html", "Log",    active=="log");
  h += navBtn("/info.html","Info",   active=="info");
  h += navBtn("/config",   "Config", active=="config");
  h += "</div>";
  return h;
}

static String pageWrap(const String& title, const String& active, const String& bodyHtml, uint32_t refreshMs=0) {
  String h;
  h += "<!doctype html><html><head><meta charset='utf-8'>"
       "<meta name='viewport' content='width=device-width,initial-scale=1'>"
       "<title>" + title + "</title>"
       "<style>"
       "body{font-family:system-ui;margin:20px;max-width:1100px}"
       "h2{margin:0 0 12px 0}"
       ".card{border:1px solid #ddd;border-radius:16px;padding:14px;background:#fff;box-shadow:0 1px 2px rgba(0,0,0,.05);margin:12px 0}"
       ".muted{opacity:.75}"
       ".ok{background:#e9f7ee;border-color:#bfe6c9}"
       ".warn{background:#fff5e6;border-color:#ffe0a6}"
       ".bad{background:#ffecec;border-color:#ffbfbf}"
       "pre{padding:12px;border:1px solid #ddd;border-radius:12px;background:#fafafa;overflow:auto}"
       "code{background:#f2f2f2;padding:2px 6px;border-radius:6px}"
       "input,textarea,select{width:100%;padding:10px;border:1px solid #ccc;border-radius:12px;box-sizing:border-box}"
       "button{padding:10px 14px;border:1px solid #ccc;border-radius:12px;background:#111;color:#fff;cursor:pointer}"
       ".btn2{padding:10px 14px;border:1px solid #ccc;border-radius:12px;background:#f7f7f7;color:#111;text-decoration:none;display:inline-block}"
       "table{width:100%;border-collapse:separate;border-spacing:0}"
       "th,td{padding:10px;border-bottom:1px solid #eee;text-align:left;vertical-align:top}"
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
  s += "'>"; s += htmlEscape(t); s += "</span>";
  return s;
}

static String fmt2(float v, int decimals) {
  char b[24];
  dtostrf(v, 0, decimals, b);
  return String(b);
}

// ===================== Pair provisioning via NimBLE Central =====================
// Devuelve true si se pudo escribir PROV+CTL y status muestra provisioned==1
static bool provisionNodeOverGatt(const NimBLEAddress& addr, uint32_t gwid, const uint8_t key[16], int8_t tx_dbm, uint8_t flags, String& outMsg) {
  outMsg = "";

  NimBLEClient* client = nullptr;
  bool ok = false;

  try {
    client = NimBLEDevice::createClient();
    client->setConnectionParams(12, 24, 0, 100); // interval min/max, latency, timeout (100*10ms)
    client->setConnectTimeout(5);

    if (!client->connect(addr)) {
      outMsg = "connect fail";
      NimBLEDevice::deleteClient(client);
      return false;
    }

    NimBLERemoteService* svc = client->getService(SVC_UUID);
    if (!svc) {
      outMsg = "service not found";
      client->disconnect();
      NimBLEDevice::deleteClient(client);
      return false;
    }

    NimBLERemoteCharacteristic* chProv = svc->getCharacteristic(CH_PROV);
    NimBLERemoteCharacteristic* chCtl  = svc->getCharacteristic(CH_CTL);
    NimBLERemoteCharacteristic* chStat = svc->getCharacteristic(CH_STAT);

    if (!chProv || !chCtl || !chStat) {
      outMsg = "chars not found";
      client->disconnect();
      NimBLEDevice::deleteClient(client);
      return false;
    }

    uint8_t buf[22];
    buf[0] = (uint8_t)(gwid & 0xFF);
    buf[1] = (uint8_t)((gwid >> 8) & 0xFF);
    buf[2] = (uint8_t)((gwid >> 16) & 0xFF);
    buf[3] = (uint8_t)((gwid >> 24) & 0xFF);
    memcpy(&buf[4], key, 16);
    buf[20] = (uint8_t)tx_dbm;
    buf[21] = flags;

    if (!chProv->writeValue(buf, sizeof(buf), true)) {
      outMsg = "write PROV fail";
      client->disconnect();
      NimBLEDevice::deleteClient(client);
      return false;
    }

    uint8_t ctl = 0xA5;
    if (!chCtl->writeValue(&ctl, 1, true)) {
      outMsg = "write CTL fail";
      client->disconnect();
      NimBLEDevice::deleteClient(client);
      return false;
    }

    // leer status y validar (status[0] == 1)
    std::string st = chStat->readValue();
    if (st.size() >= 1 && ((uint8_t)st[0]) == 1) {
      ok = true;
      outMsg = "provision ok";
    } else {
      outMsg = "status not provisioned";
    }

    client->disconnect();
    NimBLEDevice::deleteClient(client);
    return ok;

  } catch (...) {
    outMsg = "exception";
    if (client) {
      client->disconnect();
      NimBLEDevice::deleteClient(client);
    }
    return false;
  }
}

// ===================== Web: HOME / DEVICES =====================
static void handleHome(){
  noCacheHeaders();

  String b;
  b += "<h2>BLE Gateway (NimBLE)</h2>";

  b += "<div class='card'>";
  b += "<div><b>AP IP:</b> " + WiFi.softAPIP().toString() + "</div>";
  b += "<div><b>STA IP:</b> " + WiFi.localIP().toString() + "</div>";
  b += "<div><b>STA status:</b> " + String((int)WiFi.status()) + " (3=connected)</div>";
  b += "</div>";

  b += "<div class='card'>";
  b += "<div><b>MQTT:</b> " + htmlEscape(mqttHost) + ":" + String(mqttPort) + "</div>";
  b += "<div><b>Base:</b> " + htmlEscape(mqttBase) + "</div>";
  b += "<div><b>Status:</b> " + String(mqtt.connected() ? "connected" : "disconnected") + "</div>";
  b += "</div>";

  b += "<div class='card muted'>";
  b += "<div><b>Gateway ID:</b> 0x" + String(gatewayId(), HEX) + "</div>";
  b += "<div>Usa <b>/pair</b> para provisionar nodos y asignarlos a slots.</div>";
  b += "</div>";

  server.send(200, "text/html", pageWrap("Home","home",b,0));
}

static void handleDevicesHtml(){
  noCacheHeaders();
  const uint32_t now = millis();
  const uint32_t offline_ms = 5000;

  String b;
  b += "<h2>Devices</h2>";
  b += "<div class='card muted'>Offline si no hay update en &gt; " + String(offline_ms) + " ms.</div>";

  b += "<div class='card' style='padding:0'><div style='overflow:auto;max-height:70vh;border-radius:16px'>";
  b += "<table><thead><tr><th>Slot</th><th>Dev ID</th><th>Key</th><th>Status</th><th>Temp</th><th>VIN</th><th>MCU</th><th>RSSI</th><th>Last</th></tr></thead><tbody>";

  for(int i=0;i<SLOT_COUNT;i++){
    uint16_t id; uint32_t last; int16_t t100; uint16_t vin; int16_t mcu; int8_t rssi; uint8_t flags; uint8_t key[16];
    portENTER_CRITICAL(&slotsMux);
    id = slots[i].dev_id; last = slots[i].last_seen_ms; t100=slots[i].last_temp_x100; vin=slots[i].last_vin_mv; mcu=slots[i].last_mcu_x100; rssi=slots[i].last_rssi; flags=slots[i].last_flags; memcpy(key, slots[i].key, 16);
    portEXIT_CRITICAL(&slotsMux);

    String st; const char* cls="warn";
    if (id==0){ st="empty"; cls="warn"; }
    else if (last==0){ st="waiting"; cls="warn"; }
    else if ((now-last)>offline_ms){ st="offline"; cls="bad"; }
    else { st="online"; cls="ok"; }

    bool keySet=false; for(int k=0;k<16;k++) if (key[k]!=0){ keySet=true; break; }

    b += "<tr>";
    b += "<td><b>"+String(i)+"</b></td>";
    b += "<td>"+String(id)+"</td>";
    b += "<td>"+badge(keySet?"bound":"factory", keySet?"ok":"warn")+"</td>";
    b += "<td>"+badge(st,cls)+"</td>";
    b += "<td>"+(id?fmt2((float)t100/100.0f,2):String("-"))+"</td>";
    b += "<td>"+(id?fmt2((float)vin/1000.0f,3):String("-"))+"</td>";
    b += "<td>"+(id?(mcu?fmt2((float)mcu/100.0f,2):String("-")):String("-"))+"</td>";
    b += "<td>"+(id?String((int)rssi):String("-"))+"</td>";
    b += "<td>"+String((unsigned long)last)+"</td>";
    b += "</tr>";
  }

  b += "</tbody></table></div></div>";
  server.send(200, "text/html", pageWrap("Devices","devices",b,2000));
}

// ===================== Pair Manager =====================
static String lastPairBanner = "";
static String lastPairClass  = "muted";

static void handlePairGet(){
  noCacheHeaders();

  String b;
  b += "<h2>Pair Manager</h2>";
  b += "<div class='card " + lastPairClass + "'>" + htmlEscape(lastPairBanner.length()?lastPairBanner:String("Listando nodos. Solo aparecen con pairing flag (0xFFF0=0x01) como <b>YES</b>.")) + "</div>";

  b += "<div class='card'><h3>Seen nodes (auto-refresh)</h3>";
  b += "<div style='overflow:auto;max-height:70vh'><table><thead><tr><th>Dev ID</th><th>MAC</th><th>RSSI</th><th>Age(ms)</th><th>Proto</th><th>Pairing</th><th>Provision</th></tr></thead><tbody>";

  uint32_t now = millis();
  for(int i=0;i<SEEN_MAX;i++){
    if (seen[i].dev_id==0) continue;

    String mac = String(seen[i].addr.toString().c_str());
    b += "<tr>";
    b += "<td><b>"+String(seen[i].dev_id)+"</b></td>";
    b += "<td><code>"+mac+"</code></td>";
    b += "<td>"+String((int)seen[i].rssi)+"</td>";
    b += "<td>"+String((unsigned long)(now - seen[i].last_ms))+"</td>";
    b += "<td>"+String((int)seen[i].proto)+"</td>";
    b += "<td>"+badge(seen[i].pairing?"YES":"no", seen[i].pairing?"ok":"warn")+"</td>";

    b += "<td>";
    b += "<form method='POST' action='/pair/provision' style='display:flex;gap:8px;align-items:center'>";
    b += "<input type='hidden' name='mac' value='"+mac+"'>";
    b += "<input type='hidden' name='devid' value='"+String(seen[i].dev_id)+"'>";
    b += "<select name='slot' style='max-width:110px'>";
    for(int s=0;s<SLOT_COUNT;s++) b += "<option value='"+String(s)+"'>slot "+String(s)+"</option>";
    b += "</select>";
    b += "<select name='tx' style='max-width:120px'>";
    b += "<option value='0'>0 dBm</option>";
    b += "<option value='4'>+4 dBm</option>";
    b += "<option value='8'>+8 dBm</option>";
    b += "<option value='-4'>-4 dBm</option>";
    b += "</select>";
    b += "<button "+String(seen[i].pairing?"":"disabled")+">Provision</button>";
    b += "</form>";
    b += "</td>";

    b += "</tr>";
  }

  b += "</tbody></table></div></div>";

  b += "<div class='card'><h3>Slots</h3><div style='overflow:auto'><table><thead><tr><th>Slot</th><th>Dev ID</th><th>Key</th><th>Actions</th></tr></thead><tbody>";
  for(int i=0;i<SLOT_COUNT;i++){
    uint16_t id; uint8_t key[16];
    portENTER_CRITICAL(&slotsMux); id=slots[i].dev_id; memcpy(key, slots[i].key,16); portEXIT_CRITICAL(&slotsMux);
    bool keySet=false; for(int k=0;k<16;k++) if(key[k]!=0){ keySet=true; break; }

    b += "<tr>";
    b += "<td><b>"+String(i)+"</b></td>";
    b += "<td>"+String(id)+"</td>";
    b += "<td>"+badge(keySet?"set":"none", keySet?"ok":"warn")+"</td>";
    b += "<td style='white-space:nowrap'>";
    b += "<form method='POST' action='/pair/remove' style='display:inline'><input type='hidden' name='slot' value='"+String(i)+"'><button>Remove</button></form> ";
    b += "</td></tr>";
  }
  b += "</tbody></table></div></div>";

  server.send(200, "text/html", pageWrap("Pair","pair",b,2000));
}

static void handlePairProvisionPost(){
  lastPairBanner = "";
  lastPairClass  = "muted";

  String mac = server.arg("mac");
  // Resolver MAC -> NimBLEAddress sin parsear string (compat con NimBLE-Arduino h2zero)
  bool foundAddr = false;
  NimBLEAddress addr;
  for (int i = 0; i < SEEN_MAX; i++) {
    if (seen[i].dev_id == 0) continue;
    String m = String(seen[i].addr.toString().c_str());
    if (m == mac) { addr = seen[i].addr; foundAddr = true; break; }
  }
  if (!foundAddr) {
    lastPairBanner = "MAC no encontrada en tabla seen[] (espera a que aparezca en /pair).";
    lastPairClass = "bad";
    server.sendHeader("Location","/pair"); server.send(303);
    return;
  }

  uint16_t devid = (uint16_t)server.arg("devid").toInt();
  int slot = server.arg("slot").toInt();
  int tx = server.arg("tx").toInt();

  if (slot < 0 || slot >= SLOT_COUNT) {
    lastPairBanner = "Bad slot";
    lastPairClass = "bad";
    server.sendHeader("Location","/pair"); server.send(303);
    return;
  }

  std::string macs = std::string(mac.c_str());
  uint8_t key[16];
  randomKey16(key);

  String msg;
  bool ok = provisionNodeOverGatt(addr, gatewayId(), key, (int8_t)tx, 0x00, msg);

  if (ok) {
    portENTER_CRITICAL(&slotsMux);
    slots[slot].dev_id = devid;
    memcpy(slots[slot].key, key, 16);
    portEXIT_CRITICAL(&slotsMux);
    saveSlotsToNVS();
    lastPairBanner = "Provision OK. Slot " + String(slot) + " dev_id=" + String(devid) + " key=" + bytesToHex(key,16);
    lastPairClass = "ok";
    logln("PAIR: provision ok");
  } else {
    lastPairBanner = "Provision FAIL (" + msg + ").";
    lastPairClass = "bad";
    logln("PAIR: provision fail");
  }

  server.sendHeader("Location","/pair"); server.send(303);
}

static void handlePairRemovePost(){
  int slot = server.arg("slot").toInt();
  if (slot < 0 || slot >= SLOT_COUNT) { server.send(400,"text/plain","bad slot"); return; }

  portENTER_CRITICAL(&slotsMux);
  slots[slot].dev_id = 0;
  memset(slots[slot].key, 0, 16);
  slots[slot].last_seen_ms = 0;
  portEXIT_CRITICAL(&slotsMux);

  saveSlotsToNVS();
  lastPairBanner = "Slot " + String(slot) + " cleared";
  lastPairClass = "warn";
  server.sendHeader("Location","/pair"); server.send(303);
}

// ===================== STAT/LOG/INFO =====================
static void handleStatText(){
  char buf[520];
  snprintf(buf,sizeof(buf),
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
    (unsigned long)cnt_adv_raw,(unsigned long)cnt_dec_ok,(unsigned long)cnt_dec_fail,(unsigned long)cnt_replay_drop,
    (unsigned long)cnt_unassigned_drop,(unsigned long)cnt_pub_ok,(unsigned long)cnt_pub_fail,(unsigned long)cnt_mqtt_conn_ok,(unsigned long)cnt_mqtt_conn_fail,
    (int)WiFi.status(), WiFi.localIP().toString().c_str()
  );
  server.send(200,"text/plain",buf);
}

static void handleStatHtml(){
  noCacheHeaders();
  String b;
  b += "<h2>Stat</h2><div class='card'><pre>";
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
  b += "</pre></div>";
  server.send(200,"text/html",pageWrap("Stat","stat",b,2000));
}

static void handleLogText(){ server.send(200,"text/plain",getLogString()); }

static void handleLogHtml(){
  noCacheHeaders();
  String b;
  b += "<h2>Log</h2><div class='card'><pre style='max-height:70vh'>";
  b += htmlEscape(getLogString());
  b += "</pre></div>";
  server.send(200,"text/html",pageWrap("Log","log",b,3000));
}

static void handleInfoText(){
  char buf[340];
  snprintf(buf,sizeof(buf),
    "ap_ip=%s\nsta_ip=%s\nsta_status=%d\nheap_free=%u\nreset_reason=%d\ngateway_id=0x%08lx\nmqtt=%s:%u\n",
    WiFi.softAPIP().toString().c_str(),
    WiFi.localIP().toString().c_str(),
    (int)WiFi.status(),
    (unsigned)ESP.getFreeHeap(),
    (int)esp_reset_reason(),
    (unsigned long)gatewayId(),
    mqttHost.c_str(), (unsigned)mqttPort
  );
  server.send(200,"text/plain",buf);
}

static void handleInfoHtml(){
  noCacheHeaders();
  String b;
  b += "<h2>Info</h2><div class='card'><pre>";
  b += "ap_ip=" + WiFi.softAPIP().toString() + "\n";
  b += "sta_status=" + String((int)WiFi.status()) + "\n";
  b += "sta_ip=" + WiFi.localIP().toString() + "\n";
  b += "heap_free=" + String((unsigned)ESP.getFreeHeap()) + "\n";
  b += "reset_reason=" + String((int)esp_reset_reason()) + "\n";
  b += "gateway_id=0x" + String(gatewayId(), HEX) + "\n";
  b += "</pre></div>";
  server.send(200,"text/html",pageWrap("Info","info",b,0));
}

// ===================== CONFIG =====================
static bool cfg_last_saved=false, cfg_last_sta_ok=false, cfg_last_mqtt_ok=false;
static String cfg_last_ip="", cfg_last_msg="";

static void renderConfigPage(){
  noCacheHeaders();
  String b;
  b += "<h2>Config WiFi + MQTT</h2>";

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

  b += "<label><input type='checkbox' name='reboot' value='1'> Reiniciar después de guardar</label><br><br>";

  b += "<div style='display:flex;gap:10px;flex-wrap:wrap'>";
  b += "<button type='submit'>Save</button>";
  b += "<a class='btn2' href='/'>Exit</a>";
  b += "</div>";

  b += "</form></div>";

  server.send(200,"text/html",pageWrap("Config","config",b,0));
}

static void handleConfigGet(){ cfg_last_saved=false; cfg_last_msg=""; renderConfigPage(); }

static void handleConfigPost(){
  if (server.hasArg("ssid")) wifiSsid = server.arg("ssid");
  if (server.hasArg("pass")) wifiPass = server.arg("pass");

  if (server.hasArg("mhost")) mqttHost = server.arg("mhost");
  if (server.hasArg("mport")) mqttPort = (uint16_t)server.arg("mport").toInt();
  if (server.hasArg("muser")) mqttUser = server.arg("muser");
  if (server.hasArg("mpass")) mqttPasswd = server.arg("mpass");
  if (server.hasArg("mbase")) mqttBase = server.arg("mbase");

  wifiSsid.trim(); wifiPass.trim();
  mqttHost.trim(); mqttUser.trim(); mqttPasswd.trim(); mqttBase.trim();

  if (!mqttHost.length()) mqttHost = MQTT_HOST_DEFAULT;
  if (!mqttPort) mqttPort = MQTT_PORT_DEFAULT;
  if (!mqttBase.length()) mqttBase = MQTT_BASE_DEFAULT;

  saveConfigBase();

  cfg_last_sta_ok = tryWiFiSTAHot(6000);
  cfg_last_ip = (WiFi.status()==WL_CONNECTED) ? WiFi.localIP().toString() : "";
  cfg_last_mqtt_ok = tryMQTTHot(2500);

  cfg_last_saved=true;
  cfg_last_msg="Reconexión en caliente ejecutada.";

  logln("CFG: saved");
  logln(cfg_last_sta_ok ? "CFG: STA ok" : "CFG: STA fail");
  logln(cfg_last_mqtt_ok ? "CFG: MQTT ok" : "CFG: MQTT fail");

  renderConfigPage();

  if (server.hasArg("reboot") && server.arg("reboot")=="1") { delay(400); ESP.restart(); }
}

// ===================== Web setup =====================
static void handleNotFound(){
  String m="404\nuri="+server.uri()+"\n";
  server.send(404,"text/plain",m);
}

static void webSetup(){
  server.on("/", handleHome);
  server.on("/devices", handleDevicesHtml);

  server.on("/pair", handlePairGet);
  server.on("/pair/provision", HTTP_POST, handlePairProvisionPost);
  server.on("/pair/remove", HTTP_POST, handlePairRemovePost);

  server.on("/stat", handleStatText);
  server.on("/stat.html", handleStatHtml);
  server.on("/log", handleLogText);
  server.on("/log.html", handleLogHtml);
  server.on("/info", handleInfoText);
  server.on("/info.html", handleInfoHtml);

  server.on("/config", HTTP_GET, handleConfigGet);
  server.on("/config", HTTP_POST, handleConfigPost);

  server.onNotFound(handleNotFound);
  server.begin();
  logln("WEB: started");
}

// ===================== setup / loop =====================
void setup(){
  pinMode(LED_PIN, OUTPUT);
  ledWrite(false);

  Serial.begin(115200);
  delay(200);

  checkFactoryResetAtBoot();
  logln("BOOT: gateway start (NimBLE + Pair Manager)");

  advQ = xQueueCreate(96, sizeof(AdvMsg));
  pubQ = xQueueCreate(64, sizeof(PubMsg));
  if (!advQ) logln("ERR: advQ alloc failed");
  if (!pubQ) logln("ERR: pubQ alloc failed");

  loadConfig();
  mqttApplyConfig();

  wifiBoot();
  webSetup();

  // Tareas: scan en core 0, proc en core 1
  xTaskCreatePinnedToCore(scanTask, "scanTask", 8192, nullptr, 2, nullptr, 0);
  xTaskCreatePinnedToCore(procTask, "procTask", 8192, nullptr, 2, nullptr, 1);
}

void loop(){
  server.handleClient();
  mqtt.loop();
  mqttEnsureNonBlocking();

  statusLedTick(WiFi.status()==WL_CONNECTED, mqtt.connected());

  // Publicación MQTT (solo en loop)
  if (pubQ && mqtt.connected()){
    PubMsg pm;
    while(xQueueReceive(pubQ, &pm, 0)==pdTRUE){
      if (mqtt.publish(pm.topic, pm.payload, pm.len)) cnt_pub_ok++;
      else cnt_pub_fail++;
    }
  } else if (pubQ) {
    PubMsg pm;
    while(xQueueReceive(pubQ, &pm, 0)==pdTRUE) {}
  }

  static uint32_t hb=0;
  if (millis()-hb>5000){ hb=millis(); logln("HB: alive"); }

  delay(5);
}
