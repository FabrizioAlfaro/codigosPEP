#include <bluefruit.h>
#include <Wire.h>

#include <Adafruit_LittleFS.h>
#include <InternalFileSystem.h>
using namespace Adafruit_LittleFS_Namespace;

#include <Crypto.h>
#include <AES.h>
#include <EAX.h>

// ===================== TMP117 =====================
#define SDA_PIN D4
#define SCL_PIN D5
static const uint8_t TMP117_ADDR  = 0x49;      // ADDR a V+
static const uint8_t REG_TEMP     = 0x00;
static const float   TMP117_LSB_C = 0.0078125f;

// ===================== VIN ADC (tu hardware) =====================
// Punto medio divisor -> A3 (P0.29)
// R2 a "tierra conmutada" -> D6 (P1.11)
#define PIN_ADC    A3
#define PIN_GND_SW D6
static const float VREF = 3.3f;
static const float DIV_FACTOR = 2.0f;          // 1M/1M
static const uint8_t N_SAMPLES = 8;

// ===================== Protocolo ADV =====================
static const uint8_t  PROTO_VER = 0x01;
static const uint16_t DEV_ID    = 0x0003;      // <<< CAMBIA por nodo

// Clave de grupo AES-128 (16 bytes) - MISMA en gateway
static const uint8_t GROUP_KEY[16] = {
  0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
  0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10
};

// Manufacturer payload (23 bytes):
// [0] proto_ver
// [1..2] dev_id LE
// [3..6] boot_id LE
// [7..9] ctr24 LE
// [10..14] ct(5) = {temp_x100 int16, vin_mv uint16, flags u8}
// [15..22] tag(8)
static uint8_t mfg[23];

static uint32_t boot_id = 0;
static uint32_t ctr32 = 0; // usaremos ctr24 = ctr32 & 0xFFFFFF

// Persistencia boot_id
static const char *BOOT_FILE = "/boot.bin";
File bootFile(InternalFS);

// Crypto
EAX<AES128> eax;

// ===================== I2C helper =====================
bool i2cRead16(uint8_t addr, uint8_t reg, uint16_t &val) {
  Wire.beginTransmission(addr);
  Wire.write(reg);
  if (Wire.endTransmission(false) != 0) return false;
  if (Wire.requestFrom((int)addr, 2) != 2) return false;
  val = ((uint16_t)Wire.read() << 8) | Wire.read();
  return true;
}

bool readTMP117_x100(int16_t &temp_x100) {
  uint16_t raw;
  if (!i2cRead16(TMP117_ADDR, REG_TEMP, raw)) return false;
  float tC = ((int16_t)raw) * TMP117_LSB_C;
  temp_x100 = (int16_t)(tC * 100.0f + (tC >= 0 ? 0.5f : -0.5f));
  return true;
}

// ===================== ADC helper =====================
uint16_t readAdcAvgRaw() {
  pinMode(PIN_GND_SW, OUTPUT);
  digitalWrite(PIN_GND_SW, LOW);

  delay(5);
  (void)analogRead(PIN_ADC);
  delayMicroseconds(300);

  uint32_t acc = 0;
  for (uint8_t i = 0; i < N_SAMPLES; i++) {
    acc += analogRead(PIN_ADC);
    delayMicroseconds(300);
  }

  pinMode(PIN_GND_SW, INPUT);

  float rawAvg = (float)acc / (float)N_SAMPLES;
  return (uint16_t)(rawAvg + 0.5f);
}

uint16_t rawToVin_mV(uint16_t raw) {
  float v_adc = (raw * VREF) / 4095.0f;
  float vin   = v_adc * DIV_FACTOR;
  int mv = (int)(vin * 1000.0f + 0.5f);
  if (mv < 0) mv = 0;
  return (uint16_t)mv;
}

// ===================== boot_id persistente =====================
void loadAndBumpBootId() {
  InternalFS.begin();

  uint32_t v = 0;
  if (bootFile.open(BOOT_FILE, FILE_O_READ)) {
    if (bootFile.size() == 4) bootFile.read((uint8_t*)&v, 4);
    bootFile.close();
  }
  v += 1;
  boot_id = v;

  if (bootFile.open(BOOT_FILE, FILE_O_WRITE)) {
    bootFile.seek(0);
    bootFile.write((uint8_t*)&boot_id, 4);
    bootFile.truncate(4);
    bootFile.close();
  }
}

// ===================== Construir paquete cifrado =====================
void buildEncryptedAdv() {
  int16_t  temp_x100 = 0;
  uint8_t  flags = 0;

  if (!readTMP117_x100(temp_x100)) flags |= 0x01;

  uint16_t raw = readAdcAvgRaw();
  uint16_t vin_mv = rawToVin_mV(raw);

  // Plaintext 5 bytes
  uint8_t pt[5];
  pt[0] = (uint8_t)(temp_x100 & 0xFF);
  pt[1] = (uint8_t)((temp_x100 >> 8) & 0xFF);
  pt[2] = (uint8_t)(vin_mv & 0xFF);
  pt[3] = (uint8_t)((vin_mv >> 8) & 0xFF);
  pt[4] = flags;

  uint32_t ctr24 = (ctr32++ & 0xFFFFFF);

  // Header
  mfg[0] = PROTO_VER;
  mfg[1] = (uint8_t)(DEV_ID & 0xFF);
  mfg[2] = (uint8_t)((DEV_ID >> 8) & 0xFF);

  mfg[3] = (uint8_t)(boot_id & 0xFF);
  mfg[4] = (uint8_t)((boot_id >> 8) & 0xFF);
  mfg[5] = (uint8_t)((boot_id >> 16) & 0xFF);
  mfg[6] = (uint8_t)((boot_id >> 24) & 0xFF);

  mfg[7] = (uint8_t)(ctr24 & 0xFF);
  mfg[8] = (uint8_t)((ctr24 >> 8) & 0xFF);
  mfg[9] = (uint8_t)((ctr24 >> 16) & 0xFF);

  // IV 16 bytes: dev_id(2) boot_id(4) ctr(3) proto(1) padding(6)
  uint8_t iv[16] = {0};
  iv[0] = mfg[1]; iv[1] = mfg[2];
  memcpy(&iv[2], &mfg[3], 4);
  memcpy(&iv[6], &mfg[7], 3);
  iv[9] = PROTO_VER;

  // AAD = header 10 bytes
  uint8_t aad[10];
  memcpy(aad, mfg, sizeof(aad));

  eax.clear();
  eax.setKey(GROUP_KEY, sizeof(GROUP_KEY));
  eax.setIV(iv, sizeof(iv));
  eax.addAuthData(aad, sizeof(aad));

  // Ciphertext -> mfg[10..14]
  eax.encrypt(&mfg[10], pt, sizeof(pt));

  // Tag truncado 8 bytes -> mfg[15..22]
  eax.computeTag(&mfg[15], 8);
}

// ===================== Advertising estable (sin resets) =====================
// Configura el advertising UNA vez en setup.
// Para “actualizar” manufacturer data sin softdevice drama, hacemos:
//   stop -> clearData -> add -> start(1)
// (start(1) evita algunos estados raros al relanzar)
// Intervalos se configuran UNA vez.
void advStartWithCurrentMfg() {
  Bluefruit.Advertising.stop();
  Bluefruit.Advertising.clearData();
  Bluefruit.ScanResponse.clearData();

  Bluefruit.Advertising.addFlags(BLE_GAP_ADV_FLAGS_LE_ONLY_GENERAL_DISC_MODE);
  Bluefruit.Advertising.addTxPower();
  Bluefruit.Advertising.addManufacturerData(mfg, sizeof(mfg));

  // Intervalo de radio para ADV (100 ms base)
  Bluefruit.Advertising.setInterval(160, 160);
  Bluefruit.Advertising.start(1); // 1 segundo (se relanza cada loop)
}

// ===================== GATT mínimo (stub para futuro) =====================
BLEService cfgService("12345678-1234-5678-1234-56789abc0000");
BLECharacteristic cfgChar("12345678-1234-5678-1234-56789abc0001");

void setupGattStub() {
  cfgService.begin();
  cfgChar.setProperties(CHR_PROPS_READ | CHR_PROPS_WRITE);
  cfgChar.setPermission(SECMODE_OPEN, SECMODE_OPEN);
  cfgChar.setFixedLen(4); // placeholder
  uint8_t v[4] = {0,0,0,0};
  cfgChar.begin();
  cfgChar.write(v, sizeof(v));
}

void printBootConfig() {
  Serial.println();
  Serial.println("=== BOOT CONFIG ===");
  Serial.print("PROTO_VER: "); Serial.println(PROTO_VER);
  Serial.print("DEV_ID: 0x"); Serial.println(DEV_ID, HEX);
  Serial.print("BOOT_ID: "); Serial.println(boot_id);
  Serial.println("PUB: 500 ms + jitter 0..30 ms");
  Serial.print("TMP117 addr: 0x"); Serial.println(TMP117_ADDR, HEX);
  Serial.println("I2C: SDA=D4  SCL=D5");
  Serial.println("VIN: mid=A3(P0.29)  gnd_sw=D6(P1.11)");
  Serial.println("DIV: 1M/1M factor 2.0");
  Serial.println("AEAD: AES-EAX key=16B tag=8B");
  Serial.println("===================");
}

void setup() {
  Serial.begin(115200);
  delay(200);
  unsigned long t0 = millis();
  while (!Serial && (millis() - t0 < 1500)) delay(10);

  // ADC
  analogReadResolution(12);
  pinMode(PIN_ADC, INPUT);
  pinMode(PIN_GND_SW, INPUT);

  // I2C
  Wire.setPins(SDA_PIN, SCL_PIN);
  Wire.begin();

  // boot_id persistente
  loadAndBumpBootId();

  // RNG para jitter
  randomSeed(boot_id ^ DEV_ID);

  // BLE
  Bluefruit.begin();
  Bluefruit.setName("XIAO-TLM");
  Bluefruit.autoConnLed(false);

  setupGattStub();

  printBootConfig();
}

void loop() {
  buildEncryptedAdv();
  advStartWithCurrentMfg();

  uint16_t jitter = (uint16_t)random(0, 31);
  delay(500 + jitter);
}

