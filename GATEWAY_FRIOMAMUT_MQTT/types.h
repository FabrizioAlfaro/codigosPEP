#pragma once
#include <stdint.h>

struct RawAdvMsg {
  uint8_t  mfg[23];
  int8_t   rssi;
};

struct Telemetry {
  uint16_t dev_id;
  uint32_t boot_id;
  uint32_t ctr24;
  int16_t  temp_x100;
  uint16_t vin_mv;
  uint8_t  flags;
};

struct SlotState {
  uint16_t dev_id = 0;   // 0 = slot vacío

  uint32_t last_boot_id = 0;
  uint32_t last_ctr24   = 0;

  int16_t  last_temp_x100 = 0;
  uint16_t last_vin_mv    = 0;
  uint8_t  last_flags     = 0;
  int8_t   last_rssi      = -127;
  uint32_t last_seen_ms   = 0;
};
