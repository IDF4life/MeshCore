#pragma once

// IDF private relay: repeater state, persistence and admin commands around PrivateRelayPolicy.h.
// Off by default; with it off the repeater behaves exactly like stock MeshCore.

#include <Mesh.h>
#include <helpers/PrivateRelayPolicy.h>

#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  #include <InternalFileSystem.h>
#elif defined(RP2040_PLATFORM)
  #include <LittleFS.h>
#elif defined(ESP32)
  #include <SPIFFS.h>
#endif

class PrivateRelay {
  mesh::PrivateRelayLists _lists;
  uint8_t _switch_on;        // operator switch ("private on")
  uint16_t _auto_below_mv;   // 0 = no automatic switching
  bool _auto_active;
  uint16_t _last_batt_mv;
  uint32_t _counts[mesh::PV_COUNT];

  static bool groupMacOk(const uint8_t* secret, const uint8_t* mac_and_data, int len);
  void list(const char* arg, char* reply) const;

public:
  PrivateRelay();

  bool isActive() const { return _switch_on || _auto_active; }

  /** Called from allowPacketForward() after the stock checks. true = may forward. */
  bool allowForward(const mesh::Packet* pkt);

  /** Called about once a minute with the battery reading (mV, 0 = unknown). */
  void tick(uint16_t batt_mv);

  bool load(FILESYSTEM* fs);
  bool save(FILESYSTEM* fs);

  /** Admin command after the word "private" (args may be empty). reply: up to ~150 chars. */
  void handleCommand(const char* args, char* reply, FILESYSTEM* fs);
};
