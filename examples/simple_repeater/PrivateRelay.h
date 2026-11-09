#pragma once

// IDF private relay: repeater state, persistence and admin commands around PrivateRelayPolicy.h.
// Off by default; with it off the repeater behaves exactly like stock MeshCore.

#include <Mesh.h>
#include <helpers/PrivateRelayPolicy.h>

#include <helpers/IdentityStore.h>   // defines FILESYSTEM (and File) for each platform

class PrivateRelay {
  mesh::PrivateRelayLists _lists;
  uint8_t _switch_on;        // operator switch ("private on")
  uint16_t _timed_min_left;  // "private on <minutes>": minutes left; never saved, so a restart is public
  uint16_t _auto_below_mv;   // 0 = no automatic switching
  bool _auto_active;
  uint16_t _last_batt_mv;
  uint32_t _counts[mesh::PV_COUNT];

  // Radios recently heard by their (signature-checked) adverts, so an operator can approve one
  // by name or key prefix instead of typing 64 hex digits. RAM only.
  struct Heard { uint8_t key[PUB_KEY_SIZE]; char name[24]; uint32_t seq; };
  enum { HEARD_MAX = 16 };
  Heard _heard[HEARD_MAX];
  uint32_t _heard_seq;
  const Heard* findHeard(const char* name_or_hex) const;

  static bool groupMacOk(const uint8_t* secret, const uint8_t* mac_and_data, int len);
  void list(const char* arg, char* reply) const;

public:
  PrivateRelay();

  bool isActive() const { return _switch_on || _auto_active || _timed_min_left > 0; }

  /** Called from allowPacketForward() after the stock checks. true = may forward. */
  bool allowForward(const mesh::Packet* pkt);

  /** Called about once a minute with the battery reading (mV, 0 = unknown); also counts down a
   *  timed private window. */
  void tick(uint16_t batt_mv);

  /** Called for every advert whose signature checked out (any type, any hop count). */
  void noteAdvert(const uint8_t* pub_key, const char* name);

  bool load(FILESYSTEM* fs);
  bool save(FILESYSTEM* fs);

  /** Admin command after the word "private" (args may be empty). reply: up to ~150 chars. */
  void handleCommand(const char* args, char* reply, FILESYSTEM* fs);
};
