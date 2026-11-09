#pragma once

#include <string.h>
#include <Packet.h>

/*
 * IDF private relay (selective forwarding) - pure decision logic, unit tested natively.
 *
 * When a repeater's private mode is active, only traffic it can recognise as the team's is
 * forwarded. Team radios need no change: they stay ordinary, unscoped MeshCore radios and keep
 * using every other repeater. This only limits what THIS repeater passes on, to save airtime and
 * battery. It is load shedding, not access control:
 *  - team channel packets (GRP_TXT / GRP_DATA): channel hash and MAC checked against the team
 *    channel secrets this repeater holds - strong;
 *  - adverts: the full public key must be on the approved list - strong (the advert signature is
 *    already verified by Mesh before forwarding);
 *  - TXT_MSG, REQ, RESPONSE, PATH: forwarded when the 1-byte destination or source hash matches an
 *    approved radio - LOOSE (1-byte hashes collide: with 8 approved radios roughly 6% of strangers'
 *    packets of these types also match);
 *  - ANON_REQ (logins): destination hash must match an approved radio (eg. another IDF repeater);
 *  - ACK, MULTIPART: always forwarded (tiny, and carry nothing to recognise; dropping them would
 *    break delivery confirmations of team messages);
 *  - everything else (TRACE, CONTROL, RAW_CUSTOM, reserved): not forwarded.
 * Packets addressed to this repeater itself (logins, admin commands) are handled before forwarding
 * and are never affected.
 */

#ifndef PRIVATE_MAX_APPROVED
  #define PRIVATE_MAX_APPROVED 32
#endif
#ifndef PRIVATE_MAX_CHANNELS
  #define PRIVATE_MAX_CHANNELS 4
#endif

namespace mesh {

struct PrivateChannel {
  uint8_t hash;                  // first byte of SHA-256(secret), as MeshCore channels compute it
  uint8_t secret[PUB_KEY_SIZE];  // 16-byte secrets are zero padded, as in GroupChannel
};

struct PrivateRelayLists {
  uint8_t num_approved;
  uint8_t approved[PRIVATE_MAX_APPROVED][PUB_KEY_SIZE];
  uint8_t num_channels;
  PrivateChannel channels[PRIVATE_MAX_CHANNELS];

  void clear() { memset(this, 0, sizeof(*this)); }

  int findApproved(const uint8_t* key, int key_len) const {
    for (int i = 0; i < num_approved; i++) {
      if (memcmp(approved[i], key, key_len) == 0) return i;
    }
    return -1;
  }

  bool hashApproved(uint8_t h) const {
    for (int i = 0; i < num_approved; i++) {
      if (approved[i][0] == h) return true;
    }
    return false;
  }
};

/** Checks a group packet's MAC with a channel secret (the repeater passes Utils::MACThenDecrypt). */
typedef bool (*GroupMacCheck)(const uint8_t* secret, const uint8_t* mac_and_data, int len);

enum PrivateVerdict : uint8_t {
  PV_TEAM_CHANNEL = 0,
  PV_APPROVED_ADVERT,
  PV_APPROVED_HASH,
  PV_ALWAYS,          // ACK / MULTIPART
  PV_DROP_CHANNEL,    // group packet that is not a team channel
  PV_DROP_ADVERT,     // advert from a radio that is not approved
  PV_DROP_HASH,       // peer packet with no approved hash
  PV_DROP_TYPE,       // type never forwarded in private mode
  PV_COUNT
};

inline bool privateVerdictForwards(PrivateVerdict v) { return v <= PV_ALWAYS; }

inline const char* privateVerdictName(PrivateVerdict v) {
  static const char* names[PV_COUNT] = {"team-chan", "adv-ok", "hash-ok", "ack", "drop-chan",
                                        "drop-adv", "drop-hash", "drop-type"};
  return v < PV_COUNT ? names[v] : "?";
}

inline PrivateVerdict privateRelayVerdict(const Packet* pkt, const PrivateRelayLists& lists,
                                          GroupMacCheck mac_ok) {
  const uint8_t* p = pkt->payload;
  int len = pkt->payload_len;
  switch (pkt->getPayloadType()) {
    case PAYLOAD_TYPE_ADVERT:
      if (len >= PUB_KEY_SIZE && lists.findApproved(p, PUB_KEY_SIZE) >= 0) return PV_APPROVED_ADVERT;
      return PV_DROP_ADVERT;

    case PAYLOAD_TYPE_GRP_TXT:
    case PAYLOAD_TYPE_GRP_DATA:
      if (len > 1 + CIPHER_MAC_SIZE && mac_ok != NULL) {
        for (int i = 0; i < lists.num_channels; i++) {
          if (lists.channels[i].hash == p[0] && mac_ok(lists.channels[i].secret, &p[1], len - 1)) {
            return PV_TEAM_CHANNEL;
          }
        }
      }
      return PV_DROP_CHANNEL;

    case PAYLOAD_TYPE_TXT_MSG:
    case PAYLOAD_TYPE_REQ:
    case PAYLOAD_TYPE_RESPONSE:
    case PAYLOAD_TYPE_PATH:
      if (len >= 2 && (lists.hashApproved(p[0]) || lists.hashApproved(p[1]))) return PV_APPROVED_HASH;
      return PV_DROP_HASH;

    case PAYLOAD_TYPE_ANON_REQ:
      if (len >= 1 && lists.hashApproved(p[0])) return PV_APPROVED_HASH;
      return PV_DROP_HASH;

    case PAYLOAD_TYPE_ACK:
    case PAYLOAD_TYPE_MULTIPART:
      return PV_ALWAYS;

    default:
      return PV_DROP_TYPE;
  }
}

/**
 * Automatic private mode on low battery, with hysteresis.
 * \param  active   current automatic state
 * \param  batt_mv  latest battery reading (0 = unknown: state unchanged)
 * \param  below_mv go private below this (0 = automatic switching off)
 * \returns the new automatic state
 */
inline bool privateAutoState(bool active, uint16_t batt_mv, uint16_t below_mv,
                             uint16_t hysteresis_mv = 100) {
  if (below_mv == 0) return false;
  if (batt_mv == 0) return active;
  if (!active && batt_mv < below_mv) return true;
  if (active && batt_mv >= (uint32_t)below_mv + hysteresis_mv) return false;
  return active;
}

}  // namespace mesh
