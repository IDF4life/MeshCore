#include "PrivateRelay.h"

#include <Utils.h>

#define PRIVATE_RELAY_FILE   "/idf_private"
#define PRIVATE_RELAY_MAGIC  0x49445031UL  // "IDP1"

PrivateRelay::PrivateRelay() {
  _lists.clear();
  _switch_on = 0;
  _timed_min_left = 0;
  _auto_below_mv = 0;
  _auto_active = false;
  _last_batt_mv = 0;
  memset(_counts, 0, sizeof(_counts));
  memset(_heard, 0, sizeof(_heard));
  _heard_seq = 0;
}

void PrivateRelay::noteAdvert(const uint8_t* pub_key, const char* name) {
  int slot = 0;
  for (int i = 0; i < HEARD_MAX; i++) {
    if (_heard[i].seq && memcmp(_heard[i].key, pub_key, PUB_KEY_SIZE) == 0) { slot = i; break; }
    if (_heard[i].seq < _heard[slot].seq) slot = i;   // oldest (or empty) slot
  }
  memcpy(_heard[slot].key, pub_key, PUB_KEY_SIZE);
  memset(_heard[slot].name, 0, sizeof(_heard[slot].name));
  if (name) strncpy(_heard[slot].name, name, sizeof(_heard[slot].name) - 1);
  _heard[slot].seq = ++_heard_seq;
}

const PrivateRelay::Heard* PrivateRelay::findHeard(const char* q) const {
  int ql = strlen(q);
  uint8_t pre[PUB_KEY_SIZE];
  bool hex = ql >= 6 && ql <= PUB_KEY_SIZE * 2 && (ql & 1) == 0 && mesh::Utils::fromHex(pre, ql / 2, q);
  const Heard* found = NULL;
  for (int i = 0; i < HEARD_MAX; i++) {
    const Heard* h = &_heard[i];
    if (!h->seq) continue;
    bool match = strcmp(h->name, q) == 0 || (hex && memcmp(h->key, pre, ql / 2) == 0);
    if (match) {
      if (found && memcmp(found->key, h->key, PUB_KEY_SIZE) != 0) return NULL;  // ambiguous
      found = h;
    }
  }
  return found;
}

bool PrivateRelay::groupMacOk(const uint8_t* secret, const uint8_t* mac_and_data, int len) {
  uint8_t tmp[MAX_PACKET_PAYLOAD];
  if (len <= 0 || len > MAX_PACKET_PAYLOAD) return false;
  return mesh::Utils::MACThenDecrypt(secret, tmp, mac_and_data, len) > 0;
}

bool PrivateRelay::allowForward(const mesh::Packet* pkt) {
  if (!isActive()) return true;
  mesh::PrivateVerdict v = mesh::privateRelayVerdict(pkt, _lists, groupMacOk);
  if (v < mesh::PV_COUNT) _counts[v]++;
  return mesh::privateVerdictForwards(v);
}

void PrivateRelay::tick(uint16_t batt_mv) {
  if (_timed_min_left > 0) _timed_min_left--;   // called once a minute
  if (batt_mv > 0) _last_batt_mv = batt_mv;
  // Never go private automatically with nothing approved: it would block every team packet too.
  bool lists_empty = _lists.num_approved == 0 && _lists.num_channels == 0;
  _auto_active = lists_empty ? false : mesh::privateAutoState(_auto_active, batt_mv, _auto_below_mv);
}

static File openForWrite(FILESYSTEM* fs, const char* name) {
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  fs->remove(name);
  return fs->open(name, FILE_O_WRITE);
#elif defined(RP2040_PLATFORM)
  return fs->open(name, "w");
#else
  return fs->open(name, "w", true);
#endif
}

bool PrivateRelay::save(FILESYSTEM* fs) {
  File f = openForWrite(fs, PRIVATE_RELAY_FILE);
  if (!f) return false;
  uint32_t magic = PRIVATE_RELAY_MAGIC;
  bool ok = f.write((uint8_t*)&magic, sizeof(magic)) == sizeof(magic);
  ok = ok && f.write(&_switch_on, 1) == 1;
  ok = ok && f.write((uint8_t*)&_auto_below_mv, sizeof(_auto_below_mv)) == sizeof(_auto_below_mv);
  ok = ok && f.write((uint8_t*)&_lists, sizeof(_lists)) == sizeof(_lists);
  f.close();
  return ok;
}

bool PrivateRelay::load(FILESYSTEM* fs) {
  if (!fs->exists(PRIVATE_RELAY_FILE)) return false;
#if defined(RP2040_PLATFORM)
  File f = fs->open(PRIVATE_RELAY_FILE, "r");
#else
  File f = fs->open(PRIVATE_RELAY_FILE);
#endif
  if (!f) return false;
  uint32_t magic = 0;
  uint8_t sw = 0;
  uint16_t mv = 0;
  mesh::PrivateRelayLists l;
  bool ok = f.read((uint8_t*)&magic, sizeof(magic)) == sizeof(magic) && magic == PRIVATE_RELAY_MAGIC;
  ok = ok && f.read(&sw, 1) == 1;
  ok = ok && f.read((uint8_t*)&mv, sizeof(mv)) == sizeof(mv);
  ok = ok && f.read((uint8_t*)&l, sizeof(l)) == sizeof(l);
  f.close();
  // A damaged or unknown file leaves the repeater public (stock behaviour), never half private.
  if (!ok || l.num_approved > PRIVATE_MAX_APPROVED || l.num_channels > PRIVATE_MAX_CHANNELS) return false;
  _switch_on = sw ? 1 : 0;
  _auto_below_mv = mv;
  _lists = l;
  return true;
}

static const char* skipSpaces(const char* s) {
  while (*s == ' ') s++;
  return s;
}

static bool startsWord(const char* s, const char* word) {
  size_t n = strlen(word);
  return strncmp(s, word, n) == 0 && (s[n] == 0 || s[n] == ' ');
}

void PrivateRelay::list(const char* arg, char* reply) const {
  int page = atoi(arg);  // 0-based page of 16 keys
  int start = page * 16;
  int n = sprintf(reply, "approved %d:", _lists.num_approved);
  for (int i = start; i < _lists.num_approved && i < start + 16; i++) {
    n += sprintf(&reply[n], " %02X%02X%02X", _lists.approved[i][0], _lists.approved[i][1],
                 _lists.approved[i][2]);
  }
  if (_lists.num_approved > start + 16) sprintf(&reply[n], " (more: private list %d)", page + 1);
}

void PrivateRelay::handleCommand(const char* args, char* reply, FILESYSTEM* fs) {
  const char* a = skipSpaces(args);
  bool changed = false;

  if (*a == 0) {  // status
    uint32_t fwd = 0, drop = 0;
    for (int i = 0; i < mesh::PV_COUNT; i++) {
      if (mesh::privateVerdictForwards((mesh::PrivateVerdict)i)) fwd += _counts[i]; else drop += _counts[i];
    }
    char autobuf[40];
    if (_auto_below_mv) {
      sprintf(autobuf, "auto <%umV%s, batt %umV", _auto_below_mv, _auto_active ? " ACTIVE" : "", _last_batt_mv);
    } else {
      strcpy(autobuf, "auto off");
    }
    char swbuf[24];
    if (_switch_on) strcpy(swbuf, "on");
    else if (_timed_min_left) sprintf(swbuf, "timed %umin left", _timed_min_left);
    else strcpy(swbuf, "off");
    sprintf(reply, "private %s (switch %s, %s) approved %d chans %d fwd %lu drop %lu",
            isActive() ? "ON" : "OFF", swbuf, autobuf, _lists.num_approved,
            _lists.num_channels, (unsigned long)fwd, (unsigned long)drop);
    return;
  }
  if (startsWord(a, "on")) {
    if (_lists.num_approved == 0 && _lists.num_channels == 0) {
      strcpy(reply, "Err - approve radios or add a team channel first");
      return;
    }
    const char* m = skipSpaces(a + 2);
    if (*m) {
      // "private on 15": private for that many minutes, then public again by itself. Not saved:
      // a restart during the window comes back public (ChatGPT 11-09, first outdoor trial).
      int mins = atoi(m);
      if (mins < 1 || mins > 1440) {
        strcpy(reply, "Err - minutes must be 1-1440 (or plain 'private on')");
        return;
      }
      _timed_min_left = (uint16_t)mins;
      sprintf(reply, "OK - private ON for %d min (public again after, or after a restart)", mins);
      return;
    }
    _switch_on = 1; _timed_min_left = 0; changed = true;
    strcpy(reply, "OK - private ON");
  } else if (startsWord(a, "off")) {
    _switch_on = 0; _timed_min_left = 0; changed = true;
    strcpy(reply, _auto_active ? "OK - switch off (auto still ON: low battery)" : "OK - private OFF");
  } else if (startsWord(a, "auto")) {
    int mv = atoi(skipSpaces(a + 4));
    if (mv != 0 && (mv < 3000 || mv > 4200)) {
      strcpy(reply, "Err - auto mV must be 0 (off) or 3000-4200");
      return;
    }
    if (mv != 0 && _lists.num_approved == 0 && _lists.num_channels == 0) {
      strcpy(reply, "Err - approve radios or add a team channel first");
      return;
    }
    _auto_below_mv = (uint16_t)mv; changed = true;
    tick(_last_batt_mv);
    if (mv) sprintf(reply, "OK - auto private below %dmV", mv); else strcpy(reply, "OK - auto off");
  } else if (startsWord(a, "approve")) {
    const char* hex = skipSpaces(a + 7);
    uint8_t key[PUB_KEY_SIZE];
    if (strlen(hex) == PUB_KEY_SIZE * 2 && mesh::Utils::fromHex(key, PUB_KEY_SIZE, hex)) {
      // full key given
    } else {
      const Heard* h = findHeard(hex);   // a radio heard recently, by name or key prefix
      if (h == NULL) {
        strcpy(reply, "Err - not heard (see 'private heard'), ambiguous, or give the full 64-hex key");
        return;
      }
      memcpy(key, h->key, PUB_KEY_SIZE);
    }
    if (_lists.findApproved(key, PUB_KEY_SIZE) >= 0) {
      strcpy(reply, "OK - already approved");
      return;
    }
    if (_lists.num_approved >= PRIVATE_MAX_APPROVED) {
      strcpy(reply, "Err - approved list full");
      return;
    }
    memcpy(_lists.approved[_lists.num_approved++], key, PUB_KEY_SIZE); changed = true;
    sprintf(reply, "OK - approved %02X%02X%02X (%d)", key[0], key[1], key[2], _lists.num_approved);
  } else if (startsWord(a, "remove")) {
    const char* hex = skipSpaces(a + 6);
    int hl = strlen(hex);
    uint8_t pre[PUB_KEY_SIZE];
    if (hl < 6 || hl > PUB_KEY_SIZE * 2 || (hl & 1) || !mesh::Utils::fromHex(pre, hl / 2, hex)) {
      strcpy(reply, "Err - give at least 6 hex digits of the key");
      return;
    }
    int i = _lists.findApproved(pre, hl / 2);
    if (i < 0) {
      strcpy(reply, "Err - not on the list");
      return;
    }
    for (int j = i; j < _lists.num_approved - 1; j++) memcpy(_lists.approved[j], _lists.approved[j + 1], PUB_KEY_SIZE);
    _lists.num_approved--; changed = true;
    sprintf(reply, "OK - removed (%d left)", _lists.num_approved);
  } else if (startsWord(a, "heard")) {
    int n = sprintf(reply, "heard:");
    for (int i = 0; i < HEARD_MAX && n < 130; i++) {
      if (!_heard[i].seq) continue;
      bool ok = _lists.findApproved(_heard[i].key, PUB_KEY_SIZE) >= 0;
      n += snprintf(&reply[n], 150 - n, " %.12s(%02X%02X%02X)%s", _heard[i].name, _heard[i].key[0],
                    _heard[i].key[1], _heard[i].key[2], ok ? "*" : "");
    }
    return;
  } else if (startsWord(a, "list")) {
    list(skipSpaces(a + 4), reply);
    return;
  } else if (startsWord(a, "channel")) {
    const char* c = skipSpaces(a + 7);
    if (startsWord(c, "clear")) {
      _lists.num_channels = 0; changed = true;
      strcpy(reply, "OK - team channels cleared");
    } else if (startsWord(c, "add")) {
      const char* hex = skipSpaces(c + 3);
      int hl = strlen(hex);
      mesh::PrivateChannel ch;
      memset(&ch, 0, sizeof(ch));
      if ((hl != 32 && hl != 64) || !mesh::Utils::fromHex(ch.secret, hl / 2, hex)) {
        strcpy(reply, "Err - give the channel secret as 32 or 64 hex digits");
        return;
      }
      if (_lists.num_channels >= PRIVATE_MAX_CHANNELS) {
        strcpy(reply, "Err - team channel list full");
        return;
      }
      mesh::Utils::sha256(&ch.hash, 1, ch.secret, hl / 2);  // as MeshCore channels compute it
      _lists.channels[_lists.num_channels++] = ch; changed = true;
      sprintf(reply, "OK - team channel %02X added (%d)", ch.hash, _lists.num_channels);
    } else {
      sprintf(reply, "team channels %d:", _lists.num_channels);
      for (int i = 0; i < _lists.num_channels; i++) sprintf(&reply[strlen(reply)], " %02X", _lists.channels[i].hash);
    }
  } else if (startsWord(a, "stats")) {
    const char* s = skipSpaces(a + 5);
    if (startsWord(s, "reset")) {
      memset(_counts, 0, sizeof(_counts));
      strcpy(reply, "OK - counters reset");
      return;
    }
    int n = 0;
    reply[0] = 0;
    for (int i = 0; i < mesh::PV_COUNT; i++) {
      n += sprintf(&reply[n], "%s%s %lu", i ? ", " : "", mesh::privateVerdictName((mesh::PrivateVerdict)i),
                   (unsigned long)_counts[i]);
    }
    return;
  } else {
    strcpy(reply, "Err - private [on [min]|off|auto <mV>|heard|approve <name|key>|remove <hex>|list|channel add <hex>|stats]");
    return;
  }

  if (changed && !save(fs)) {
    strcat(reply, " (NOT saved!)");
  }
}
