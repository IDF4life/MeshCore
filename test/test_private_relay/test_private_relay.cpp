#include <gtest/gtest.h>
#include "helpers/PrivateRelayPolicy.h"

using namespace mesh;

static PrivateRelayLists lists() {
  PrivateRelayLists l;
  l.clear();
  l.num_approved = 2;
  memset(l.approved[0], 0x37, PUB_KEY_SIZE);  // IDF1's radio (37DE...)
  memset(l.approved[1], 0xC6, PUB_KEY_SIZE);  // IDF10R (C688...)
  l.num_channels = 1;
  l.channels[0].hash = 0x5A;
  memset(l.channels[0].secret, 0x11, 16);
  return l;
}

static bool g_mac_called;
static bool macAcceptsTeam(const uint8_t* secret, const uint8_t* data, int len) {
  g_mac_called = true;
  return secret[0] == 0x11 && data[0] == 0xAB;  // stands in for a valid MAC
}

static Packet pkt(uint8_t type, std::initializer_list<uint8_t> payload) {
  Packet p;
  p.header = ROUTE_TYPE_FLOOD | (type << PH_TYPE_SHIFT);
  p.payload_len = 0;
  for (uint8_t b : payload) p.payload[p.payload_len++] = b;
  return p;
}

TEST(PrivateRelay, TeamChannelNeedsHashAndMac) {
  auto l = lists();
  auto good = pkt(PAYLOAD_TYPE_GRP_TXT, {0x5A, 0xAB, 0xCD, 1, 2, 3});
  EXPECT_EQ(PV_TEAM_CHANNEL, privateRelayVerdict(&good, l, macAcceptsTeam));
  auto bad_mac = pkt(PAYLOAD_TYPE_GRP_DATA, {0x5A, 0x00, 0xCD, 1, 2, 3});
  EXPECT_EQ(PV_DROP_CHANNEL, privateRelayVerdict(&bad_mac, l, macAcceptsTeam));
  g_mac_called = false;
  auto other = pkt(PAYLOAD_TYPE_GRP_TXT, {0x11, 0xAB, 0xCD, 1, 2, 3});  // Public, another hash
  EXPECT_EQ(PV_DROP_CHANNEL, privateRelayVerdict(&other, l, macAcceptsTeam));
  EXPECT_FALSE(g_mac_called);  // no MAC work for other channels
  auto tiny = pkt(PAYLOAD_TYPE_GRP_TXT, {0x5A, 0xAB});
  EXPECT_EQ(PV_DROP_CHANNEL, privateRelayVerdict(&tiny, l, macAcceptsTeam));
}

TEST(PrivateRelay, AdvertNeedsFullApprovedKey) {
  auto l = lists();
  Packet a; a.header = ROUTE_TYPE_FLOOD | (PAYLOAD_TYPE_ADVERT << PH_TYPE_SHIFT);
  memset(a.payload, 0x37, PUB_KEY_SIZE); a.payload_len = PUB_KEY_SIZE + 70;
  EXPECT_EQ(PV_APPROVED_ADVERT, privateRelayVerdict(&a, l, macAcceptsTeam));
  a.payload[31] = 0x38;  // same first byte, different key: not approved
  EXPECT_EQ(PV_DROP_ADVERT, privateRelayVerdict(&a, l, macAcceptsTeam));
  a.payload_len = 10;
  EXPECT_EQ(PV_DROP_ADVERT, privateRelayVerdict(&a, l, macAcceptsTeam));
}

TEST(PrivateRelay, PeerPacketsByDestOrSrcHash) {
  auto l = lists();
  for (uint8_t t : {PAYLOAD_TYPE_TXT_MSG, PAYLOAD_TYPE_REQ, PAYLOAD_TYPE_RESPONSE, PAYLOAD_TYPE_PATH}) {
    auto to_team = pkt(t, {0x37, 0x99, 0, 0});
    auto from_team = pkt(t, {0x99, 0xC6, 0, 0});
    auto strangers = pkt(t, {0x98, 0x99, 0, 0});
    EXPECT_EQ(PV_APPROVED_HASH, privateRelayVerdict(&to_team, l, macAcceptsTeam));
    EXPECT_EQ(PV_APPROVED_HASH, privateRelayVerdict(&from_team, l, macAcceptsTeam));
    EXPECT_EQ(PV_DROP_HASH, privateRelayVerdict(&strangers, l, macAcceptsTeam));
  }
  auto login_ours = pkt(PAYLOAD_TYPE_ANON_REQ, {0xC6, 1, 2});
  auto login_other = pkt(PAYLOAD_TYPE_ANON_REQ, {0x29, 0xC6, 2});  // dest only counts
  EXPECT_EQ(PV_APPROVED_HASH, privateRelayVerdict(&login_ours, l, macAcceptsTeam));
  EXPECT_EQ(PV_DROP_HASH, privateRelayVerdict(&login_other, l, macAcceptsTeam));
}

TEST(PrivateRelay, AcksAlwaysOthersNever) {
  auto l = lists();
  auto ack = pkt(PAYLOAD_TYPE_ACK, {1, 2, 3, 4});
  auto multi = pkt(PAYLOAD_TYPE_MULTIPART, {1, 2, 3, 4, 5});
  EXPECT_EQ(PV_ALWAYS, privateRelayVerdict(&ack, l, macAcceptsTeam));
  EXPECT_EQ(PV_ALWAYS, privateRelayVerdict(&multi, l, macAcceptsTeam));
  for (uint8_t t : {PAYLOAD_TYPE_TRACE, PAYLOAD_TYPE_CONTROL, PAYLOAD_TYPE_RAW_CUSTOM, 0x0C}) {
    auto p = pkt(t, {0x37, 0xC6, 0, 0});
    EXPECT_EQ(PV_DROP_TYPE, privateRelayVerdict(&p, l, macAcceptsTeam));
  }
  EXPECT_TRUE(privateVerdictForwards(PV_ALWAYS));
  EXPECT_FALSE(privateVerdictForwards(PV_DROP_CHANNEL));
}

TEST(PrivateRelay, EmptyListsForwardOnlyAcks) {
  PrivateRelayLists l; l.clear();
  auto txt = pkt(PAYLOAD_TYPE_TXT_MSG, {0x37, 0xC6, 0, 0});
  EXPECT_EQ(PV_DROP_HASH, privateRelayVerdict(&txt, l, macAcceptsTeam));
  auto g = pkt(PAYLOAD_TYPE_GRP_TXT, {0x5A, 0xAB, 0xCD, 1});
  EXPECT_EQ(PV_DROP_CHANNEL, privateRelayVerdict(&g, l, NULL));
}

TEST(PrivateRelay, AutoOnLowBatteryWithHysteresis) {
  EXPECT_FALSE(privateAutoState(false, 3500, 0));          // off
  EXPECT_FALSE(privateAutoState(true, 3500, 0));
  EXPECT_TRUE(privateAutoState(false, 3599, 3600));        // below
  EXPECT_TRUE(privateAutoState(true, 3650, 3600));         // inside hysteresis: stays
  EXPECT_FALSE(privateAutoState(true, 3700, 3600));        // recovered
  EXPECT_TRUE(privateAutoState(true, 0, 3600));            // unknown reading: unchanged
  EXPECT_FALSE(privateAutoState(false, 0, 3600));
}
