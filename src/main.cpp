// C3 AdBlock — DNS sinkhole + web dashboard for the ESP32-C3 (no PSRAM).
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched.
// Dashboard at http://c3adblock.local : per-client stats, system info,
// ban clients, add custom block domains. All control state persisted to flash.

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>            // firmware OTA
#include <HTTPClient.h>        // remote blocklist fetch
#include <WiFiClientSecure.h>  // https fetch
#include <ArduinoOTA.h>        // network firmware flashing (pio run over wifi)
#include <DNSServer.h>         // captive-portal catch-all DNS
#include <Preferences.h>       // NVS store for provisioned WiFi creds
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/sockets.h"
#include "esp_netif.h"
#include "secrets.h"   // WIFI_SSID / WIFI_PASS — used only as a FALLBACK if no creds
                       // have been provisioned via the captive portal (copy secrets.example.h)

// ---- config ----
#ifndef UPSTREAM_IP
#define UPSTREAM_IP 9, 9, 9, 9                    // Quad9
#endif
#ifndef UPSTREAM2_IP
#define UPSTREAM2_IP 149, 112, 112, 112           // Quad9 secondary (backup)
#endif
#ifndef UPSTREAM_PORT
#define UPSTREAM_PORT 53
#endif
#ifndef FW_VERSION
#define FW_VERSION "dev"                          // set by tools/version.py from git describe
#endif
static const IPAddress UPSTREAM(UPSTREAM_IP);     // defaults; the dashboard can change both
static const IPAddress UPSTREAM2(UPSTREAM2_IP);
static const uint32_t UPSTREAM_TIMEOUT_MS = 800;  // per server; backup gets its own window
// Optional build flags (platformio.ini build_flags):
//   -DWIFI_TX_POWER=WIFI_POWER_8_5dBm  lower TX power. Many C3 SuperMini boards have a weak
//                                      antenna layout and drop WiFi (or the setup AP is not
//                                      visible) at full power. See [env:c3-supermini].
//   -DSTATIC_IP=192,168,1,250 -DSTATIC_GW=192,168,1,1 -DSTATIC_MASK=255,255,255,0
//   -DSTATIC_DNS=9,9,9,9               fixed address for routers without DHCP reservation.
//                                      Keep it outside the router's DHCP pool.
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
static const int INDEX_ENTRIES = 4096;   // 20 KB first-level flash index
static const int CACHE_SIZE = 256;       // must be power of 2
static const int MAX_RANGE = 256;        // max hashes per index bucket (fine up to ~1M hashes; flash holds far fewer)

// ---- globals ----
WiFiUDP dnsServer, upstreamCli;
WebServer web(80);
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0;
uint8_t buf[1536];   // fits any non-fragmented UDP reply (EDNS answers can exceed 512)
static uint8_t qcopy[1536];   // the client's query, kept so it can be re-sent to the backup

// upstream resolvers: [0] primary, [1] backup (0.0.0.0 = none)
IPAddress upDns[2] = { UPSTREAM, UPSTREAM2 };
uint32_t upAnswered[2] = {0, 0}, upTimeouts[2] = {0, 0};
uint32_t primaryDownUntil = 0;   // while set, try the backup first (primary just timed out)

// first-level flash index (sorted sample hashes) + small direct-mapped cache
static uint8_t blIndex[INDEX_ENTRIES][HASH_BYTES];
static uint8_t cacheKey[CACHE_SIZE][HASH_BYTES];
static uint8_t cacheRes[CACHE_SIZE];
static uint8_t cacheValid[CACHE_SIZE];
static uint8_t rangeBuf[MAX_RANGE * HASH_BYTES];

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; String label; bool v6; uint8_t ip6[16]; };
static const int MAX_CLIENTS = 96;
Dev clients[MAX_CLIENTS]; int numClients = 0;

static const int MAX_CUSTOM = 200;
String customDom[MAX_CUSTOM]; uint64_t customHash[MAX_CUSTOM]; int numCustom = 0;

static const int MAX_BAN = 32;
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;

// remote blocklist auto-update
String updateUrl = "";              // URL of a prebuilt blocklist.bin (e.g. GitHub release asset)
uint32_t updateIntervalH = 24;      // hours between auto-fetches
uint32_t lastCheckMs = 0;
String updateStatus = "never";

// WiFi provisioning (captive portal)
Preferences prefs;
DNSServer   dnsPortal;
String      portalOpts;             // <option> list of scanned networks, built once at portal start

// blocking pause (Pi-hole-style "disable for a while")
bool     blockingOn = true;
uint32_t resumeAt   = 0;            // millis() to auto-resume; 0 = paused indefinitely / not paused

// ---------- hashing / matching ----------
static uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}
static inline uint64_t unpackHash(const uint8_t* b) {
  uint64_t v = 0;
  for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
  return v;
}
static inline void packHash(uint64_t h, uint8_t* b) {
  for (int k = 0; k < HASH_BYTES; k++) { b[k] = (uint8_t)h; h >>= 8; }
}

static void buildFlashIndex() {
  if (!blocklist || numHashes == 0) return;
  for (int i = 0; i < INDEX_ENTRIES; i++) {
    uint32_t pos = (uint32_t)((uint64_t)i * (numHashes - 1) / (INDEX_ENTRIES - 1));
    blocklist.seek((uint32_t)pos * HASH_BYTES);
    blocklist.read(blIndex[i], HASH_BYTES);
  }
  for (int i = 0; i < CACHE_SIZE; i++) cacheValid[i] = 0;
}

static bool inFlash(uint64_t h) {
  if (numHashes == 0) return false;
  uint64_t first = unpackHash(blIndex[0]);
  uint64_t last  = unpackHash(blIndex[INDEX_ENTRIES - 1]);
  if (h < first || h > last) return false;

  int lo = 0, hi = INDEX_ENTRIES - 2, seg = 0;
  while (lo <= hi) {
    int mid = (lo + hi) >> 1;
    uint64_t midv = unpackHash(blIndex[mid]);
    if (midv < h) {
      seg = mid;
      lo = mid + 1;
    } else if (midv > h) {
      hi = mid - 1;
    } else {
      return true;
    }
  }

  uint32_t startPos = (uint32_t)((uint64_t)seg * (numHashes - 1) / (INDEX_ENTRIES - 1));
  uint32_t endPos   = (uint32_t)((uint64_t)(seg + 1) * (numHashes - 1) / (INDEX_ENTRIES - 1));
  if (endPos >= numHashes) endPos = numHashes - 1;
  uint32_t rangeCount = endPos - startPos + 1;
  if (rangeCount > (uint32_t)MAX_RANGE) rangeCount = MAX_RANGE;

  blocklist.seek((uint32_t)startPos * HASH_BYTES);
  blocklist.read(rangeBuf, (uint32_t)rangeCount * HASH_BYTES);

  for (uint32_t i = 0; i < rangeCount; i++) {
    uint64_t v = unpackHash(rangeBuf + i * HASH_BYTES);
    if (v == h) return true;
    if (v > h) break;
  }
  return false;
}

static bool inCustom(uint64_t h) { for (int i = 0; i < numCustom; i++) if (customHash[i] == h) return true; return false; }

// Only flash results are cached: the flash list only changes via reopenBlocklist(), which
// rebuilds the index and clears the cache. Custom domains change at runtime, so they're
// checked uncached (a short linear scan) to avoid serving stale answers.
static bool isBlockedHash(uint64_t h) {
  if (inCustom(h)) return true;
  uint32_t slot = h & (CACHE_SIZE - 1);
  if (cacheValid[slot]) {
    uint8_t want[HASH_BYTES]; packHash(h, want);
    bool same = true;
    for (int k = 0; k < HASH_BYTES; k++) if (cacheKey[slot][k] != want[k]) { same = false; break; }
    if (same) return cacheRes[slot] != 0;
  }
  bool res = inFlash(h);
  cacheValid[slot] = 1;
  cacheRes[slot] = res ? 1 : 0;
  packHash(h, cacheKey[slot]);
  return res;
}

static bool isBlocked(const char* domain) {
  const char* p = domain;
  while (p && *p) {
    uint64_t h = fnv40(p, strlen(p));
    if (isBlockedHash(h)) return true;
    const char* dot = strchr(p, '.'); if (!dot) break;
    const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
  }
  return false;
}

// ---------- persistence ----------
// Turn what people paste into a bare domain: "https://Max.AppLovin.com/p/x?id=1" ->
// "max.applovin.com", "*.applovin.com" -> "applovin.com" (a listed domain already covers its
// subdomains, and the matcher has no wildcards). Returns "" if it isn't a usable domain.
static String normDomain(String d) {
  d.trim(); d.toLowerCase();
  int sch = d.indexOf("://"); if (sch >= 0) d = d.substring(sch + 3);
  int cut = d.length();
  for (const char* sep = "/?#:"; *sep; sep++) { int k = d.indexOf(*sep); if (k >= 0 && k < cut) cut = k; }
  d = d.substring(0, cut);
  while (d.startsWith("*") || d.startsWith(".")) d = d.substring(1);
  while (d.endsWith(".")) d.remove(d.length() - 1);
  if (d.startsWith("www.")) d = d.substring(4);
  if (d.indexOf('.') <= 0 || d.length() > 253) return "";
  for (char ch : d) if (!(isalnum((unsigned char)ch) || ch == '.' || ch == '-' || ch == '_')) return "";
  return d;
}
static void saveCustom();
static void loadCustom() {
  bool changed = false;
  numCustom = 0; File f = LittleFS.open("/custom.txt", "r"); if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String raw = f.readStringUntil('\n'); raw.trim();
    String l = normDomain(raw);
    bool dup = false; for (int i = 0; i < numCustom; i++) if (customDom[i] == l) dup = true;
    if (l.length() && !dup) { customDom[numCustom] = l; customHash[numCustom] = fnv40(l.c_str(), l.length()); numCustom++; }
    if (raw.length() && (l != raw || dup)) changed = true;   // e.g. an old "*.x.com" entry
  }
  f.close();
  if (changed) saveCustom();
}
static void saveCustom() { File f = LittleFS.open("/custom.txt", "w"); if (!f) return; for (int i = 0; i < numCustom; i++) f.println(customDom[i]); f.close(); }
static bool addCustom(String d) {
  d = normDomain(d);
  if (!d.length() || numCustom >= MAX_CUSTOM) return false;
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) return false;
  customDom[numCustom] = d; customHash[numCustom] = fnv40(d.c_str(), d.length()); numCustom++; saveCustom(); return true;
}
static void removeCustom(String d) {
  d.trim(); d.toLowerCase();
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) {
    for (int j = i; j < numCustom - 1; j++) { customDom[j] = customDom[j+1]; customHash[j] = customHash[j+1]; }
    numCustom--; saveCustom(); return;
  }
}
static bool isBannedIP(uint32_t ip) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true; return false; }
static void loadBanned() {
  numBanned = 0; File f = LittleFS.open("/banned.txt", "r"); if (!f) return;
  while (f.available() && numBanned < MAX_BAN) { String l = f.readStringUntil('\n'); l.trim(); IPAddress ip; if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip; }
  f.close();
}
static void saveBanned() {
  numBanned = 0;
  for (int i = 0; i < numClients && numBanned < MAX_BAN; i++) if (clients[i].banned) bannedIP[numBanned++] = clients[i].ip;
  File f = LittleFS.open("/banned.txt", "w"); if (!f) return;
  for (int i = 0; i < numBanned; i++) { IPAddress ip(bannedIP[i]); f.println(ip.toString()); }
  f.close();
}

// ---------- client table ----------
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6); ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++) if (!clients[i].v6 && clients[i].ip == ip) { clients[i].lastSeen = millis(); return &clients[i]; }
  if (numClients < MAX_CLIENTS) {
    Dev* c = &clients[numClients++];
    c->v6 = false; c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis(); c->banned = isBannedIP(ip); c->label = "";
    getMac(ip, c->mac); return c;
  }
  return nullptr;
}
// IPv6 clients get their own rows (shown by address; ban is IPv4 only).
static Dev* getClient6(const uint8_t* a) {
  for (int i = 0; i < numClients; i++) if (clients[i].v6 && !memcmp(clients[i].ip6, a, 16)) { clients[i].lastSeen = millis(); return &clients[i]; }
  if (numClients >= MAX_CLIENTS) return nullptr;
  Dev* c = &clients[numClients++];
  c->v6 = true; memcpy(c->ip6, a, 16); c->ip = 0; c->blocked = c->allowed = 0; c->lastSeen = millis(); c->banned = false; c->label = "";
  memset(c->mac, 0, 6);
  return c;
}

// ---------- DNS ----------
static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return 0; int i = 12; size_t o = 0;
  while (i < len) { uint8_t l = pkt[i++]; if (l == 0) break; if (l & 0xC0) return 0;
    if (o + l + 1 >= 250 || i + l > len) return 0; if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]); }
  out[o] = 0; if (i + 4 > len) return 0; *qtype = (pkt[i] << 8) | pkt[i + 1]; *qend = i + 4;
  if (o > 4 && strncmp(out, "www.", 4) == 0) { memmove(out, out + 4, o - 3); o -= 4; }
  return o;
}
static int buildBlocked(int qend, uint16_t qtype) {
  buf[2] = 0x81; buf[3] = 0x80; buf[6] = 0; buf[7] = (qtype == 1) ? 1 : 0; buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  if (qtype != 1) return qend;
  const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4, 0,0,0,0};
  memcpy(buf + qend, ans, sizeof(ans)); return qend + sizeof(ans);
}
// Send the query in buf to one resolver and wait for the reply that belongs to THIS query.
// Issue #10: after one timeout the late reply used to sit in the socket and get relayed
// to the next client (every answer shifted by one). Now: drain stale datagrams first,
// send with a fresh random txid, and only accept a reply whose txid, question section,
// and source address/port match. The client's own txid is restored on the way back.
static int askUpstream(const IPAddress& up, int qlen, int qend) {
  upstreamCli.flush();                                   // release any half-read buffer
  while (upstreamCli.parsePacket() > 0) upstreamCli.flush();   // drop stale late replies
  const uint8_t cid0 = buf[0], cid1 = buf[1];
  const uint16_t wid = (uint16_t)esp_random();
  uint8_t q[260]; int ql = qend - 12;
  const bool haveQ = ql > 0 && ql <= (int)sizeof(q) && qend <= qlen;
  if (haveQ) memcpy(q, buf + 12, ql);
  buf[0] = wid >> 8; buf[1] = wid & 0xFF;
  upstreamCli.beginPacket(up, UPSTREAM_PORT); upstreamCli.write(buf, qlen); upstreamCli.endPacket();
  buf[0] = cid0; buf[1] = cid1;
  const uint32_t t0 = millis();
  while (millis() - t0 < UPSTREAM_TIMEOUT_MS) {          // deadline, not a retry count
    int sz = upstreamCli.parsePacket();
    if (sz <= 0) { delay(1); continue; }
    const bool fromUp = upstreamCli.remoteIP() == up && upstreamCli.remotePort() == UPSTREAM_PORT;
    int n = upstreamCli.read(buf, sizeof(buf));
    upstreamCli.flush();                                 // oversized datagram can't strand rx_buffer
    if (!fromUp || n < 12 || sz > (int)sizeof(buf)) continue;
    if (buf[0] != (wid >> 8) || buf[1] != (wid & 0xFF)) continue;
    if (haveQ && (n < 12 + ql || memcmp(buf + 12, q, ql) != 0)) continue;
    buf[0] = cid0; buf[1] = cid1;
    return n;
  }
  return 0;
}
// Primary first, then the backup if the primary doesn't answer in time. After a primary
// timeout the backup goes first for a minute, so one dead resolver doesn't add 800 ms to
// every lookup.
static int forwardUpstream(int qlen, int qend) {
  memcpy(qcopy, buf, qlen);
  const bool haveBackup = (uint32_t)upDns[1] != 0;
  const bool backupFirst = haveBackup && primaryDownUntil && (int32_t)(primaryDownUntil - millis()) > 0;
  if (!backupFirst) primaryDownUntil = 0;
  const int order[2] = { backupFirst ? 1 : 0, backupFirst ? 0 : 1 };
  for (int k = 0; k < 2; k++) {
    const int i = order[k];
    if ((uint32_t)upDns[i] == 0) continue;
    if (k) memcpy(buf, qcopy, qlen);                     // the failed try may have left a stray reply in buf
    int n = askUpstream(upDns[i], qlen, qend);
    if (n > 0) { upAnswered[i]++; if (i == 0) primaryDownUntil = 0; return n; }
    upTimeouts[i]++;
    if (i == 0 && haveBackup) primaryDownUntil = millis() + 60000UL;
  }
  return 0;
}
// ---------- answer cache (allowed lookups only) ----------
// Pages fire bursts of the same lookups. Answering repeats from RAM instead of waiting on
// the upstream keeps the device fast, so clients don't give up and fall back to another
// DNS server on their list (issue #40). Blocked names never get here: the block check runs
// first, so adding a custom block takes effect at once. 4-way sets, oldest entry evicted.
static const int AC_SETS = 16, AC_WAYS = 4, AC_MAX = 512;   // 64 answers, ~33 KB
static const uint32_t AC_MAX_TTL = 3600, AC_EMPTY_TTL = 60;
struct CachedAnswer { uint64_t key; uint32_t storedMs, ttl; uint16_t len, qend; bool edns; uint8_t data[AC_MAX]; };
static CachedAnswer acache[AC_SETS][AC_WAYS];
uint32_t cacheHits = 0;
static uint64_t acSeed = 0;                     // random per boot, so set placement can't be precomputed

// The key only picks the set and speeds up the compare. A hit also needs the stored
// question to match exactly (case-insensitive), so a hash collision can't serve the answer
// for a different name.
static uint64_t answerKey(int qend) {          // question bytes (case-folded) + "has EDNS"
  if (!acSeed) acSeed = ((uint64_t)esp_random() << 32) | esp_random() | 1;
  uint64_t h = 0xcbf29ce484222325ULL ^ acSeed;
  for (int i = 12; i < qend; i++) { h ^= (uint8_t)tolower(buf[i]); h *= 0x100000001b3ULL; }
  h ^= (buf[10] | buf[11]) ? 1 : 0; h *= 0x100000001b3ULL;
  return h | 1;                                 // 0 marks an empty slot
}
static int skipName(const uint8_t* m, int n, int i) {
  while (i < n) {
    uint8_t l = m[i];
    if ((l & 0xC0) == 0xC0) return i + 2 <= n ? i + 2 : -1;
    if (l & 0xC0) return -1;
    i += 1 + l; if (l == 0) return i;
  }
  return -1;
}
// Walk every resource record. Finds the smallest TTL, and if age > 0 also lowers each TTL
// by age (never below 1). The EDNS OPT record (type 41) uses the TTL field for flags: skipped.
static bool walkTtls(uint8_t* m, int n, uint32_t* minTtl, uint32_t age) {
  if (n < 12 || ((m[4] << 8) | m[5]) != 1) return false;
  int rrs = ((m[6] << 8) | m[7]) + ((m[8] << 8) | m[9]) + ((m[10] << 8) | m[11]);
  int i = skipName(m, n, 12); if (i < 0 || i + 4 > n) return false; i += 4;
  uint32_t mn = UINT32_MAX;
  for (int r = 0; r < rrs; r++) {
    i = skipName(m, n, i); if (i < 0 || i + 10 > n) return false;
    uint16_t type = (m[i] << 8) | m[i + 1];
    uint16_t rdlen = (m[i + 8] << 8) | m[i + 9];
    if (type != 41) {
      uint32_t ttl = ((uint32_t)m[i + 4] << 24) | ((uint32_t)m[i + 5] << 16) | ((uint32_t)m[i + 6] << 8) | m[i + 7];
      if (ttl < mn) mn = ttl;
      if (age) { ttl = ttl > age + 1 ? ttl - age : 1;
        m[i + 4] = ttl >> 24; m[i + 5] = ttl >> 16; m[i + 6] = ttl >> 8; m[i + 7] = ttl; }
    }
    i += 10 + rdlen; if (i > n) return false;
  }
  *minTtl = mn;
  return true;
}
// Fill buf with a cached answer for the query in buf. Returns its length, or 0 on a miss.
static int cacheGet(uint64_t key, int qend) {
  CachedAnswer* set = acache[key % AC_SETS];
  const uint32_t now = millis();
  for (int w = 0; w < AC_WAYS; w++) {
    CachedAnswer& e = set[w];
    if (e.key != key || e.qend != qend || e.edns != ((buf[10] | buf[11]) != 0)) continue;
    bool same = true;
    for (int i = 12; i < qend && same; i++) same = tolower(e.data[i]) == tolower(buf[i]);
    if (!same) continue;
    uint32_t age = (now - e.storedMs) / 1000;
    if (age >= e.ttl) { e.key = 0; return 0; }
    uint8_t id0 = buf[0], id1 = buf[1], q[260]; int ql = qend - 12;
    if (ql <= 0 || ql > (int)sizeof(q)) return 0;
    memcpy(q, buf + 12, ql);
    memcpy(buf, e.data, e.len);
    buf[0] = id0; buf[1] = id1; memcpy(buf + 12, q, ql);   // client's id + its exact question casing
    uint32_t mn;
    if (age) walkTtls(buf, e.len, &mn, age);
    cacheHits++;
    return e.len;
  }
  return 0;
}
// Store the upstream reply now in buf (only clean NOERROR / NXDOMAIN answers that fit).
static void cachePut(uint64_t key, int n, int qend, bool edns) {
  if (n < 12 || n > AC_MAX || qend > n) return;
  if (buf[2] & 0x02) return;                    // truncated -> client will retry over TCP
  uint8_t rcode = buf[3] & 0x0F; if (rcode != 0 && rcode != 3) return;
  uint32_t ttl;
  if (!walkTtls(buf, n, &ttl, 0)) return;
  if (ttl == UINT32_MAX) ttl = AC_EMPTY_TTL;    // no records at all
  if (ttl == 0) return;
  if (ttl > AC_MAX_TTL) ttl = AC_MAX_TTL;
  CachedAnswer* set = acache[key % AC_SETS];
  CachedAnswer* slot = &set[0];
  for (int w = 0; w < AC_WAYS; w++) {
    if (set[w].key == key || set[w].key == 0) { slot = &set[w]; break; }
    if ((int32_t)(set[w].storedMs - slot->storedMs) < 0) slot = &set[w];
  }
  slot->key = key; slot->storedMs = millis(); slot->ttl = ttl; slot->len = n; slot->qend = qend; slot->edns = edns;
  memcpy(slot->data, buf, n);
}

// Answer the query in buf (qlen bytes) for client c. Returns the reply length in buf (0 = none).
static int answerQuery(int qlen, Dev* c) {
  char domain[256]; uint16_t qtype = 0; int qend = qlen;
  size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);
  bool ban = c && c->banned;
  bool blocked = ban || (blockingOn && dl && numHashes && isBlocked(domain));
  int rlen;
  if (blocked) { rlen = buildBlocked(qend, qtype); totalBlocked++; if (c) c->blocked++; }
  else {
    const bool cacheable = dl && qend <= qlen && ((buf[4] << 8) | buf[5]) == 1;
    const uint64_t key = cacheable ? answerKey(qend) : 0;
    const bool edns = (buf[10] | buf[11]) != 0;
    rlen = cacheable ? cacheGet(key, qend) : 0;
    if (!rlen) { rlen = forwardUpstream(qlen, qend); if (rlen > 0 && cacheable) cachePut(key, rlen, qend, edns); }
    totalAllowed++; if (c) c->allowed++;
  }
  return rlen;
}

// IPv6 DNS: a second socket on [::]:53 (IPv6 only, the IPv4 one stays as it is). Lets the
// router hand out this device as the IPv6 DNS too, so IPv6 lookups can't skip the blocker.
// Disable with -DNO_IPV6_DNS.
static int dns6 = -1;
uint32_t queries6 = 0;
static void startDns6() {
#ifndef NO_IPV6_DNS
  dns6 = socket(AF_INET6, SOCK_DGRAM, 0);
  if (dns6 < 0) { Serial.println("[dns6] socket failed"); return; }
  int one = 1; setsockopt(dns6, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
  struct sockaddr_in6 a; memset(&a, 0, sizeof(a));
  a.sin6_family = AF_INET6; a.sin6_port = htons(DNS_PORT); a.sin6_addr = in6addr_any;
  if (bind(dns6, (struct sockaddr*)&a, sizeof(a)) < 0) { Serial.printf("[dns6] bind failed: %d\n", errno); close(dns6); dns6 = -1; return; }
  fcntl(dns6, F_SETFL, fcntl(dns6, F_GETFL, 0) | O_NONBLOCK);
  Serial.println("[dns6] listening on [::]:53");
#endif
}

// Drain a whole RX burst per call (capped, so web/OTA still get a turn) instead of
// one packet per loop iteration. Returns true if any query was handled this call.
static bool handleDns() {
  bool did = false;
  for (int budget = 0; budget < 16; budget++) {
    int sz = dnsServer.parsePacket(); if (sz <= 0) break;
    did = true;
    IPAddress cip = dnsServer.remoteIP(); uint16_t cport = dnsServer.remotePort();
    int qlen = dnsServer.read(buf, sizeof(buf)); if (qlen < 13) continue;
    int rlen = answerQuery(qlen, getClient((uint32_t)cip));
    if (rlen > 0) { dnsServer.beginPacket(cip, cport); dnsServer.write(buf, rlen); dnsServer.endPacket(); }
  }
  for (int budget = 0; dns6 >= 0 && budget < 16; budget++) {
    struct sockaddr_in6 from; socklen_t fl = sizeof(from);
    int qlen = recvfrom(dns6, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fl);
    if (qlen <= 0) break;
    did = true;
    if (qlen < 13) continue;
    queries6++;
    int rlen = answerQuery(qlen, getClient6(from.sin6_addr.s6_addr));
    if (rlen > 0) sendto(dns6, buf, rlen, 0, (struct sockaddr*)&from, fl);
  }
  return did;
}

// This device's IPv6 addresses (link-local + any SLAAC global), for the dashboard.
static String ip6List() {
  String o;
  esp_netif_t* nif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  if (!nif) return o;
  esp_ip6_addr_t addrs[LWIP_IPV6_NUM_ADDRESSES];
  int n = esp_netif_get_all_ip6(nif, addrs);
  for (int i = 0; i < n; i++) {
    char t[48]; ip6addr_ntoa_r((const ip6_addr_t*)&addrs[i], t, sizeof(t));
    o += (o.length() ? ",\"" : "\""); o += t; o += "\"";
  }
  return o;
}

// ---------- web ----------
static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
static String jesc(const String& s) { String o; for (char ch : s) { if (ch == '"' || ch == '\\') o += '\\'; o += ch; } return o; }
// HTML text/attribute escaping for the setup portal. jesc() covers JSON (stats
// endpoint); the portal builds HTML, and its inputs — a scanned SSID, the
// submitted WiFi name — are attacker-controllable during provisioning (the
// portal AP is open, and a nearby attacker can also broadcast an SSID of their
// choosing). Without escaping both, a crafted SSID/name is reflected script
// into the setup page, the same class as the dashboard XSS fixed earlier.
static String htmlEscape(const String& s) {
  String o; o.reserve(s.length());
  for (char ch : s) {
    switch (ch) {
      case '&':  o += "&amp;";  break;
      case '<':  o += "&lt;";   break;
      case '>':  o += "&gt;";   break;
      case '"':  o += "&quot;"; break;
      case '\'': o += "&#39;";  break;
      default:   o += ch;
    }
  }
  return o;
}

#include "page.h"   // dashboard HTML (PROGMEM) — see issue #6

static void handleStats() {
  uint32_t up = millis() / 1000;
  char ut[24]; snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  String j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"uptime\":\"" + ut + "\"" +
             ",\"ip6\":[" + ip6List() + "],\"q6\":" + String(queries6) + ",\"cachehits\":" + String(cacheHits) + ",\"ver\":\"" FW_VERSION "\",\"chip\":\"" + String(ESP.getChipModel()) + "\"" +
             ",\"dns1\":\"" + upDns[0].toString() + "\",\"dns2\":\"" + ((uint32_t)upDns[1] ? upDns[1].toString() : String("")) + "\"" +
             ",\"dnsok\":[" + upAnswered[0] + "," + upAnswered[1] + "],\"dnsto\":[" + upTimeouts[0] + "," + upTimeouts[1] + "]" +
             ",\"dnsbackup\":" + (primaryDownUntil && (int32_t)(primaryDownUntil - millis()) > 0 ? "true" : "false") +
             ",\"upurl\":\"" + jesc(updateUrl) + "\",\"upiv\":" + updateIntervalH + ",\"upstat\":\"" + jesc(updateStatus) + "\"" +
             ",\"blocking\":" + (blockingOn ? "true" : "false") +
             ",\"resumeIn\":" + (uint32_t)(!blockingOn && resumeAt ? (resumeAt - millis()) / 1000 : 0) +
             ",\"defcreds\":" + ((strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0) ? "true" : "false") +
             ",\"clients\":[";
  for (int i = 0; i < numClients; i++) { Dev& c = clients[i]; IPAddress ip(c.ip);
    char t6[48] = ""; if (c.v6) ip6addr_ntoa_r((const ip6_addr_t*)c.ip6, t6, sizeof(t6));
    j += (i ? "," : ""); j += "{\"ip\":\"" + (c.v6 ? String(t6) : ip.toString()) + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (c.banned?"true":"false") + "}"; }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
  j += "]}";
  web.send(200, "application/json", j);
}
// Upstream shipped every state-changing/OTA endpoint with zero authentication —
// anyone on the LAN could reflash firmware or rewrite the blocklist. Gate them.
//
// Basic Auth alone isn't enough here: these are GET endpoints with side effects,
// and browsers auto-attach cached Basic Auth credentials to *any* request to an
// already-authenticated origin — including one triggered by a completely
// unrelated page the victim's browser visits later (e.g. <img src="http://
// c3adblock.local/forgetwifi">). That's CSRF, and it defeats the LAN-attacker
// threat model entirely: the attacker doesn't need network access, just to get
// the victim's browser to fire one request. A custom header can't be attached
// by a plain <img>/<form> CSRF vector (only same-origin fetch() can set it, and
// that's exactly what the dashboard's own JS does), so requiring one blocks the
// drive-by case without needing TLS, cookies, or a token endpoint.
static const char* CSRF_HEADER = "X-Requested-With";
static const char* CSRF_VALUE  = "c3-adblock";
static bool requireAuth() {
  if (web.header(CSRF_HEADER) != CSRF_VALUE) { web.send(403, "text/plain", "missing CSRF header"); return false; }
  if (web.authenticate(WEB_USER, WEB_PASS)) return true;
  web.requestAuthentication();
  return false;
}
static void handleBan() {
  if (!requireAuth()) return;
  IPAddress ip; if (ip.fromString(web.arg("ip"))) { Dev* c = getClient((uint32_t)ip); if (c) { c->banned = !c->banned; saveBanned(); } }
  web.send(200, "text/plain", "ok");
}

// ---------- blocklist swap (shared by upload + remote fetch) ----------
// The partition holds one list, so we free the old one before writing the new.
// While swapping, numHashes=0 -> device fail-opens (forwards, no blocking).
static void reopenBlocklist() {
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0;
  buildFlashIndex();
}
static void beginBlocklistSwap() {
  if (blocklist) blocklist.close();
  numHashes = 0;
  LittleFS.remove(BLOCKLIST_PATH);
  LittleFS.remove("/blocklist.new");
}
static bool commitNewBlocklist() {                  // /blocklist.new -> live (validated)
  File f = LittleFS.open("/blocklist.new", "r");
  size_t sz = f ? f.size() : 0; if (f) f.close();
  bool ok = sz > 0 && (sz % HASH_BYTES) == 0;       // sorted hash blob -> 5-byte multiple
  if (ok) LittleFS.rename("/blocklist.new", BLOCKLIST_PATH);
  else    LittleFS.remove("/blocklist.new");
  reopenBlocklist();
  return ok;
}

// ---------- OTA blocklist update (browser upload) ----------
static bool upOk = false;
static bool upAuthOk = false;
static File upFile;
static void handleUploadDone() {
  if (!upAuthOk) { web.requestAuthentication(); return; }
  web.send(upOk ? 200 : 500, "text/plain",
           upOk ? "ok" : "rejected: empty or size not a multiple of 5 (not a blocklist.bin?)");
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      upAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
      if (!upAuthOk) { Serial.println("[ota] blocklist upload: auth/CSRF check failed"); break; }
      upOk = false; beginBlocklistSwap();
      upFile = LittleFS.open("/blocklist.new", "w");
      Serial.printf("[ota] receiving %s\n", u.filename.c_str());
      break;
    case UPLOAD_FILE_WRITE:
      if (upAuthOk && upFile) upFile.write(u.buf, u.currentSize);
      break;
    case UPLOAD_FILE_END:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      upOk = commitNewBlocklist();
      Serial.printf("[ota] %s -> %u domains\n", upOk ? "OK" : "REJECTED", numHashes);
      break;
    case UPLOAD_FILE_ABORTED:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      LittleFS.remove("/blocklist.new"); reopenBlocklist();
      Serial.println("[ota] aborted");
      break;
  }
}

// ---------- remote blocklist auto-update ----------
static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r"); if (!f) return;
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim(); if (iv.length()) updateIntervalH = iv.toInt();
  f.close(); if (updateIntervalH < 1) updateIntervalH = 1;
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w"); if (!f) return;
  f.println(updateUrl); f.println(updateIntervalH); f.close();
}
// ---------- upstream resolver config (/dns.cfg: primary, backup) ----------
static void loadDnsCfg() {
  File f = LittleFS.open("/dns.cfg", "r"); if (!f) return;
  for (int i = 0; i < 2; i++) {
    String l = f.readStringUntil('\n'); l.trim(); IPAddress ip;
    if (l.length() && ip.fromString(l)) upDns[i] = ip;
  }
  f.close();
  if ((uint32_t)upDns[0] == 0) upDns[0] = UPSTREAM;
}
static void saveDnsCfg() {
  File f = LittleFS.open("/dns.cfg", "w"); if (!f) return;
  f.println(upDns[0].toString()); f.println(upDns[1].toString()); f.close();
}
static bool fetchBlocklist(String url) {
  url.trim(); if (!url.length()) { updateStatus = "no url set"; return false; }
  Serial.printf("[remote] GET %s\n", url.c_str());
  WiFiClientSecure cs; cs.setInsecure();            // blocklist isn't secret -> skip cert pinning
  WiFiClient cl;
  HTTPClient http; http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);  // GitHub release -> CDN redirect
  bool https = url.startsWith("https");
  if (!(https ? http.begin(cs, url) : http.begin(cl, url))) { updateStatus = "begin failed"; return false; }
  int code = http.GET();
  if (code != HTTP_CODE_OK) { http.end(); updateStatus = "HTTP " + String(code); Serial.printf("[remote] %s\n", updateStatus.c_str()); return false; }
  beginBlocklistSwap();
  File f = LittleFS.open("/blocklist.new", "w");
  if (!f) { http.end(); updateStatus = "fs open failed"; reopenBlocklist(); return false; }
  WiFiClient* stream = http.getStreamPtr();
  int len = http.getSize(); uint8_t b[1024]; size_t total = 0; uint32_t idle = millis();
  while (http.connected() && (len < 0 || (int)total < len)) {
    size_t avail = stream->available();
    if (avail) { int n = stream->readBytes(b, avail > sizeof(b) ? sizeof(b) : avail); if (n > 0) { f.write(b, n); total += n; idle = millis(); } }
    else { if (millis() - idle > 15000) break; delay(2); }
  }
  f.close(); http.end();
  bool ok = commitNewBlocklist();
  updateStatus = ok ? ("ok: " + String(numHashes) + " domains") : ("bad data (" + String(total) + "B)");
  Serial.printf("[remote] %s\n", updateStatus.c_str());
  return ok;
}

// ---------- firmware OTA (browser upload of firmware.bin -> reboot) ----------
static bool fwAuthOk = false;
static void handleFwUpdateDone() {
  if (!fwAuthOk) { web.requestAuthentication(); return; }
  bool ok = !Update.hasError();
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    fwAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
    if (!fwAuthOk) { Serial.println("[fw-ota] auth/CSRF check failed, rejecting flash"); return; }
    Serial.printf("[fw-ota] %s\n", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (!fwAuthOk) return;
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (!fwAuthOk) return;
    if (Update.end(true)) Serial.printf("[fw-ota] %u bytes OK\n", u.totalSize);
    else Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    if (!fwAuthOk) return;
    Update.abort(); Serial.println("[fw-ota] aborted");
  }
}

// ---------- WiFi provisioning (captive portal) ----------
// Try provisioned NVS creds first, then the compile-time secrets.h creds as a
// fallback (so the maintainer's own device + source builders keep working). If
// neither connects, fall through to the config portal.
static bool hasCreds() {
  prefs.begin("wifi", true); bool nvs = prefs.getString("ssid", "").length() > 0; prefs.end();
  return nvs || (WIFI_SSID && *WIFI_SSID && strcmp(WIFI_SSID, "YOUR_WIFI_SSID") != 0);
}
static bool connectWiFi() {
  prefs.begin("wifi", true);
  String ss = prefs.getString("ssid", "");
  String pw = prefs.getString("pass", "");
  prefs.end();
  const char* ssid = ss.length() ? ss.c_str() : WIFI_SSID;
  const char* pass = ss.length() ? pw.c_str() : WIFI_PASS;
  if (!ssid || !*ssid || strcmp(ssid, "YOUR_WIFI_SSID") == 0) return false;  // unconfigured
  Serial.printf("WiFi: connecting to \"%s\"%s\n", ssid, ss.length() ? " (provisioned)" : " (secrets.h)");
  WiFi.mode(WIFI_STA); WiFi.setSleep(false);
#ifdef STATIC_IP
#ifndef STATIC_MASK
#define STATIC_MASK 255, 255, 255, 0
#endif
#ifndef STATIC_DNS
#define STATIC_DNS UPSTREAM_IP
#endif
  if (WiFi.config(IPAddress(STATIC_IP), IPAddress(STATIC_GW), IPAddress(STATIC_MASK), IPAddress(STATIC_DNS)))
    Serial.printf("WiFi: static IP %s\n", IPAddress(STATIC_IP).toString().c_str());
  else
    Serial.println("WiFi: static IP config failed, using DHCP");
#endif
  WiFi.begin(ssid, pass);
#ifdef WIFI_TX_POWER
  WiFi.setTxPower(WIFI_TX_POWER);
#endif
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 30000) { delay(250); Serial.print("."); }
  Serial.println();
  return WiFi.status() == WL_CONNECTED;
}

static void handlePortalRoot() {
  String html =
    "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>C3 AdBlock setup</title>"
    "<body style='font:16px system-ui,sans-serif;max-width:420px;margin:36px auto;padding:0 16px;background:#0d1117;color:#c9d1d9'>"
    "<h2>&#128737; C3 AdBlock &mdash; WiFi setup</h2>"
    "<p style='color:#8b949e'>Pick your network and enter its password. The device restarts and joins it.</p>"
    "<form method=POST action=/wifisave>"
    // A real <select> is usable on every phone; the datalist this used to be
    // renders an affordance in several in-app browsers but no list, so picking
    // a network looked impossible. Typing the name still covers hidden APs.
    "<select name=s style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>" + portalOpts + "</select>"
    "<input name=s2 placeholder='or type the WiFi name' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<input name=p type=password placeholder='Password' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<button style='width:100%;padding:12px;margin-top:8px;border-radius:6px;border:0;background:#3fb950;color:#000;font-weight:600;cursor:pointer'>Connect</button>"
    "</form></body>";
  web.send(200, "text/html", html);
}
static void handleWifiSave() {
  String ss = web.arg("s2"); ss.trim();          // typed name wins
  if (!ss.length()) ss = web.arg("s");           // ...otherwise the picked one
  String pw = web.arg("p");
  if (!ss.length()) { web.send(400, "text/plain", "missing WiFi name"); return; }
  prefs.begin("wifi", false); prefs.putString("ssid", ss); prefs.putString("pass", pw); prefs.end();
  web.send(200, "text/html", "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                             "&#9989; Saved. Restarting and joining <b>" + htmlEscape(ss) + "</b>&hellip;<br><br>"
                             "Reconnect your phone to your normal WiFi, then find the box at <b>c3adblock.local</b>.</body>");
  delay(900); ESP.restart();
}
// Never returns — blocks in the portal loop until creds are saved (then reboots).
static void startConfigPortal() {
  // Bring the radio up before the first scan. An unconfigured device gets here
  // straight from connectWiFi() without any WiFi call, and the first scan right
  // after boot can come back empty - which left the network list with no
  // entries at all. Start the station, then retry a few times.
  WiFi.mode(WIFI_STA);
  delay(200);
  int n = 0;
  for (int attempt = 1; attempt <= 3 && n <= 0; attempt++) {
    if (attempt > 1) delay(700);
    n = WiFi.scanNetworks();
    Serial.printf("[setup] scan %d/3: %d networks\n", attempt, n);
  }
  portalOpts = "<option value=''>-- pick your network --</option>";
  for (int i = 0; i < n && i < 15; i++) {
    const String s = WiFi.SSID(i);
    portalOpts += "<option value='" + htmlEscape(s) + "'>" + htmlEscape(s) + "</option>";
  }
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[24]; snprintf(ap, sizeof(ap), "C3-AdBlock-%02X%02X", mac[4], mac[5]);
  WiFi.mode(WIFI_AP); WiFi.softAP(ap);
#ifdef WIFI_TX_POWER
  WiFi.setTxPower(WIFI_TX_POWER);
#endif
  IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);              // catch-all -> phones pop the captive portal
  web.on("/", handlePortalRoot);
  web.on("/wifisave", HTTP_POST, handleWifiSave);
  web.onNotFound(handlePortalRoot);            // any captive-portal probe -> the form
  web.begin();
  Serial.printf("\n[setup] No WiFi. Join open network \"%s\" and a setup page pops up (or http://%s)\n",
                ap, apIP.toString().c_str());
  // A configured device that merely failed to join (router rebooting, weak signal) must not
  // get stuck here: if nobody is using the portal, reboot and retry WiFi every 3 minutes.
  const bool configured = hasCreds();
  uint32_t t0 = millis();
  while (true) {
    dnsPortal.processNextRequest(); web.handleClient(); delay(2);
    if (WiFi.softAPgetStationNum() > 0) t0 = millis();          // someone is setting it up
    if (configured && millis() - t0 > 180000UL) { Serial.println("[setup] retrying WiFi"); ESP.restart(); }
  }
}

void setup() {
  Serial.begin(115200); delay(300);
  Serial.println("\n[c3-adblock] booting, firmware " FW_VERSION);
  if (!LittleFS.begin(true)) Serial.println("LittleFS FAILED");
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  if (blocklist) {
    numHashes = blocklist.size() / HASH_BYTES;
    Serial.printf("blocklist: %u domains\n", numHashes);
    buildFlashIndex();
  }
  loadCustom(); loadBanned(); loadUpdateCfg(); loadDnsCfg();
  Serial.printf("custom: %d, banned: %d\n", numCustom, numBanned);

  // Hold BOOT at power-on to wipe saved WiFi and force the setup portal.
#if CONFIG_IDF_TARGET_ESP32C3
  const int BOOT_PIN = 9;     // C3 BOOT button
#else
  const int BOOT_PIN = 0;     // classic ESP32 BOOT button (GPIO9 is a flash pin there)
#endif
  pinMode(BOOT_PIN, INPUT_PULLUP);
  if (digitalRead(BOOT_PIN) == LOW) { delay(60);
    if (digitalRead(BOOT_PIN) == LOW) { prefs.begin("wifi", false); prefs.clear(); prefs.end();
      Serial.println("[setup] BOOT held -> cleared saved WiFi"); } }

  if (!connectWiFi()) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());
  if (MDNS.begin("c3adblock")) { MDNS.addService("http", "tcp", 80); Serial.println("dashboard: http://c3adblock.local"); }

  if (strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0)
    Serial.println("[WARN] secrets.h still has placeholder WEB_PASS/OTA_PASS — those are public "
                    "(they're in the repo's example file). Set real values before trusting this "
                    "device on a network you don't fully control.");

  dnsServer.begin(DNS_PORT); upstreamCli.begin(0);
#ifndef NO_IPV6_DNS
  WiFi.enableIpV6();                                      // link-local now; SLAAC global from router RAs
  WiFi.onEvent([](arduino_event_id_t, arduino_event_info_t) { WiFi.enableIpV6(); }, ARDUINO_EVENT_WIFI_STA_CONNECTED);
  startDns6();
#endif
  { const char* hdrs[] = { CSRF_HEADER }; web.collectHeaders(hdrs, 1); }  // needed for requireAuth()'s CSRF check
  web.on("/", []() { web.send_P(200, "text/html", PAGE); });
  web.on("/stats.json", handleStats);
  web.on("/ban", handleBan);
  web.on("/addblock", []() {
    if (!requireAuth()) return;
    String d = normDomain(web.arg("d"));
    if (!d.length()) { web.send(400, "text/plain", "not a domain"); return; }
    addCustom(d); web.send(200, "text/plain", d);
  });
  web.on("/unblock", []() { if (!requireAuth()) return; removeCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/pause", []() {                    // /pause?s=300  (0 or absent = indefinite)
    if (!requireAuth()) return;
    long s = web.hasArg("s") ? web.arg("s").toInt() : 0;
    blockingOn = false; resumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
    web.send(200, "text/plain", "paused");
  });
  web.on("/resume", []() { if (!requireAuth()) return; blockingOn = true; resumeAt = 0; web.send(200, "text/plain", "resumed"); });
  web.on("/forgetwifi", []() { if (!requireAuth()) return; web.send(200, "text/plain", "cleared — rebooting into setup portal");
    prefs.begin("wifi", false); prefs.clear(); prefs.end(); delay(500); ESP.restart(); });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);      // blocklist OTA (auth inside handleUpload)
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);  // firmware OTA (auth inside handleFwUpload)
  web.on("/fetchnow", []() { if (!requireAuth()) return; fetchBlocklist(updateUrl); web.send(200, "text/plain", updateStatus); });
  web.on("/setupdate", []() {
    if (!requireAuth()) return;
    if (web.hasArg("u")) updateUrl = web.arg("u");
    if (web.hasArg("h")) { updateIntervalH = web.arg("h").toInt(); if (updateIntervalH < 1) updateIntervalH = 1; }
    saveUpdateCfg(); web.send(200, "text/plain", "ok");
  });
  web.on("/setdns", []() {               // /setdns?p=9.9.9.9&b=1.1.1.1  (b empty = no backup, def=1 = defaults)
    if (!requireAuth()) return;
    IPAddress p, b;
    if (web.hasArg("def")) { upDns[0] = UPSTREAM; upDns[1] = UPSTREAM2; }
    else {
      String bs = web.arg("b"); bs.trim();
      if (!p.fromString(web.arg("p")) || (uint32_t)p == 0) { web.send(400, "text/plain", "primary is not an IPv4 address"); return; }
      if (bs.length() && !b.fromString(bs)) { web.send(400, "text/plain", "backup is not an IPv4 address"); return; }
      if (p == WiFi.localIP() || (bs.length() && b == WiFi.localIP())) { web.send(400, "text/plain", "that is this device (would loop)"); return; }
      upDns[0] = p; upDns[1] = bs.length() ? b : IPAddress(0, 0, 0, 0);
    }
    primaryDownUntil = 0; upAnswered[0] = upAnswered[1] = upTimeouts[0] = upTimeouts[1] = 0;
    saveDnsCfg();
    Serial.printf("[dns] upstream %s, backup %s\n", upDns[0].toString().c_str(), upDns[1].toString().c_str());
    web.send(200, "text/plain", "ok");
  });
  web.begin();
  ArduinoOTA.setHostname("c3adblock");   // pio run -t upload --upload-port c3adblock.local
  ArduinoOTA.setPassword(OTA_PASS);      // network OTA was unauthenticated upstream
  ArduinoOTA.begin();
  Serial.println("DNS :53 + dashboard :80 + OTA up");
}

void loop() {
  ArduinoOTA.handle();
  web.handleClient();
  bool busy = handleDns();
  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) { blockingOn = true; resumeAt = 0; }
  if (updateUrl.length()) {               // periodic remote blocklist auto-update
    uint32_t now = millis();
    if (lastCheckMs == 0) lastCheckMs = now;   // skip an immediate fetch on boot
    else if (now - lastCheckMs >= updateIntervalH * 3600000UL) { lastCheckMs = now; fetchBlocklist(updateUrl); }
  }
  if (!busy) delay(1);   // sleep only when idle: full speed under load, cool when quiet
}
