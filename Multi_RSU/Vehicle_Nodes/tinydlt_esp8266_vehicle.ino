/*
 TinyDLT ESP8266 Vehicle Node - multi-RSU
 Port of tinydlt_esp32_vehicle_3rsu.ino. Protocol and canonical bytes are
 identical; only the platform-specific parts differ.

 Libraries: PubSubClient, ArduinoJson, Crypto (Rhys Weatherley)
 Board    : any ESP8266 (NodeMCU, Wemos D1 mini, ESP-12)

 IMPORTANT - set Tools > CPU Frequency to 160 MHz. PoW and Ed25519 are
 software here (no hardware SHA), so 80 MHz roughly doubles the time per
 transaction. The sketch prints its own PoW and signing times; use those
 numbers for the paper rather than any estimate.

 Differences from the ESP32 version, and why:
   1. SHA-256 comes from BearSSL (bundled with the ESP8266 core) instead
      of mbedtls.
   2. The key is stored in EEPROM instead of NVS/Preferences.
   3. The sequence number is NOT written to flash. It is derived from
      epoch milliseconds, so it already increases across reboots, and
      EEPROM.commit() on every transaction would wear the flash out.
   4. Ed25519::sign() is a single blocking call that can exceed the 3.2 s
      software watchdog on this chip, so the software WDT is suspended
      around it (the 8 s hardware WDT still protects the board).
   5. Randomness comes from RANDOM_REG32, ESP8266's hardware RNG.
   6. JSON documents are allocated on the heap: the ESP8266 stack is only
      about 4 kB and a 1 kB StaticJsonDocument on it is asking for
      trouble.
   7. Chip ID replaces the ESP32 efuse MAC in the MQTT client id.

 First boot prints the public key. Add it to vehicle_keys.json on ONE
 RSU; the others learn it through the RSU handshake.
*/

#include <ESP8266WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <EEPROM.h>
#include <bearssl/bearssl_hash.h>
#include <Crypto.h>
#include <Ed25519.h>
#include <time.h>
#include <sys/time.h>

/* ============================== CONFIG =============================== */
const char* VEHICLE_ID    = "vehicle_01";     // must differ from the ESP32's
const char* WIFI_SSID     = "iotoi";
const char* WIFI_PASSWORD = "12345678";

// List ONLY the RSUs that are actually running. An entry whose broker is
// down costs a connection timeout on every failover sweep.
struct Rsu { const char* id; const char* host; uint16_t port; };
Rsu RSUS[] = {
  {"RSU1", "10.53.35.118", 1883},
  {"RSU2", "10.53.35.168", 1883},
  {"RSU3", "10.53.35.128", 1883},
};

// Declared HERE, above the first function definition in the sketch.
// The Arduino IDE inserts its auto-generated prototypes immediately
// before the first function, so any type used in a signature (sense(),
// dataCanonical(), bodyHead()) must be declared before that point.
struct SensorData {
  String event;
  int    speed_kmh;          // integer, never a float
  String latitude;           // fixed-decimal string
  String longitude;
};


/* ============================ ATTACK MODES ===========================
 * For the attack experiments (F6, F9). Run ONE attacker board alongside
 * an honest one (ATTACK_NONE), one attack type per run.
 *   ATTACK_INVALID_POW   nonce not solved       -> invalid_pow
 *   ATTACK_BAD_SIGNATURE signature corrupted    -> bad_vehicle_signature
 *   ATTACK_REPLAY        sequence number reused -> replay_sequence
 *   ATTACK_SPAM          one tx every 300 ms    -> rate_limit
 *   ATTACK_FAKE_DATA     speed_kmh = 999        -> speed_out_of_range
 * ==================================================================== */
#define ATTACK_NONE          0
#define ATTACK_INVALID_POW   1
#define ATTACK_BAD_SIGNATURE 2
#define ATTACK_REPLAY        3
#define ATTACK_SPAM          4
#define ATTACK_FAKE_DATA     5

const int ATTACK_MODE = ATTACK_NONE;

const char* attackName() {
  switch (ATTACK_MODE) {
    case ATTACK_INVALID_POW:   return "invalid_pow";
    case ATTACK_BAD_SIGNATURE: return "bad_signature";
    case ATTACK_REPLAY:        return "replay_sequence";
    case ATTACK_SPAM:          return "spam";
    case ATTACK_FAKE_DATA:     return "fake_data";
    default:                   return "none";
  }
}

const int NUM_RSUS = sizeof(RSUS) / sizeof(RSUS[0]);
int preferredRSU = 0;

const uint8_t  VERSION          = 1;
const uint8_t  POW_BITS         = 12;     // must equal POW_DIFFICULTY on the RSU
const uint32_t MIN_INTERVAL_MS  = 5000;   // 5000
const uint32_t MAX_INTERVAL_MS  = 10000;  // 10000
const uint32_t TIPS_TIMEOUT_MS  = 5000;  
const int      MAX_TIP_TIMEOUTS = 2;      // then hand over to the next RSU

const bool  SEND_GPS = true;
const char* FIXED_LAT = "12.971600";      // fixed-decimal strings
const char* FIXED_LON = "77.594600";

const int EEPROM_SIZE  = 64;
const int EEPROM_MAGIC = 0xA5;            // byte 0, then 32 key bytes
/* ===================================================================== */

WiFiClient   net;
PubSubClient mqtt(net);

uint8_t  privateKey[32], publicKey[32];
uint64_t sequenceNo = 0;
int      rsuIndex = 0;
int      tipTimeouts = 0;
String   rsuId;

String   tipA = "GENESIS";
String   tipB = "";
bool     tipsReady = false;
bool     waitingTips = false;
unsigned long tipRequestAt = 0;
unsigned long lastTipWaitMs = 0;
unsigned long lastTxAt = 0;
unsigned long nextTxInterval = 7000;


/* ============================== HELPERS ============================== */

String hexOf(const uint8_t* p, size_t n) {
  const char* h = "0123456789abcdef";
  String s; s.reserve(n * 2);
  for (size_t i = 0; i < n; i++) { s += h[p[i] >> 4]; s += h[p[i] & 15]; }
  return s;
}

// Portable 64-bit to decimal: String(uint64_t) truncates on this core and
// epoch milliseconds do not fit in 32 bits.
String u64str(uint64_t v) {
  char buf[21];
  int i = 20;
  buf[i] = '\0';
  if (v == 0) buf[--i] = '0';
  while (v > 0) { buf[--i] = '0' + (char)(v % 10); v /= 10; }
  return String(&buf[i]);
}

// DIFFERENCE 1: BearSSL instead of mbedtls. Same SHA-256, same bytes.
String sha256Hex(const String& s) {
  uint8_t d[32];
  br_sha256_context c;
  br_sha256_init(&c);
  br_sha256_update(&c, s.c_str(), s.length());
  br_sha256_out(&c, d);
  return hexOf(d, 32);
}

// Leading-zero test on the raw digest (no hex conversion in the hot loop).
bool leadingZeroBitsRaw(const uint8_t* d, uint8_t bits) {
  uint8_t full = bits / 8, rem = bits % 8;
  for (uint8_t i = 0; i < full; i++) if (d[i] != 0) return false;
  if (!rem) return true;
  return (d[full] >> (8 - rem)) == 0;
}

bool leadingZeroBits(const String& h, uint8_t bits) {
  uint8_t n = bits / 4, r = bits % 4;
  for (uint8_t i = 0; i < n; i++) if (h[i] != '0') return false;
  if (!r) return true;
  char c = h[n];
  int v = (c <= '9') ? c - '0' : c - 'a' + 10;
  return v < (1 << (4 - r));
}

uint64_t epochMs() {
  struct timeval tv; gettimeofday(&tv, nullptr);
  return (uint64_t)tv.tv_sec * 1000ULL + tv.tv_usec / 1000ULL;
}

bool clockReady() { return time(nullptr) > 1700000000; }

/* ============================ VEHICLE KEY ============================ */

void setupKey() {
  // DIFFERENCE 2: EEPROM, not Preferences. Byte 0 is a magic marker,
  // bytes 1..32 hold the private key.
  EEPROM.begin(EEPROM_SIZE);

  if (EEPROM.read(0) == EEPROM_MAGIC) {
    for (int i = 0; i < 32; i++) privateKey[i] = EEPROM.read(1 + i);
    Ed25519::derivePublicKey(publicKey, privateKey);
  } else {
    // DIFFERENCE 5: ESP8266 hardware RNG.
    for (int i = 0; i < 32; i++)
      privateKey[i] = (uint8_t)(RANDOM_REG32 & 0xFF);

    Ed25519::derivePublicKey(publicKey, privateKey);

    EEPROM.write(0, EEPROM_MAGIC);
    for (int i = 0; i < 32; i++) EEPROM.write(1 + i, privateKey[i]);
    EEPROM.commit();
    Serial.println("Generated a new vehicle key (stored in EEPROM).");
  }

  Serial.println("=====================================================");
  Serial.print("VEHICLE_ID: ");  Serial.println(VEHICLE_ID);
  Serial.print("ATTACK_MODE: "); Serial.println(attackName());
  Serial.print("PUBLIC_KEY: ");  Serial.println(hexOf(publicKey, 32));
  Serial.println("Add to vehicle_keys.json on ONE RSU:");
  Serial.print("  \""); Serial.print(VEHICLE_ID); Serial.print("\": \"");
  Serial.print(hexOf(publicKey, 32)); Serial.println("\"");
  Serial.println("=====================================================");
}

/* ============================== NETWORK ============================== */

void connectWiFi() {
  if (WiFi.status() == WL_CONNECTED) return;
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  // Lower radio power reduces the current spike that browns out boards on
  // thin USB cables. Raise it back to 20.5 if range suffers.
  WiFi.setOutputPower(14.0);

  Serial.print("WiFi");
  unsigned long t = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t < 20000) {
    delay(300); Serial.print(".");
  }
  Serial.println();
  if (WiFi.status() == WL_CONNECTED) {
    Serial.print("IP: "); Serial.println(WiFi.localIP());
  }
}

void syncClock() {
  // UTC. gettimeofday() must return real epoch time; the RSU rejects
  // anything more than 30 s away from its own clock.
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  for (int i = 0; i < 40 && !clockReady(); i++) delay(500);
  Serial.println(clockReady() ? "NTP synchronized." : "WARNING: no NTP.");
}

String topicSubmit()   { return "tangle/" + rsuId + "/submit_tx"; }
String topicTips()     { return "tangle/" + rsuId + "/request_tips"; }
String topicTipReply() { return "tangle/tips/" + String(VEHICLE_ID); }

void mqttCallback(char* topic, byte* payload, unsigned int len) {
  String msg; msg.reserve(len);
  for (unsigned int i = 0; i < len; i++) msg += (char)payload[i];
  String t = String(topic);

  if (t == topicTipReply()) {
    // DIFFERENCE 6: heap, not stack - the ESP8266 stack is ~4 kB.
    DynamicJsonDocument d(1024);
    if (deserializeJson(d, msg)) return;
    JsonArray a = d["tips"].as<JsonArray>();
    tipA = "GENESIS"; tipB = "";
    int n = 0;
    for (JsonVariant x : a) {
      String v = x.as<String>();
      if (!v.length()) continue;
      if (n == 0) tipA = v; else if (n == 1) tipB = v;
      if (++n == 2) break;
    }
    lastTipWaitMs = millis() - tipRequestAt;   // energy model input
    tipsReady = true; waitingTips = false; tipTimeouts = 0;
    Serial.print("Tips: "); Serial.print(tipA);
    if (tipB.length()) { Serial.print(" , "); Serial.print(tipB); }
    Serial.println();
    return;
  }

  if (t == "tangle/confirmed" || t == "tangle/" + rsuId + "/confirmed") {
    DynamicJsonDocument d(1024);
    if (deserializeJson(d, msg)) return;
    Serial.print("CONFIRMED: ");
    Serial.print(d["txid"].as<String>().substring(0, 12));
    Serial.print("  CW="); Serial.print(d["cumulative_weight"].as<int>());
    Serial.print("  quorum=");
    for (JsonVariant x : d["quorum_votes"].as<JsonArray>()) {
      Serial.print(x.as<String>()); Serial.print(" ");
    }
    Serial.println();
  }
}

bool connectRSU(int idx) {
  rsuIndex = idx;
  rsuId = RSUS[idx].id;
  mqtt.setServer(RSUS[idx].host, RSUS[idx].port);
  mqtt.setCallback(mqttCallback);
  mqtt.setBufferSize(2048);
  if (mqtt.connected()) mqtt.disconnect();

  // DIFFERENCE 7: chip id instead of the ESP32 efuse MAC.
  String cid = String(VEHICLE_ID) + "_" + String(ESP.getChipId(), HEX);
  Serial.print("MQTT -> "); Serial.print(rsuId);
  Serial.print(" "); Serial.println(RSUS[idx].host);

  if (!mqtt.connect(cid.c_str())) {
    Serial.print("MQTT state="); Serial.println(mqtt.state());
    return false;
  }

  mqtt.subscribe(topicTipReply().c_str(), 1);
  mqtt.subscribe("tangle/confirmed", 1);
  mqtt.subscribe(("tangle/" + rsuId + "/confirmed").c_str(), 1);
  tipTimeouts = 0;
  Serial.println("MQTT connected.");
  return true;
}

bool connectAnyRSU() {
  connectWiFi();
  for (int i = 0; i < NUM_RSUS; i++)
    if (connectRSU((preferredRSU + i) % NUM_RSUS)) return true;
  return false;
}

void requestTips() {
  if (!mqtt.connected()) return;
  String s = "{\"client\":\"" + String(VEHICLE_ID) + "\"}";
  tipsReady = false; waitingTips = true; tipRequestAt = millis();
  mqtt.publish(topicTips().c_str(), s.c_str(), false);
}

/* ============================== SENSING ============================== */

SensorData sense() {
  // A random walk stays inside the RSU's 25 km/h/s acceleration limit.
  static int speed = 55;
  speed += (int)random(-6, 7);
  if (speed < 5) speed = 5;
  if (speed > 120) speed = 120;

  SensorData s;
  s.speed_kmh = speed;
  s.latitude  = SEND_GPS ? String(FIXED_LAT) : String("");
  s.longitude = SEND_GPS ? String(FIXED_LON) : String("");

  int r = random(100);
  if (r < 85)      s.event = "normal";
  else if (r < 93) s.event = "congestion";
  else if (r < 98) s.event = "hazard";
  else             s.event = "accident";
  return s;
}

/* ======================= CANONICAL JSON (CRITICAL) ===================
 * Byte-for-byte identical to the ESP32 version. The RSU recomputes
 * sha256(canonical(body)) and verifies the signature over the same
 * bytes, where canonical = json.dumps(sort_keys=True,
 * separators=(",",":")). Body keys in sorted order:
 *   approves, creator, data, nonce, pow_difficulty, sequence,
 *   timestamp_ms, version
 * and inside data: event, latitude, longitude, speed_kmh.
 * Built only from the snapshot passed in, never from globals, because
 * the tips can change while PoW is running.
 * ==================================================================== */

String dataCanonical(const SensorData& s) {
  String o = "{\"event\":\"" + s.event + "\"";
  if (s.latitude.length() && s.longitude.length()) {
    o += ",\"latitude\":\"" + s.latitude + "\"";
    o += ",\"longitude\":\"" + s.longitude + "\"";
  }
  o += ",\"speed_kmh\":" + String(s.speed_kmh) + "}";
  return o;
}

String approvesCanonical(const String& a, const String& b) {
  if (!b.length() || a == b) return "[\"" + a + "\"]";
  return "[\"" + a + "\",\"" + b + "\"]";
}

String bodyHead(const String& approves, const SensorData& s) {
  return "{\"approves\":" + approves +
         ",\"creator\":\"" + String(VEHICLE_ID) +
         "\",\"data\":" + dataCanonical(s);
}

String bodyTail(uint64_t seq, uint64_t ts) {
  return ",\"pow_difficulty\":" + String(POW_BITS) +
         ",\"sequence\":" + u64str(seq) +
         ",\"timestamp_ms\":" + u64str(ts) +
         ",\"version\":" + String(VERSION) + "}";
}

/* ============================== SUBMIT =============================== */

bool makeAndSubmit() {
  if (!mqtt.connected() || !tipsReady || !clockReady()) return false;

  // --- snapshot everything the body depends on ---
  SensorData s    = sense();
  if (ATTACK_MODE == ATTACK_FAKE_DATA) s.speed_kmh = 999;
  String approves = approvesCanonical(tipA, tipB);
  uint64_t ts     = epochMs();

  // DIFFERENCE 3: not persisted. Epoch milliseconds already increase
  // across reboots, and committing to EEPROM every transaction would
  // wear the flash out.
  uint64_t seq    = (ts > sequenceNo) ? ts : sequenceNo + 1;
  if (ATTACK_MODE == ATTACK_REPLAY && sequenceNo > 0) {
    seq = sequenceNo;                        // reuse -> replay_sequence
  } else {
    sequenceNo = seq;
  }

  String head = bodyHead(approves, s);
  String tail = bodyTail(seq, ts);
  String preimage = head + tail;

  // Midstate PoW: hash the fixed ~500-byte preimage ONCE, then for each
  // attempt copy that context and append only the nonce digits. Same
  // result as hashing preimage+nonce from scratch, far fewer bytes hashed.
  // BearSSL contexts are plain structs, so a struct copy is a valid clone.
  br_sha256_context base;
  br_sha256_init(&base);
  br_sha256_update(&base, preimage.c_str(), preimage.length());

  uint32_t nonce = 0, attempts = 0;
  uint8_t digest[32];
  char nbuf[12];
  unsigned long start = millis();
  while (ATTACK_MODE != ATTACK_INVALID_POW) {
    attempts++;
    int nlen = snprintf(nbuf, sizeof(nbuf), "%lu", (unsigned long)nonce);

    br_sha256_context c = base;
    br_sha256_update(&c, nbuf, nlen);
    br_sha256_out(&c, digest);

    if (leadingZeroBitsRaw(digest, POW_BITS)) break;
    nonce++;
    // Software SHA-256 and a 3.2 s software watchdog: yield often.
    if ((attempts & 0xFF) == 0) yield();
  }
  if (ATTACK_MODE == ATTACK_INVALID_POW) nonce = random(0, 1000);
  unsigned long powMs = millis() - start;

  String body = head + ",\"nonce\":" + String(nonce) + tail;
  String txid = sha256Hex(body);

  // DIFFERENCE 4: Ed25519::sign() is one blocking call and can outrun the
  // 3.2 s software watchdog. Suspend it here; the 8 s hardware watchdog
  // still protects the board.
  uint8_t sig[64];
  unsigned long signStart = millis();
  ESP.wdtDisable();
  Ed25519::sign(sig, privateKey, publicKey, body.c_str(), body.length());
  if (ATTACK_MODE == ATTACK_BAD_SIGNATURE) sig[0] ^= 0xFF;
  ESP.wdtEnable(0);
  unsigned long signMs = millis() - signStart;

  // Publish the signed bytes themselves, with the extra fields spliced in
  // front. Re-serialising the body would change the numbers.
  // Device-side measurements for the datasheet energy model (F7). They
  // sit OUTSIDE the signed body, so they change neither the txid nor the
  // signature; the RSU simply records them.
  String payload = "{\"id\":\"" + txid +
                   "\",\"signature\":\"" + hexOf(sig, 64) +
                   "\",\"pow_time_ms\":" + String(powMs) +
                   ",\"sign_time_ms\":" + String(signMs) +
                   ",\"tip_wait_ms\":" + String(lastTipWaitMs) +
                   ",\"cpu_mhz\":" + String(ESP.getCpuFreqMHz()) +
                   ",\"device\":\"esp8266\"," +
                   body.substring(1);

  if (!mqtt.publish(topicSubmit().c_str(), payload.c_str(), false)) {
    Serial.println("PUBLISH FAILED (raise mqtt.setBufferSize)");
    return false;
  }

  Serial.println("----- TRANSACTION SUBMITTED -----");
  Serial.print("RSU: ");        Serial.println(rsuId);
  Serial.print("txid: ");       Serial.println(txid.substring(0, 12));
  Serial.print("sequence: ");   Serial.println(u64str(seq));
  Serial.print("event: ");      Serial.println(s.event);
  Serial.print("speed_kmh: ");  Serial.println(s.speed_kmh);
  Serial.print("approves: ");   Serial.println(approves);
  Serial.print("PoW: ");        Serial.print(attempts);
  Serial.print(" hashes, ");    Serial.print(powMs);
  Serial.print(" ms   sign: "); Serial.print(signMs); Serial.println(" ms");
  Serial.print("bytes: ");      Serial.print(payload.length());
  Serial.print("   free heap: "); Serial.println(ESP.getFreeHeap());
  Serial.println("---------------------------------");

  tipsReady = false;
  lastTxAt = millis();
  nextTxInterval = (ATTACK_MODE == ATTACK_SPAM)
                   ? 300
                   : random(MIN_INTERVAL_MS, MAX_INTERVAL_MS + 1);
  return true;
}

void failoverIfNeeded() {
  if (mqtt.connected()) return;
  for (int k = 1; k <= NUM_RSUS; k++)
    if (connectRSU((rsuIndex + k) % NUM_RSUS)) return;
}

/* ============================ SETUP / LOOP =========================== */

void setup() {
  Serial.begin(115200);
  delay(1000);
  randomSeed(RANDOM_REG32);

  Serial.println("\n=== TinyDLT ESP8266 Vehicle (multi-RSU) ===");
  Serial.print("CPU: "); Serial.print(ESP.getCpuFreqMHz());
  Serial.println(" MHz (set 160 MHz in Tools for faster PoW)");

  setupKey();
  connectWiFi();
  syncClock();

  if (!connectAnyRSU()) Serial.println("No RSU reachable at startup.");

  lastTxAt = millis();
  nextTxInterval = (ATTACK_MODE == ATTACK_SPAM)
                   ? 300
                   : random(MIN_INTERVAL_MS, MAX_INTERVAL_MS + 1);
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) connectWiFi();

  if (!mqtt.connected()) { failoverIfNeeded(); delay(250); return; }

  mqtt.loop();

  // No tip reply: that RSU is not serving us. Hand over after a couple of
  // misses rather than on the first one.
  if (waitingTips && millis() - tipRequestAt > TIPS_TIMEOUT_MS) {
    waitingTips = false;
    if (++tipTimeouts >= MAX_TIP_TIMEOUTS) {
      Serial.println("No tips; handing over to the next RSU.");
      connectRSU((rsuIndex + 1) % NUM_RSUS);
    }
  }

  if (!tipsReady && !waitingTips && millis() - lastTxAt >= nextTxInterval)
    requestTips();

  if (tipsReady && !waitingTips) makeAndSubmit();

  delay(5);
}
