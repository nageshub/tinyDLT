/*
 TinyDLT ESP32 Vehicle Node - multi-RSU  (corrected)
 Libraries: PubSubClient, ArduinoJson, Crypto (Rhys Weatherley)

 Fixes against the previous draft (each one caused 100% rejection or a
 silent failure):
   1. Floats in `data` -> rejected as txid_mismatch. The ESP wrote
      "42.000000" and "12.971600"; Python re-serialises the parsed values
      as "42.0" and "12.9716", so the recomputed txid never matched.
      Speed is now an integer and the coordinates are JSON strings. The
      RSU does float() on them, so its range check still works, but the
      signed bytes are exactly what we wrote.
   2. The payload was rebuilt with ArduinoJson after signing, so the wire
      bytes differed from the signed bytes. The signed body string is now
      published verbatim, with id/signature/pow_time_ms spliced in.
   3. The tips could change during PoW (mqtt.loop() ran inside the mining
      loop), making the body disagree with the PoW preimage. All body
      inputs are now snapshotted before mining.
   4. String(uint64_t) is not portable across ESP32 core versions and can
      truncate epoch milliseconds to 32 bits. Explicit u64 helper added.
   5. Ed25519::generatePrivateKey() needs the Crypto RNG to be seeded;
      the key is now filled from esp_random().
   6. Sequence was a counter that resets when NVS is erased -> the RSU
      then rejects replay_sequence. It is now epoch-ms based, monotonic,
      and still persisted.
   7. Speed jumped randomly over the full range, tripping the RSU's
      acceleration check and halving every data score. Now a random walk.

 First boot prints the public key. Add it to vehicle_keys.json on ONE
 RSU; the others learn it through the RSU handshake.
*/

#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <mbedtls/sha256.h>
#include <esp_system.h>
#include <Crypto.h>
#include <Ed25519.h>
#include <time.h>
#include <sys/time.h>

/* ============================== CONFIG =============================== */
const char* VEHICLE_ID    = "vehicle_02";
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
  int    speed_kmh;          // integer: see fix 1
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

const int ATTACK_MODE = ATTACK_INVALID_POW;

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
const uint32_t MIN_INTERVAL_MS  = 5000;
const uint32_t MAX_INTERVAL_MS  = 10000;
const uint32_t TIPS_TIMEOUT_MS  = 5000;
const int      MAX_TIP_TIMEOUTS = 2;      // then hand over to the next RSU

// An isolated testbed usually has no internet, so NTP never syncs and the
// node would sign transactions with a 1970 clock (rejected as
// timestamp_invalid). The RSU stamps every tip reply with its own time; if
// NTP is unavailable the node adopts that clock instead. Note for the
// paper: this trusts the RSU as a time source.
const bool  USE_RSU_TIME = true;
const uint32_t NTP_WAIT_MS = 6000;      // do not stall the boot on NTP

// ---- registration certificate (how this node joins without anyone
// editing vehicle_keys.json). Issue it with:
//     python3 ca_tool.py issue vehicle_01 <public key printed on boot>
// and paste the two lines it prints here. Leave VEHICLE_CERT empty to use
// the manual allowlist instead. The certificate travels outside the signed
// body, so it changes neither the txid nor the PoW.
const char* VEHICLE_CERT     = "";
const char* VEHICLE_CERT_SIG = "";

const bool  SEND_GPS = true;
const char* FIXED_LAT = "12.971600";      // fixed-decimal strings, see fix 1
const char* FIXED_LON = "77.594600";
/* ===================================================================== */

WiFiClient   net;
PubSubClient mqtt(net);
Preferences  prefs;

uint8_t  privateKey[32], publicKey[32];
uint64_t sequenceNo = 0;
int      rsuIndex = 0;
int      tipTimeouts = 0;
String   rsuId;

String   tipA = "GENESIS";
String   tipB = "";
bool     tipsReady = false;
bool     rsuTimeSet = false;
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

bool fromHex(const String& s, uint8_t* out, size_t n) {
  if (s.length() != n * 2) return false;
  auto nib = [](char c)->int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; i < n; i++) {
    int a = nib(s[2 * i]), b = nib(s[2 * i + 1]);
    if (a < 0 || b < 0) return false;
    out[i] = (uint8_t)((a << 4) | b);
  }
  return true;
}

// FIX 4: portable 64-bit to decimal. String(uint64_t) may not exist or may
// truncate, and epoch milliseconds do not fit in 32 bits.
String u64str(uint64_t v) {
  char buf[21];
  int i = 20;
  buf[i] = '\0';
  if (v == 0) buf[--i] = '0';
  while (v > 0) { buf[--i] = '0' + (char)(v % 10); v /= 10; }
  return String(&buf[i]);
}

String sha256Hex(const String& s) {
  uint8_t d[32];
  mbedtls_sha256_context c;
  mbedtls_sha256_init(&c);
  mbedtls_sha256_starts(&c, 0);
  mbedtls_sha256_update(&c, (const unsigned char*)s.c_str(), s.length());
  mbedtls_sha256_finish(&c, d);
  mbedtls_sha256_free(&c);
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

bool ntpSynced()   { return time(nullptr) > 1700000000; }
bool clockReady()  { return ntpSynced() || rsuTimeSet; }

// Adopt the RSU's clock (fix: no NTP on an isolated network).
void adoptRsuTime(uint64_t serverMs) {
  if (!USE_RSU_TIME || serverMs < 1700000000000ULL) return;

  int64_t drift = (int64_t)serverMs - (int64_t)epochMs();
  if (ntpSynced() && drift > -2000 && drift < 2000) return;

  struct timeval tv;
  tv.tv_sec  = (time_t)(serverMs / 1000ULL);
  tv.tv_usec = (suseconds_t)((serverMs % 1000ULL) * 1000ULL);
  settimeofday(&tv, nullptr);
  rsuTimeSet = true;

  Serial.print("Clock set from ");
  Serial.print(rsuId);
  Serial.print(" (drift was ");
  Serial.print((long)drift);
  Serial.println(" ms)");
}

/* ============================ VEHICLE KEY ============================ */

void setupKey() {
  prefs.begin("tinydlt", false);
  String k = prefs.getString("priv", "");

  if (k.length() == 64 && fromHex(k, privateKey, 32)) {
    Ed25519::derivePublicKey(publicKey, privateKey);
  } else {
    // FIX 5: fill from the hardware RNG instead of relying on the Crypto
    // library's RNG being seeded.
    for (int i = 0; i < 32; i++) privateKey[i] = (uint8_t)(esp_random() & 0xFF);
    Ed25519::derivePublicKey(publicKey, privateKey);
    prefs.putString("priv", hexOf(privateKey, 32));
    Serial.println("Generated a new vehicle key (stored in NVS).");
  }

  sequenceNo = prefs.getULong64("seq", 0);

  Serial.println("=====================================================");
  Serial.print("VEHICLE_ID: ");  Serial.println(VEHICLE_ID);
  Serial.print("ATTACK_MODE: "); Serial.println(attackName());
  Serial.print("PUBLIC_KEY: ");  Serial.println(hexOf(publicKey, 32));
  if (strlen(VEHICLE_CERT)) {
    Serial.println("Carrying a registration certificate: the RSUs will");
    Serial.println("enrol this node automatically on first contact.");
  } else {
    Serial.println("No certificate. Either issue one:");
    Serial.print("  python3 ca_tool.py issue ");
    Serial.print(VEHICLE_ID); Serial.print(" ");
    Serial.println(hexOf(publicKey, 32));
    Serial.println("or add this line to vehicle_keys.json on one RSU:");
    Serial.print("  \""); Serial.print(VEHICLE_ID); Serial.print("\": \"");
    Serial.print(hexOf(publicKey, 32)); Serial.println("\"");
  }
  Serial.println("=====================================================");
}

/* ============================== NETWORK ============================== */

void connectWiFi() {
  if (WiFi.status() == WL_CONNECTED) return;
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  // "Brownout detector was triggered" means the 3V3 rail dips when the
  // radio transmits: a thin USB cable, a weak port, or a hub. Fix the
  // supply first (short good cable into a powered port, or 5V/1A, plus
  // 100uF+ across 3V3/GND); lowering the radio power cuts the peak draw.
  WiFi.setTxPower(WIFI_POWER_11dBm);
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
  // FIX: UTC. gettimeofday() must return real epoch time; the RSU rejects
  // anything more than 30 s from its own clock.
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  unsigned long t0 = millis();
  while (!ntpSynced() && millis() - t0 < NTP_WAIT_MS) delay(250);

  if (ntpSynced()) {
    Serial.println("NTP synchronized.");
  } else {
    Serial.println("No NTP (no internet?). Will take the time from the "
                   "RSU's tip reply instead.");
  }
}

String topicSubmit()   { return "tangle/" + rsuId + "/submit_tx"; }
String topicTips()     { return "tangle/" + rsuId + "/request_tips"; }
String topicTipReply() { return "tangle/tips/" + String(VEHICLE_ID); }

void mqttCallback(char* topic, byte* payload, unsigned int len) {
  String msg; msg.reserve(len);
  for (unsigned int i = 0; i < len; i++) msg += (char)payload[i];
  String t = String(topic);

  if (t == topicTipReply()) {
    StaticJsonDocument<1024> d;
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
    // The RSU stamps its own time here; use it when NTP is unavailable.
    if (d.containsKey("ts_ms")) adoptRsuTime(d["ts_ms"].as<uint64_t>());

    lastTipWaitMs = millis() - tipRequestAt;   // energy model input
    tipsReady = true; waitingTips = false; tipTimeouts = 0;
    Serial.print("Tips: "); Serial.print(tipA);
    if (tipB.length()) { Serial.print(" , "); Serial.print(tipB); }
    Serial.println();
    return;
  }

  if (t == "tangle/confirmed" || t == "tangle/" + rsuId + "/confirmed") {
    StaticJsonDocument<1024> d;
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

  String cid = String(VEHICLE_ID) + "_" + String((uint32_t)ESP.getEfuseMac(), HEX);
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
  // FIX 7: a random walk stays inside the RSU's 25 km/h/s acceleration
  // limit. Random jumps over the whole range halve every data score.
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
 * The RSU recomputes sha256(canonical(body)) and verifies the signature
 * over the same bytes, where canonical = json.dumps(sort_keys=True,
 * separators=(",",":")). Body keys in sorted order:
 *   approves, creator, data, nonce, pow_difficulty, sequence,
 *   timestamp_ms, version
 * and inside data: event, latitude, longitude, speed_kmh.
 * Everything is built from the snapshot passed in - never from globals,
 * because the tips can change while PoW is running (fix 3).
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

  // --- snapshot everything the body depends on (fix 3) ---
  SensorData s   = sense();
  if (ATTACK_MODE == ATTACK_FAKE_DATA) s.speed_kmh = 999;
  String approves = approvesCanonical(tipA, tipB);
  uint64_t ts     = epochMs();
  uint64_t seq    = (ts > sequenceNo) ? ts : sequenceNo + 1;   // fix 6
  if (ATTACK_MODE == ATTACK_REPLAY && sequenceNo > 0) {
    seq = sequenceNo;                        // reuse -> replay_sequence
  } else {
    sequenceNo = seq;
    prefs.putULong64("seq", seq);
  }

  String head = bodyHead(approves, s);
  String tail = bodyTail(seq, ts);
  String preimage = head + tail;

  // PoW = find nonce such that sha256(preimage + decimal(nonce)) has
  // POW_BITS leading zero bits. The preimage (~500 bytes) is identical for
  // every attempt, so it is hashed ONCE into a base context; each attempt
  // clones that midstate and appends only the few nonce digits. Same hash,
  // same result as hashing the whole string each time - but the old loop
  // rebuilt a 500-byte String, rehashed it and hex-encoded it on every
  // attempt, which is what made a 12-bit PoW take ~1 s.
  mbedtls_sha256_context base;
  mbedtls_sha256_init(&base);
  mbedtls_sha256_starts(&base, 0);
  mbedtls_sha256_update(&base, (const unsigned char*)preimage.c_str(),
                        preimage.length());

  uint32_t nonce = 0, attempts = 0;
  uint8_t digest[32];
  char nbuf[12];
  unsigned long start = millis();
  while (ATTACK_MODE != ATTACK_INVALID_POW) {
    attempts++;
    int nlen = snprintf(nbuf, sizeof(nbuf), "%lu", (unsigned long)nonce);

    mbedtls_sha256_context c;
    mbedtls_sha256_init(&c);
    mbedtls_sha256_clone(&c, &base);
    mbedtls_sha256_update(&c, (const unsigned char*)nbuf, nlen);
    mbedtls_sha256_finish(&c, digest);
    mbedtls_sha256_free(&c);

    if (leadingZeroBitsRaw(digest, POW_BITS)) break;
    nonce++;
    if ((attempts & 0x3FF) == 0) yield();   // no mqtt.loop() here: fix 3
  }
  mbedtls_sha256_free(&base);
  if (ATTACK_MODE == ATTACK_INVALID_POW) nonce = random(0, 1000);
  unsigned long powMs = millis() - start;

  String body = head + ",\"nonce\":" + String(nonce) + tail;
  String txid = sha256Hex(body);

  uint8_t sig[64];
  unsigned long signStart = millis();
  Ed25519::sign(sig, privateKey, publicKey, body.c_str(), body.length());
  if (ATTACK_MODE == ATTACK_BAD_SIGNATURE) sig[0] ^= 0xFF;
  unsigned long signMs = millis() - signStart;

  // FIX 2: publish the signed bytes themselves, with the extra fields
  // spliced in front. Re-serialising the body would change the numbers.
  String payload = "{\"id\":\"" + txid +
                   "\",\"signature\":\"" + hexOf(sig, 64) +
                   "\",\"pow_time_ms\":" + String(powMs) +
                   // Device-side measurements for the datasheet energy
                   // model (F7). They sit OUTSIDE the signed body, so
                   // they change neither the txid nor the signature.
                   ",\"sign_time_ms\":" + String(signMs) +
                   ",\"tip_wait_ms\":" + String(lastTipWaitMs) +
                   ",\"cpu_mhz\":" + String(ESP.getCpuFreqMHz()) +
                   ",\"device\":\"esp32\"";

  if (strlen(VEHICLE_CERT) && strlen(VEHICLE_CERT_SIG)) {
    payload += ",\"cert\":";
    payload += VEHICLE_CERT;                 // already canonical JSON
    payload += ",\"cert_sig\":\"";
    payload += VEHICLE_CERT_SIG;
    payload += "\"";
  }

  payload += "," + body.substring(1);

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
  Serial.print("bytes: ");      Serial.println(payload.length());
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
  randomSeed((uint32_t)esp_random());

  Serial.println("\n=== TinyDLT ESP32 Vehicle (multi-RSU) ===");


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

  if (tipsReady && !waitingTips) {
    if (!clockReady()) {
      // v7: this used to be a silent stall - the node kept asking for
      // tips and never submitted, and the RSU showed tx=0 with no
      // rejection. Say it out loud, once every 10 s.
      static unsigned long lastMoan = 0;
      if (millis() - lastMoan > 10000) {
        lastMoan = millis();
        Serial.println("NOT SUBMITTING: no clock yet. Either give the "
                       "board internet for NTP, or run an rsu_server.py "
                       "new enough to put ts_ms in its tip reply.");
      }
    } else {
      makeAndSubmit();
    }
  }

  delay(5);
}
