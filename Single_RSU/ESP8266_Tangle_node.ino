#define MQTT_MAX_PACKET_SIZE 512
// ===== ATTACK MODES =====
#define ATTACK_NONE 0
#define ATTACK_INVALID_POW 1
#define ATTACK_SPAM 2
#define ATTACK_FAKE_DATA 3

int ATTACK_MODE = ATTACK_NONE;  
// change to:
// ATTACK_INVALID_POW
// ATTACK_SPAM
// ATTACK_FAKE_DATA

#include <ESP8266WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <bearssl/bearssl.h>

/* ================= CONFIG ================= */
const char* ssid = "******";
const char* pass = "****************";
const char* mqtt_server = "10.243.140.48";
const int mqtt_port = 1883;

const int DIFFICULTY = 12;
#define MAX_TX_QUEUE 10
/* ========================================== */

WiFiClient espClient;
PubSubClient client(espClient);

String nodeId;

/* ================= TX QUEUE ================= */
DynamicJsonDocument* txQueue[MAX_TX_QUEUE];
int qHead = 0;
int qTail = 0;

bool queueEmpty() {
  return qHead == qTail;
}

bool queueFull() {
  return ((qTail + 1) % MAX_TX_QUEUE) == qHead;
}

void enqueue_tx(const JsonDocument& tx) {
  if (queueFull()) {
    Serial.println("⚠️ TX queue full, dropping oldest");
    delete txQueue[qHead];
    qHead = (qHead + 1) % MAX_TX_QUEUE;
  }
  txQueue[qTail] = new DynamicJsonDocument(256);
  txQueue[qTail]->set(tx);   // safe deep copy
  qTail = (qTail + 1) % MAX_TX_QUEUE;
}

DynamicJsonDocument* dequeue_tx() {
  DynamicJsonDocument* tx = txQueue[qHead];
  qHead = (qHead + 1) % MAX_TX_QUEUE;
  return tx;
}

/* ================= PoW ================= */
bool check_pow(const String& msg, uint32_t nonce) {
  uint8_t hash[32];
  br_sha256_context ctx;

  br_sha256_init(&ctx);
  String s = msg + String(nonce);
  br_sha256_update(&ctx, s.c_str(), s.length());
  br_sha256_out(&ctx, hash);

  int zeros = 0;
  for (int i = 0; i < 32; i++) {
    for (int b = 7; b >= 0; b--) {
      if ((hash[i] >> b) & 1)
        return zeros >= DIFFICULTY;
      zeros++;
    }
  }
  return zeros >= DIFFICULTY;
}

uint32_t do_pow(const String& body, unsigned long &pow_time_ms) {
  Serial.println("⚙️  Starting PoW");
  uint32_t nonce = 0;
  unsigned long start = millis();

  while (!check_pow(body, nonce)) {
    nonce++;
    if ((nonce & 0xFF) == 0) yield();
  }

  pow_time_ms = millis() - start;
  Serial.print("✅ PoW solved in ");
  Serial.print(pow_time_ms);
  Serial.println(" ms");
  return nonce;
}

/* ================= TX BUILD (NO PoW HERE) ================= */
void build_tx() {
  Serial.println("🧱 Building transaction");

  StaticJsonDocument<256> tx;
  tx["creator"] = nodeId;
  tx["timestamp"] = millis() / 1000;

  if (ATTACK_MODE == ATTACK_FAKE_DATA) {
    tx["data"] = "speed=999";   // malicious data
    Serial.println("🚨 Fake data attack TX created");
  } else {
	const char* events[] =
		{
		  "clear",
		  "clear",
		  "clear",
		  "accident"
		};

	tx["data"] =events[random(0,4)];
  }

  enqueue_tx(tx);
}

/* ================= TX SUBMIT (PoW AFTER TIPS) ================= */
void submit_tx(JsonArray tips) {
  if (queueEmpty()) return;

  DynamicJsonDocument* tx = dequeue_tx();
  JsonArray arr = tx->createNestedArray("approves");

  for (JsonVariant v : tips) {
    arr.add(v.as<String>());
  }

  Serial.print("🔗 Approving tips: ");
  for (JsonVariant v : arr) {
    Serial.print(v.as<String>());
    Serial.print(" ");
  }
  Serial.println();

  // ---- PoW MUST be computed here ----
  String body;
  uint32_t nonce;
  unsigned long pow_time = 0;

  serializeJson(*tx, body);

  if (ATTACK_MODE == ATTACK_INVALID_POW) {
    Serial.println("🚨 Sending INVALID PoW transaction");
    nonce = random(0,1000);   // wrong nonce
  }
  else {
    nonce = do_pow(body, pow_time);
  }

  (*tx)["nonce"] = nonce;
  (*tx)["pow_time_ms"] = pow_time;

  char buf[512];
  serializeJson(*tx, buf);
  client.publish("tangle/submit_tx", buf);

  Serial.println("📤 Transaction submitted");
  delete tx;   // free heap
}

/* ================= MQTT CALLBACK ================= */
void callback(char* topic, byte* payload, unsigned int len) {
  String msg;
  for (unsigned int i = 0; i < len; i++) msg += (char)payload[i];
  String t = String(topic);

  if (t == "tangle/confirmed") {
    Serial.print("📡 Confirmed DLT data received: ");
    Serial.println(msg);
  }

  if (t == "tangle/tips/" + nodeId) {
    Serial.println("📩 Tips received");

    StaticJsonDocument<256> doc;
    if (deserializeJson(doc, msg)) {
      Serial.println("❌ Failed to parse tips JSON");
      return;
    }
    submit_tx(doc["tips"]);
  }
}

/* ================= MQTT CONNECT ================= */
void reconnectMQTT() {
  while (!client.connected()) {
    Serial.print("🔌 Connecting to MQTT...");
    if (client.connect(nodeId.c_str())) {
      Serial.println(" connected");
      client.subscribe(("tangle/tips/" + nodeId).c_str());
      client.subscribe("tangle/confirmed");
    } else {
      Serial.print(" failed, rc=");
      Serial.println(client.state());
      delay(2000);
    }
  }
}

/* ================= SETUP ================= */
void setup() {
  Serial.begin(115200);
  delay(2000);
  Serial.println("\n🚗 ESP Vehicle Node Booted");

  WiFi.begin(ssid, pass);
  Serial.print("📶 Connecting WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("\n✅ WiFi connected");
  Serial.print("📍 IP: ");
  Serial.println(WiFi.localIP());

  nodeId = WiFi.macAddress();
  Serial.print("🆔 Node ID: ");
  Serial.println(nodeId);

  client.setServer(mqtt_server, mqtt_port);
  client.setCallback(callback);
  reconnectMQTT();
}

/* ================= LOOP ================= */
void loop() {
  if (WiFi.status() != WL_CONNECTED) return;
  if (!client.connected()) reconnectMQTT();

  client.loop();

  // ---- continuous sensing ----
static unsigned long lastGen = 0;
unsigned long genInterval;
if (ATTACK_MODE == ATTACK_SPAM)
    genInterval = 500;      // spam fast
else
    genInterval = random(4000,7000);

if (millis() - lastGen > genInterval) {
    build_tx();
    lastGen = millis();
}

  // ---- opportunistic submission ----
  static unsigned long lastReq = 0;
  if (!queueEmpty() && millis() - lastReq > 3000) {
    Serial.println("🔍 Requesting tips");
    client.publish(
      "tangle/request_tips",
      ("{\"client\":\"" + nodeId + "\"}").c_str()
    );
    lastReq = millis();
  }
}
