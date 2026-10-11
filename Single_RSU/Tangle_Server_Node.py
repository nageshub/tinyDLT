#!/usr/bin/env python3
import json
import hashlib
import random
import sqlite3
import threading
from collections import defaultdict

from paho.mqtt import client as mqtt
import networkx as nx
from pyvis.network import Network
import time
import matplotlib.pyplot as plt
from plot_pow_metrics import plot_pow_time_and_energy
from performance_evaluation import plot_cdf_cp_tld_epc

# ========= TPS MEASUREMENT =========
TX_WINDOW = 5            # seconds
tx_timestamps = []       # store tx arrival times
tps_log = []             # (time, TPS)
experiment_start = time.time()
pow_time_log = []
# ==================================
# ===== CONFIRMATION LATENCY MEASUREMENT =====
tx_creation_time = {}     # txid -> creation time
confirm_latencies = []    # (tx_index, latency)
tx_index = 0
# ==========================================
VOLTAGE = 3.3        # volts
CURRENT = 0.07       # amps (ESP8266 active)
# ===== TIP COUNT MEASUREMENT =====
tip_log = []              # (elapsed_time, tip_count)
tip_start_time = time.time()
# =========================================
# ===== TRUST-BASED MALICIOUS DETECTION =====
trust_scores = defaultdict(lambda: 1.0)

TRUST_REWARD = 0.01
TRUST_PENALTY = 0.2
TRUST_THRESHOLD = 0.3
event_window = []
EVENT_WINDOW_SIZE = 10

trust_log = []   # for plotting trust evolution

# ================= CONFIG =================
BROKER = "localhost"
PORT = 1883
DB = "tangle.db"
HTML_FILE = "tangle.html"

GENESIS = "GENESIS"
DIFFICULTY = 12
CONFIRM_THRESHOLD = 2
MAX_INITIAL_TIPS = 10
published_confirmed = set()

# ===== MALICIOUS DETECTION =====
malicious_log = []
blacklist = set()
ENABLE_BLACKLIST = False   # set True to auto-block attackers

# =========================================

lock = threading.Lock()
G = nx.DiGraph()
bandits = defaultdict(lambda: {"alpha": 1, "beta": 1})

# ================= DATABASE =================
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS tx (
            id TEXT PRIMARY KEY,
            creator TEXT,
            timestamp REAL,
            data TEXT,
            approves TEXT,
            nonce INTEGER,
            pow_time_ms INTEGER,
            first_approval_time REAL,
            confirm_time REAL
        )
    """)
    conn.commit()
    conn.close()

def store_tx(tx):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
        INSERT OR REPLACE INTO tx VALUES (?,?,?,?,?,?,?,?,?)
    """, (
        tx["id"],
        tx["creator"],
        tx["timestamp"],
        tx["data"],
        json.dumps(tx["approves"]),
        tx["nonce"],
        tx.get("pow_time_ms", 0),
        None, 
        None
    ))
    conn.commit()
    conn.close()

# ================= PoW =====================
def validate_pow(tx):
    body = json.dumps({
        "creator": tx["creator"],
        "timestamp": tx["timestamp"],
        "data": tx["data"],
        "approves": tx["approves"]
    }, separators=(',', ':'))

    h = hashlib.sha256((body + str(tx["nonce"])).encode()).hexdigest()

    zeros = 0
    for c in h:
        bits = bin(int(c, 16))[2:].zfill(4)
        for b in bits:
            if b == '0':
                zeros += 1
            else:
                return zeros >= DIFFICULTY
    return zeros >= DIFFICULTY

# ================= DAG =====================
def init_genesis():
    G.add_node(GENESIS, state="genesis")

def get_tips():
    return [n for n in G.nodes if G.out_degree(n) == 0 and n != GENESIS]

def thompson_select(tips):
    return max(
        tips,
        key=lambda t: random.betavariate(bandits[t]["alpha"], bandits[t]["beta"])
    )

def select_two_tips():
    tips = get_tips()

    if len(G.nodes) <= MAX_INITIAL_TIPS:
        return [GENESIS, GENESIS]

    if len(tips) == 1:
        return [tips[0], GENESIS]

    t1 = thompson_select(tips)
    t2 = thompson_select([t for t in tips if t != t1])
    return [t1, t2]

# ================= CUMULATIVE WEIGHT =================
def cumulative_weight(n):
    return len(nx.descendants(G, n))

def update_states():
    for n in G.nodes:
        if n == GENESIS:
            G.nodes[n]["state"] = "genesis"
            continue

        cw = cumulative_weight(n)

        if cw == 0:
            G.nodes[n]["state"] = "tip"
        elif cw >= CONFIRM_THRESHOLD:
            G.nodes[n]["state"] = "confirmed"
        else:
            G.nodes[n]["state"] = "approved"

# ================= VISUALIZATION =================
def update_pyvis():
    net = Network(height="800px", width="100%", directed=True)
    net.force_atlas_2based(gravity=-40)

    for n, d in G.nodes(data=True):
        state = d["state"]
        color = {
            "genesis": "gold",
            "tip": "red",
            "approved": "orange",
            "confirmed": "green"
        }[state]

        net.add_node(
            n,
            label=n,
            color=color,
            title=f"State: {state}<br>CW: {cumulative_weight(n)}"
        )

    for u, v in G.edges:
        net.add_edge(v, u)

    net.save_graph(HTML_FILE)

# ================= MQTT ====================
client = mqtt.Client(
    client_id="rsu_dlt_server",
    callback_api_version=mqtt.CallbackAPIVersion.VERSION1
)

def on_connect(c, u, f, rc):
    print("✅ RSU connected to MQTT")
    c.subscribe("tangle/request_tips")
    c.subscribe("tangle/submit_tx")

def on_message(c, u, msg):
    payload = json.loads(msg.payload.decode())
    # creator = payload.get("creator","")

    if msg.topic == "tangle/request_tips":
        tips = select_two_tips()
        c.publish(f"tangle/tips/{payload['client']}", json.dumps({"tips": tips}))
        print("💡 Sent tips:", tips)

    elif msg.topic == "tangle/submit_tx":
        creator = payload.get("creator", "")

        # ---- BLACKLIST CHECK ----
        if creator in blacklist:
            print("⛔ Blocked blacklisted node:", creator)
            return

        # ---- TRUST THRESHOLD CHECK ----
        if trust_scores[creator] < TRUST_THRESHOLD:
            print(f"⛔ Node {creator} blocked (low trust={trust_scores[creator]:.2f})")

            if ENABLE_BLACKLIST:
                blacklist.add(creator)

            return

        # ---- PoW Validation ----
        if not validate_pow(payload):
            trust_scores[creator] = max(
                0,
                trust_scores[creator] - TRUST_PENALTY
            )

            malicious_log.append({
                "time": time.time(),
                "node": creator,
                "type": "invalid_pow"
            })

            print(f"🚨 Invalid PoW from {creator} | Trust={trust_scores[creator]:.2f}")

            trust_log.append(
                (
                    time.time() - experiment_start,
                    creator,
                    trust_scores[creator]
                )
            )

            return

        event = payload["data"]

        event_window.append(
            (
                creator,
                event
            )
        )

        update_consensus_trust()

        # ---- Valid TX → reward trust ----
        trust_scores[creator] = min(
            1,
            trust_scores[creator] + TRUST_REWARD
        )

        trust_log.append(
            (
                time.time() - experiment_start,
                creator,
                trust_scores[creator]
            )
        )

        txid = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()
        ).hexdigest()[:8]

        payload["id"] = txid

        global tx_index
        tx_index += 1
        tx_creation_time[txid] = time.time()

        with lock:
            store_tx(payload)

            G.add_node(
                txid,
                data=payload["data"],
                timestamp=payload["timestamp"],
                creator=payload["creator"]
            )

            for p in payload["approves"]:
                if p not in G:
                    G.add_node(p)

                if p != GENESIS and G.out_degree(p) == 0:
                    first_approval_time = time.time()

                    conn = sqlite3.connect(DB)
                    c = conn.cursor()

                    c.execute(
                        """UPDATE tx SET first_approval_time = ? WHERE id = ? """,
                        (first_approval_time, p)
                    )

                    conn.commit()
                    conn.close()

                G.add_edge(p, txid)
                bandits[p]["alpha"] += 1

            now = time.time()
            tx_timestamps.append(now)

            # Remove old timestamps outside window
            tx_timestamps[:] = [
                t for t in tx_timestamps
                if now - t <= TX_WINDOW
            ]

            current_tps = len(tx_timestamps) / TX_WINDOW
            elapsed = now - experiment_start

            tps_log.append((elapsed, current_tps))

            print(f"📊 TPS @ {elapsed:.1f}s = {current_tps:.2f}")

            update_states()
            update_pyvis()

            elapsed = time.time() - tip_start_time
            tips = count_tips()

            tip_log.append((elapsed, tips))

            print(f"📌 Tip count @ {elapsed:.1f}s = {tips}")

            # pow_time_log.append(payload["pow_time_ms"])
            # pow_energy_log.append(payload["pow_energy_j"])
            # time_log.append(payload["timestamp"])

            # 🔥 DLT DATA DISSEMINATION 🔥
            for n in G.nodes:
                if n == GENESIS:
                    continue

                cw = cumulative_weight(n)

                if cw >= CONFIRM_THRESHOLD and n not in published_confirmed:
                    published_confirmed.add(n)

                    confirm_time = time.time()
                    latency = confirm_time - tx_creation_time[n]

                    confirm_latencies.append(
                        (
                            tx_creation_time[n],
                            latency
                        )
                    )

                    conn = sqlite3.connect(DB)
                    c = conn.cursor()

                    c.execute(
                        """UPDATE tx SET confirm_time = ? WHERE id = ?""",
                        (confirm_time, n)
                    )

                    conn.commit()
                    conn.close()

                    print(
                        f"⏱ Confirmation latency for {n}: {latency:.3f}s"
                    )

                    tx_row = {
                        "txid": n,
                        "data": G.nodes[n]["data"],
                        "timestamp": G.nodes[n]["timestamp"],
                        "confirm_time": confirm_time
                    }

                    client.publish(
                        "tangle/confirmed",
                        json.dumps(tx_row)
                    )

                    print(f"📡 Published confirmed TX {n}")

        print(f"📥 Stored TX {txid}")
        
#===============================neighbor consensus=======================      
def update_consensus_trust():

    if len(event_window) < EVENT_WINDOW_SIZE:
        return

    counts = {}

    for creator, event in event_window:
        counts[event] = counts.get(event, 0) + 1

    majority_event = max(counts, key=counts.get)

    for creator, event in event_window:

        if event == majority_event:
            trust_scores[creator] = min(
                1.0,
                trust_scores[creator] + 0.05
            )

        else:
            trust_scores[creator] = max(
                0.0,
                trust_scores[creator] - 0.1
            )

        trust_log.append(
            (
                time.time() - experiment_start,
                creator,
                trust_scores[creator]
            )
        )

    event_window.clear()   
   

    
#===============================plot throughput=======================      
def plot_tps():
    if not tps_log:
        return

    times, tps = zip(*tps_log)

    plt.figure()
    plt.plot(times, tps)
    plt.xlabel("Time (s)")
    plt.ylabel("Transactions Per Second (TPS)")
    plt.title("DLT Transaction Throughput Over Time")
    plt.grid(True)
    plt.savefig("tps_plot.png")
    plt.show()
    
#=====================plot vonfirmation latency=================
def plot_confirmation_latency():
    if not confirm_latencies:
        return

    times, latencies = zip(*confirm_latencies)

    plt.figure()
    plt.plot(range(len(latencies)), latencies, marker='o')
    plt.xlabel("Transaction Index")
    plt.ylabel("Confirmation Latency (s)")
    plt.title("DLT Confirmation Latency")
    plt.grid(True)
    plt.savefig("confirmation_latency.png")
    plt.show()
#==================tip count calc=============================
def count_tips():
    return len([
        n for n in G.nodes
        if G.out_degree(n) == 0 and n != GENESIS
    ])
    
#=================energy calculation===============
def pow_energy_joule(pow_time_ms):
    return VOLTAGE * CURRENT * (pow_time_ms / 1000)


#===================plot tip count====================
def plot_tip_count():
    if not tip_log:
        return

    times, tips = zip(*tip_log)

    plt.figure()
    plt.plot(times, tips, marker='o')
    plt.xlabel("Time (s)")
    plt.ylabel("Number of Tips")
    plt.title("Tip Count Over Time in DAG-based DLT")
    plt.grid(True)
    plt.savefig("tip_count_over_time.png")
    plt.show()
    
#====================================
def plot_pow_metrics():

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("SELECT timestamp, pow_time_ms FROM tx ORDER BY timestamp")
    rows = c.fetchall()

    conn.close()

    if not rows:
        print("⚠️ No PoW data in database")
        return

    timestamps = [r[0] for r in rows]
    pow_time = [r[1] for r in rows]
    pow_energy = [pow_energy_joule(r[1]) for r in rows]

    # ---- Plot PoW Time ----
    plt.figure()
    plt.plot(timestamps, pow_time)
    plt.xlabel("Timestamp")
    plt.ylabel("PoW Computation Time (ms)")
    plt.title("PoW Time vs Timestamp")
    plt.grid(True)
    plt.savefig("pow_time_vs_time.png")
    plt.show()

    # ---- Plot PoW Energy ----
    plt.figure()
    plt.plot(timestamps, pow_energy)
    plt.xlabel("Timestamp")
    plt.ylabel("PoW Energy (Joules)")
    plt.title("PoW Energy vs Timestamp")
    plt.grid(True)
    plt.savefig("pow_energy_vs_time.png")
    plt.show()


def plot_attack_log():
    if not malicious_log:
        print("No attacks recorded")
        return

    times = [x["time"] - experiment_start for x in malicious_log]
    labels = [x["type"] for x in malicious_log]

    plt.figure()
    plt.scatter(times, labels)
    plt.xlabel("Time (s)")
    plt.ylabel("Attack Type")
    plt.title("Detected Malicious Transactions")
    plt.grid(True)
    plt.savefig("malicious_activity.png")
    plt.show()

def plot_trust_evolution():
    if not trust_log:
        print("No trust data recorded")
        return

    times = [x[0] for x in trust_log]
    nodes = [x[1] for x in trust_log]
    scores = [x[2] for x in trust_log]

    plt.figure()
    plt.scatter(times, scores)
    plt.xlabel("Time (s)")
    plt.ylabel("Trust Score")
    plt.title("Trust Score Evolution of Vehicles")
    plt.grid(True)
    plt.savefig("trust_evolution.png")
    plt.show()
# ================= MAIN ====================
if __name__ == "__main__":
    init_db()
    init_genesis()
    update_states()
    update_pyvis()

    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(BROKER, PORT)

    print("🚀 RSU DLT Server running")
    print("🌐 Open tangle.html for DAG")
    try:
        client.loop_forever()
    except KeyboardInterrupt:
        print("\n🛑 Experiment stopped, plotting TPS...")
        plot_tps()
        print("\n🛑 Experiment stopped, plotting confirmation latency...")
        plot_confirmation_latency()
        print("\n🛑 Experiment stopped, plotting tip count...")
        plot_tip_count()
        print("\n🛑 Experiment stopped, plotting PoW time and energy...")
        plot_pow_time_and_energy()
        print("\n🛑 Experiment stopped, plotting cdf_cp_tld_epc...")
        plot_cdf_cp_tld_epc()
        print("\n🛑 Plotting malicious activity...")
        plot_attack_log()
        print("\n🛑 Plotting trust evolution...")
        plot_trust_evolution()

