import sqlite3
import matplotlib.pyplot as plt
from collections import defaultdict

DB = "tangle.db"

VOLTAGE = 3.3
CURRENT = 0.07   # ESP8266 active current (A)

def plot_pow_time_and_energy():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("""
        SELECT creator, pow_time_ms
        FROM tx
        WHERE pow_time_ms IS NOT NULL AND pow_time_ms > 0
    """)
    rows = c.fetchall()
    conn.close()

    if not rows:
        print("⚠️ No PoW data available")
        return

    per_node = defaultdict(list)
    for creator, t in rows:
        per_node[creator].append(t)

    # -------- PoW Time --------
    plt.figure()
    for node, times in per_node.items():
        plt.plot(times, label=node)

    plt.xlabel("Transaction Index")
    plt.ylabel("PoW Time (ms)")
    plt.title("PoW Computation Time per Vehicle")
    plt.legend()
    plt.grid(True)
    plt.savefig("PoW Computation Time per Vehicle")
    plt.show()

    # -------- Energy --------
    plt.figure()
    for node, times in per_node.items():
        energy = [VOLTAGE * CURRENT * (t / 1000) for t in times]
        plt.plot(energy, label=node)

    plt.xlabel("Transaction Index")
    plt.ylabel("Energy Consumption (J)")
    plt.title("PoW Energy Consumption per Vehicle")
    plt.legend()
    plt.grid(True)
    plt.savefig("PoW Energy Consumption per Vehicle")
    plt.show()

