#!/usr/bin/env python3
"""
Datasheet-based energy model for the vehicle node
=================================================

No INA219 needed. Energy is computed as

    E = V x SUM_over_phases ( I_phase x t_phase )

where every t_phase is MEASURED on the device during the real experiment
and carried in the transaction (the RSU logs them), and every I_phase is
a published datasheet current for that chip. Because the datasheets give
ranges rather than single numbers, each transaction produces an
INTERVAL [E_low, E_high], not a point estimate. Report it that way.

Datasheet currents at 3.3 V, 25 C
---------------------------------
ESP32 (Espressif ESP32 Series Datasheet, "Current Consumption" tables):
  Wi-Fi Tx, 802.11b/g/n            180 - 240 mA  (modulation & Pout
                                                  dependent)
  Wi-Fi Rx / listening              95 - 100 mA
  Modem-sleep, CPU 240 MHz          30 -  68 mA
  Modem-sleep, CPU 160 MHz          27 -  44 mA
  Modem-sleep, CPU  80 MHz          20 -  31 mA

ESP8266 (ESP8266EX datasheet / module specs):
  Tx 802.11b CCK 1 Mbps, +19.5 dBm         215 mA
  Tx 802.11b CCK 11 Mbps, +17 dBm          170 mA
  Rx 802.11b/g, 1024-byte packet        50 - 60 mA
  Modem-sleep (CPU running, radio idle) 15 - 20 mA

These are the numbers this model uses. Two honesty notes for the paper:

1. A dev board is not a bare module. USB-serial bridges, regulators and
   LEDs on a NodeMCU/DevKit add roughly 10-30 mA that the chip datasheet
   does not include. Set `board_overhead_mA` to whatever your board adds,
   or state that the figure is chip-level only.
2. During PoW the CPU is busy while the radio stays associated. The low
   bound therefore uses modem-sleep current (radio idle between beacons)
   and the high bound uses Rx/listening current (radio awake). The truth
   sits between the two, which is exactly what the interval says.

Usage:
    from energy_model import ENERGY_PROFILES, energy_for_row
    lo, hi, parts = energy_for_row(row, ENERGY_PROFILES["esp32"])
"""

V_SUPPLY = 3.3

ENERGY_PROFILES = {
    "esp32": {
        "name": "ESP32 (WROOM-32, 3.3 V)",
        "source": "Espressif ESP32 Series Datasheet, current consumption "
                  "tables",
        "cpu_mA": {                      # modem-sleep, CPU running
            240: (30.0, 68.0),
            160: (27.0, 44.0),
            80:  (20.0, 31.0),
        },
        "rx_mA": (95.0, 100.0),          # Wi-Fi Rx / listening
        "tx_mA": (180.0, 240.0),         # Wi-Fi Tx
        "phy_mbps": 11.0,                # 802.11b CCK, the usual fallback
        "board_overhead_mA": 0.0,        # set for your dev board
    },
    "esp8266": {
        "name": "ESP8266EX (3.3 V)",
        "source": "ESP8266EX datasheet / ESP-12 module specification",
        "cpu_mA": {
            160: (15.0, 20.0),           # modem-sleep, CPU running
            80:  (15.0, 20.0),
        },
        "rx_mA": (50.0, 60.0),
        "tx_mA": (170.0, 215.0),
        "phy_mbps": 11.0,
        "board_overhead_mA": 0.0,
    },
}

# 802.11 overhead per frame: preamble + MAC/IP/TCP headers, approximated
# as a fixed 300 us plus the payload airtime. Airtime is a rounding error
# next to PoW, so this does not need to be exact - but state it.
FRAME_OVERHEAD_S = 300e-6


def _cpu_bounds(profile, cpu_mhz):
    table = profile["cpu_mA"]
    if cpu_mhz in table:
        return table[cpu_mhz]
    nearest = min(table, key=lambda f: abs(f - (cpu_mhz or 0)))
    return table[nearest]


def energy_for_row(row, profile, default_cpu_mhz=240):
    """
    row: one confirmed-transaction record with the device-side timings
         pow_time_ms, sign_time_ms, tip_wait_ms, msg_bytes (whatever is
         present; missing phases are simply skipped).
    returns (E_low_mJ, E_high_mJ, per-phase dict of (lo, hi) in mJ)
    """
    def num(key, default=0.0):
        try:
            v = float(row.get(key, default))
            return v if v == v else default          # NaN guard
        except (TypeError, ValueError):
            return default

    cpu_mhz = int(num("cpu_mhz", default_cpu_mhz) or default_cpu_mhz)
    cpu_lo, cpu_hi = _cpu_bounds(profile, cpu_mhz)
    rx_lo, rx_hi = profile["rx_mA"]
    tx_lo, tx_hi = profile["tx_mA"]
    over = profile.get("board_overhead_mA", 0.0)

    t_pow = num("pow_time_ms") / 1000.0
    t_sign = num("sign_time_ms") / 1000.0
    t_tip = num("tip_wait_ms") / 1000.0
    nbytes = num("msg_bytes")

    t_air = (FRAME_OVERHEAD_S + (nbytes * 8) / (profile["phy_mbps"] * 1e6)
             if nbytes else 0.0)

    parts = {}

    def add(label, seconds, i_lo, i_hi):
        if seconds <= 0:
            return
        parts[label] = (
            V_SUPPLY * (i_lo + over) / 1000.0 * seconds * 1000.0,   # mJ
            V_SUPPLY * (i_hi + over) / 1000.0 * seconds * 1000.0,
        )

    # PoW and signing: CPU busy, radio associated but not transmitting.
    # Low bound = modem-sleep current, high bound = Rx/listening current.
    add("proof-of-work", t_pow, cpu_lo, rx_hi)
    add("signature", t_sign, cpu_lo, rx_hi)
    # Waiting for the tip reply: radio receiving.
    add("tip round trip", t_tip, rx_lo, rx_hi)
    # Transmitting the transaction.
    add("transmit", t_air, tx_lo, tx_hi)

    lo = sum(p[0] for p in parts.values())
    hi = sum(p[1] for p in parts.values())
    return lo, hi, parts


def describe(profile):
    lines = [f"{profile['name']}  [{profile['source']}]",
             f"  supply           : {V_SUPPLY} V"]
    for f, (a, b) in sorted(profile["cpu_mA"].items(), reverse=True):
        lines.append(f"  CPU {f:>3} MHz      : {a:.0f} - {b:.0f} mA")
    lines += [
        f"  Wi-Fi Rx/listen  : {profile['rx_mA'][0]:.0f} - "
        f"{profile['rx_mA'][1]:.0f} mA",
        f"  Wi-Fi Tx         : {profile['tx_mA'][0]:.0f} - "
        f"{profile['tx_mA'][1]:.0f} mA",
        f"  board overhead   : {profile['board_overhead_mA']:.0f} mA",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    demo = {"pow_time_ms": 120, "sign_time_ms": 420, "tip_wait_ms": 35,
            "msg_bytes": 530, "cpu_mhz": 240}
    for key in ("esp32", "esp8266"):
        p = ENERGY_PROFILES[key]
        lo, hi, parts = energy_for_row(demo, p)
        print(describe(p))
        print(f"  example transaction: {lo:.2f} - {hi:.2f} mJ")
        for k, (a, b) in parts.items():
            print(f"     {k:<16}: {a:7.3f} - {b:7.3f} mJ")
        print()
