#!/usr/bin/env python3
"""
TinyDLT Vehicle Simulator
==========================

Generates valid signed vehicle transactions for the current rsu_server.py.

Current test topology:
    Vehicle Simulator -> RSU1 (10.20.141.118:1883)
                         |
                         +---- RSU4 (10.20.141.103:1883)

IMPORTANT:
- Run this simulator on RSU1 (or another host that can reach RSU1).
- rsu_server.py must already be running on RSU1 and RSU4.
- vehicle_keys.json must be in the same directory as rsu_server.py.
- This simulator uses the server's 12-bit PoW convention:
      SHA256(canonical_body_without_nonce + str(nonce))
- A transaction is NOT considered accepted merely because MQTT publish()
  succeeds. This version listens to the RSU1 confirmed topic and only uses
  confirmed transaction IDs as parents.

Example:
    python3 vehicle_simulator.py

Higher load:
    python3 vehicle_simulator.py --vehicles 5 --transactions 30 --interval 1
"""

import argparse
import threading
import hashlib
import json
import os
import random
import time
from pathlib import Path

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

RSU1_IP = "10.20.141.118"
RSU1_PORT = 1883

# Topics are built from --rsu-id at startup (default RSU1).
SUBMIT_TOPIC = "tangle/RSU1/submit_tx"
CONFIRMED_TOPIC = "tangle/RSU1/confirmed"
TIPS_REQUEST_TOPIC = "tangle/RSU1/request_tips"
TIPS_REPLY_PREFIX = "tangle/tips/"

KEY_FILE = "vehicle_keys.json"

PROTOCOL_VERSION = 1
POW_DIFFICULTY = 12


# ---------------------------------------------------------------------------
# Canonical JSON
# ---------------------------------------------------------------------------

def canonical_json(obj):
    """
    Must match the canonical JSON representation used by rsu_server.py.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# PoW
# ---------------------------------------------------------------------------

def valid_pow_digest(digest_hex, difficulty):
    """
    Check difficulty leading zero bits.
    """
    value = int(digest_hex, 16)
    return value < (1 << (256 - difficulty))


def calculate_pow(body_without_nonce, difficulty):
    """
    Calculate PoW exactly in the form expected by the current server.

    Server convention:
        digest = SHA256(canonical(body_without_nonce) + str(nonce))
    """
    base = dict(body_without_nonce)
    base.pop("nonce", None)

    preimage = canonical_json(base)

    nonce = 0
    start = time.perf_counter()

    while True:
        digest = hashlib.sha256(
            preimage + str(nonce).encode("utf-8")
        ).hexdigest()

        if valid_pow_digest(digest, difficulty):
            body = dict(base)
            body["nonce"] = nonce

            elapsed_ms = (
                time.perf_counter() - start
            ) * 1000.0

            return body, digest, elapsed_ms

        nonce += 1


# ---------------------------------------------------------------------------
# Vehicle key management
# ---------------------------------------------------------------------------

def load_or_create_vehicle_keys(vehicle_ids, key_file):
    """
    Create Ed25519 keys if necessary.

    vehicle_keys.json contains:
        {
            "VEHICLE1": "<64 hex character raw public key>",
            ...
        }

    This is the format expected by the current rsu_server.py.
    """
    key_path = Path(key_file)

    public_keys = {}

    if key_path.exists():
        try:
            loaded = json.loads(key_path.read_text())
            if isinstance(loaded, dict):
                public_keys.update(loaded)
        except Exception as exc:
            print(f"[KEYS] Warning: cannot read {key_file}: {exc}")

    private_keys = {}

    for vehicle_id in vehicle_ids:
        private_path = Path(
            f"{vehicle_id}_ed25519_private.pem"
        )

        # Reuse existing private key.
        if private_path.exists():
            try:
                private_key = serialization.load_pem_private_key(
                    private_path.read_bytes(),
                    password=None,
                )

                if not isinstance(private_key, Ed25519PrivateKey):
                    raise ValueError("private key is not Ed25519")

                private_keys[vehicle_id] = private_key

                raw_public = private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )

                public_keys[vehicle_id] = raw_public.hex()
                continue

            except Exception as exc:
                print(
                    f"[KEYS] Cannot reuse {private_path}: {exc}. "
                    "Generating a new key."
                )

        # Generate new Ed25519 key.
        private_key = Ed25519PrivateKey.generate()

        private_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

        raw_public = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        public_keys[vehicle_id] = raw_public.hex()
        private_keys[vehicle_id] = private_key

    key_path.write_text(
        json.dumps(public_keys, indent=4)
    )

    return private_keys, public_keys


# ---------------------------------------------------------------------------
# Transaction creation
# ---------------------------------------------------------------------------

def create_transaction(
    private_key,
    vehicle_id,
    sequence,
    approves,
    speed_kmh,
    difficulty,
):
    """
    Build, PoW, hash and sign one transaction.
    """

    # Do not use duplicate parents.
    clean_approves = []
    for parent in approves:
        if parent not in clean_approves:
            clean_approves.append(parent)

    body = {
        "version": PROTOCOL_VERSION,
        "creator": vehicle_id,
        "timestamp_ms": int(time.time() * 1000),
        "sequence": sequence,
        "data": {
            "speed_kmh": round(float(speed_kmh), 2),
            "event": "NORMAL_TRAFFIC",
        },
        "approves": clean_approves,
        "nonce": 0,
        "pow_difficulty": difficulty,
    }

    # Solve PoW.
    body, pow_digest, pow_time_ms = calculate_pow(
        body,
        difficulty,
    )

    # Transaction ID is the SHA-256 of the complete immutable body.
    txid = hashlib.sha256(
        canonical_json(body)
    ).hexdigest()

    # Signature covers the same immutable body.
    signature = private_key.sign(
        canonical_json(body)
    ).hex()

    transaction = dict(body)
    transaction["txid"] = txid
    transaction["signature"] = signature

    return transaction, pow_time_ms, pow_digest


# ---------------------------------------------------------------------------
# Simulator
# ---------------------------------------------------------------------------

class VehicleSimulator:

    def __init__(
        self,
        rsu_ip,
        rsu_port,
        vehicle_count,
        transaction_count,
        interval,
        difficulty,
        key_file,
        confirmation_timeout,
        flush_max=8,
        vehicle_prefix="VEHICLE",
    ):
        self.flush_max = flush_max
        self.rsu_ip = rsu_ip
        self.rsu_port = rsu_port
        self.vehicle_count = vehicle_count
        self.transaction_count = transaction_count
        self.interval = interval
        self.difficulty = difficulty
        self.key_file = key_file
        self.confirmation_timeout = confirmation_timeout

        self.vehicle_ids = [
            f"{vehicle_prefix}{i + 1}"
            for i in range(vehicle_count)
        ]

        # v4: each vehicle's speed is a random walk (realistic, and it
        # stays inside the RSU's acceleration plausibility limit).
        self.speed = {
            vehicle_id: random.uniform(40.0, 70.0)
            for vehicle_id in self.vehicle_ids
        }
        self.batch_txids = []

        self.private_keys = {}
        self.public_keys = {}

        # FIX: start sequences from the wall clock (ms) so a restarted
        # simulator always sends higher numbers than the previous run.
        # The RSU only requires "greater than last seen" and uniqueness.
        seq_base = int(time.time() * 1000)
        self.sequence = {
            vehicle_id: seq_base
            for vehicle_id in self.vehicle_ids
        }

        # Confirmed transaction IDs received from the RSU.
        self.confirmed_txids = []

        # FIX: tips are fetched from the RSU before every transaction.
        # Waiting for confirmed parents deadlocks, because a transaction
        # needs an approver (CW >= 2) before it can be confirmed.
        self.tip_replies = {}
        self.tip_events = {
            vehicle_id: threading.Event()
            for vehicle_id in self.vehicle_ids
        }

        # txid -> transaction sent by this simulator.
        self.sent_transactions = {}

        # txid -> timestamp when submitted.
        self.submit_times = {}

        self.client = None

    # -----------------------------------------------------------------------
    # MQTT callbacks
    # -----------------------------------------------------------------------

    def on_connect(self, client, userdata, flags, reason_code, properties):
        if reason_code == 0:
            print("[MQTT] Connected to RSU1.")

            client.subscribe(
                CONFIRMED_TOPIC,
                qos=1,
            )

            for vehicle_id in self.vehicle_ids:
                client.subscribe(
                    TIPS_REPLY_PREFIX + vehicle_id,
                    qos=1,
                )

            print(
                f"[MQTT] Subscribed to {CONFIRMED_TOPIC}"
            )

        else:
            print(
                f"[MQTT] Connection failed: {reason_code}"
            )

    def on_message(self, client, userdata, msg):
        try:
            payload = json.loads(
                msg.payload.decode("utf-8")
            )

        except Exception as exc:
            print(
                f"[MQTT] Invalid confirmation JSON: {exc}"
            )
            return

        if msg.topic.startswith(TIPS_REPLY_PREFIX):
            vehicle_id = msg.topic[len(TIPS_REPLY_PREFIX):]
            tips = payload.get("tips") or ["GENESIS"]
            self.tip_replies[vehicle_id] = list(tips)
            event = self.tip_events.get(vehicle_id)
            if event is not None:
                event.set()
            return

        # The server may publish either a transaction object or
        # an event object. Handle both without assuming acceptance.
        txid = payload.get("txid")

        if not txid:
            event = payload.get("event", {})
            if isinstance(event, dict):
                txid = event.get("txid")

        if not txid:
            return

        # Only add a transaction once.
        if txid not in self.confirmed_txids:
            self.confirmed_txids.append(txid)

        submitted_at = self.submit_times.get(txid)

        if submitted_at is not None:
            latency_ms = (
                time.perf_counter() - submitted_at
            ) * 1000.0

            print(
                f"[CONFIRMED] tx={txid[:16]}... "
                f"end_to_end={latency_ms:.2f} ms"
            )
        else:
            print(
                f"[CONFIRMED] tx={txid[:16]}..."
            )

    # -----------------------------------------------------------------------
    # Parent selection
    # -----------------------------------------------------------------------

    def request_tips(self, vehicle_id, timeout=3.0):
        """
        Ask the RSU for up to two current tips (Thompson Sampling on the
        server side). Falls back to GENESIS if the RSU does not answer.
        """
        event = self.tip_events[vehicle_id]
        event.clear()
        self.tip_replies.pop(vehicle_id, None)

        self.client.publish(
            TIPS_REQUEST_TOPIC,
            json.dumps({"client": vehicle_id}),
            qos=1,
        )

        if not event.wait(timeout):
            print("  [WARN] no tip reply from RSU; using GENESIS")
            return ["GENESIS"]

        return self.tip_replies.get(vehicle_id, ["GENESIS"])

    def choose_parents_confirmed_only(self):
        """
        Choose only transaction IDs that RSU1 has confirmed.

        This prevents the previous missing_parent problem.

        First transaction:
            [GENESIS]

        Second transaction onward:
            [latest_confirmed, previous_confirmed]
        """
        confirmed = self.confirmed_txids

        if not confirmed:
            return ["GENESIS"]

        if len(confirmed) == 1:
            return [confirmed[-1], "GENESIS"]

        # Two distinct real parents.
        return [
            confirmed[-1],
            confirmed[-2],
        ]

    # -----------------------------------------------------------------------
    # Submit
    # -----------------------------------------------------------------------

    def submit(self, transaction):
        payload = json.dumps(
            transaction,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

        info = self.client.publish(
            SUBMIT_TOPIC,
            payload,
            qos=1,
        )

        info.wait_for_publish()

        if info.rc != mqtt.MQTT_ERR_SUCCESS:
            return False

        txid = transaction["txid"]

        self.sent_transactions[txid] = transaction
        self.submit_times[txid] = time.perf_counter()

        return True

    # -----------------------------------------------------------------------
    # Run
    # -----------------------------------------------------------------------

    def send_one(self, label, vehicle_id):
        self.sequence[vehicle_id] += 1
        sequence = self.sequence[vehicle_id]

        approves = self.request_tips(vehicle_id)

        speed = min(
            110.0,
            max(10.0, self.speed[vehicle_id] + random.uniform(-4.0, 4.0)),
        )
        self.speed[vehicle_id] = speed

        transaction, pow_ms, pow_digest = create_transaction(
            self.private_keys[vehicle_id],
            vehicle_id,
            sequence,
            approves,
            speed,
            self.difficulty,
        )

        ok = self.submit(transaction)

        shown = [
            a if a == "GENESIS" else a[:12]
            for a in approves
        ]
        print()
        print(
            f"[{label}] vehicle={vehicle_id} "
            f"speed={speed:.1f} km/h PoW={pow_ms:.1f} ms"
        )
        print(f"  txid={transaction['txid'][:16]}...  approves={shown}")
        print(f"  MQTT SUBMITTED: {'SUCCESS' if ok else 'FAILED'}")

        return transaction["txid"] if ok else None

    def run(self):
        print("=" * 72)
        print(" TinyDLT VEHICLE SIMULATOR")
        print("=" * 72)
        print(f"RSU1              : {self.rsu_ip}:{self.rsu_port}")
        print(f"Vehicles          : {self.vehicle_count}")
        print(f"Transactions      : {self.transaction_count}")
        print(f"Interval          : {self.interval} s")
        print(f"PoW difficulty    : {self.difficulty} bits")
        print(f"Submit topic      : {SUBMIT_TOPIC}")
        print(f"Confirmed topic   : {CONFIRMED_TOPIC}")
        print("=" * 72)

        self.private_keys, self.public_keys = (
            load_or_create_vehicle_keys(
                self.vehicle_ids,
                self.key_file,
            )
        )

        print(
            f"\n[KEYS] Vehicle keys available in "
            f"{self.key_file}"
        )

        for vehicle_id in self.vehicle_ids:
            print(
                f"  {vehicle_id}: "
                f"{self.public_keys[vehicle_id]}"
            )

        self.client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"vehicle-sim-{os.getpid()}",
        )

        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message

        print(
            f"\n[MQTT] Connecting to "
            f"{self.rsu_ip}:{self.rsu_port}..."
        )

        self.client.connect(
            self.rsu_ip,
            self.rsu_port,
            keepalive=60,
        )

        self.client.loop_start()

        # Wait for MQTT connection.
        time.sleep(1.0)

        print("[SIM] Starting transaction generation.")

        try:
            for number in range(
                1,
                self.transaction_count + 1,
            ):
                vehicle_id = self.vehicle_ids[
                    (number - 1) % self.vehicle_count
                ]

                txid = self.send_one(
                    f"TX {number}/{self.transaction_count}",
                    vehicle_id,
                )

                if txid:
                    self.batch_txids.append(txid)

                time.sleep(self.interval)

            print("\n[SIM] Initial transaction batch finished.")

            # Give the RSUs time to process the last transaction.
            print(
                f"[SIM] Waiting {self.confirmation_timeout:.1f}s "
                "for confirmations..."
            )

            deadline = (
                time.time()
                + self.confirmation_timeout
            )

            # v4 FLUSH: a transaction is confirmed only after a later one
            # approves it. In a live road network traffic never stops;
            # in a finite test the last few would stay unapproved, so
            # send a few extra transactions until the batch is confirmed.
            flushed = 0
            flush_gap = max(self.interval, 1.0)

            while time.time() < deadline:

                waiting = [
                    t for t in self.batch_txids
                    if t not in self.confirmed_txids
                ]

                if not waiting:
                    print("[SIM] All batch transactions confirmed.")
                    break

                if flushed < self.flush_max:
                    flushed += 1
                    vehicle_id = self.vehicle_ids[
                        (self.transaction_count + flushed - 1)
                        % self.vehicle_count
                    ]
                    self.send_one(
                        f"FLUSH {flushed}/{self.flush_max} "
                        f"({len(waiting)} batch tx unconfirmed)",
                        vehicle_id,
                    )
                    time.sleep(flush_gap)
                else:
                    time.sleep(0.5)

        except KeyboardInterrupt:
            print("\n[SIM] Stopped by user.")

        finally:
            self.client.loop_stop()
            self.client.disconnect()

        batch_ok = sum(
            1 for t in self.batch_txids if t in self.confirmed_txids
        )
        extra = len(self.sent_transactions) - len(self.batch_txids)

        print("\n[SIM] Finished.")
        print(
            f"[SIM] Batch submitted: {len(self.batch_txids)}  "
            f"batch confirmed: {batch_ok}  "
            f"(+{extra} flush tx)"
        )
        print(
            f"[SIM] Submitted: {len(self.sent_transactions)}"
        )
        print(
            f"[SIM] Confirmed: {len(self.confirmed_txids)}"
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="TinyDLT signed vehicle simulator"
    )

    parser.add_argument(
        "--rsu-ip",
        default=RSU1_IP,
    )

    parser.add_argument(
        "--rsu-port",
        type=int,
        default=RSU1_PORT,
    )

    parser.add_argument(
        "--rsu-id",
        default="RSU1",
        help="RSU_ID of the RSU at --rsu-ip (sets the MQTT topics)",
    )

    parser.add_argument(
        "--vehicle-prefix",
        default="VEHICLE",
        help="vehicle ID prefix; use a different one per RSU so two "
             "simulators never claim the same vehicle identity",
    )

    parser.add_argument(
        "--vehicles",
        type=int,
        default=2,
        help="number of simulated vehicles",
    )

    parser.add_argument(
        "--transactions",
        type=int,
        default=6,
        help="number of transactions",
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=3.0,
        help="seconds between transactions",
    )

    parser.add_argument(
        "--pow",
        type=int,
        default=POW_DIFFICULTY,
        help="PoW difficulty in bits",
    )

    parser.add_argument(
        "--key-file",
        default=KEY_FILE,
    )

    parser.add_argument(
        "--flush-max",
        type=int,
        default=8,
        help="max extra transactions sent after the batch so the last "
             "batch transactions get approved (0 = off)",
    )

    parser.add_argument(
        "--confirmation-timeout",
        type=float,
        default=30.0,
        help="seconds to wait for confirmations after the batch",
    )

    args = parser.parse_args()

    if args.vehicles < 1:
        parser.error("--vehicles must be >= 1")

    if args.transactions < 1:
        parser.error("--transactions must be >= 1")

    if args.interval < 0:
        parser.error("--interval must be >= 0")

    if args.pow < 1 or args.pow > 30:
        parser.error("--pow must be between 1 and 30")

    global SUBMIT_TOPIC, CONFIRMED_TOPIC, TIPS_REQUEST_TOPIC
    SUBMIT_TOPIC = f"tangle/{args.rsu_id}/submit_tx"
    CONFIRMED_TOPIC = f"tangle/{args.rsu_id}/confirmed"
    TIPS_REQUEST_TOPIC = f"tangle/{args.rsu_id}/request_tips"

    simulator = VehicleSimulator(
        rsu_ip=args.rsu_ip,
        rsu_port=args.rsu_port,
        vehicle_count=args.vehicles,
        transaction_count=args.transactions,
        interval=args.interval,
        difficulty=args.pow,
        key_file=args.key_file,
        confirmation_timeout=args.confirmation_timeout,
        flush_max=args.flush_max,
        vehicle_prefix=args.vehicle_prefix,
    )

    simulator.run()


if __name__ == "__main__":
    main()

