#!/usr/bin/env python3
"""
TinyDLT Multi-RSU Server - 3-RSU experimental implementation

Each RSU:
  * maintains its own DAG replica and SQLite database
  * accepts vehicle transactions over its local MQTT broker
  * verifies vehicle Ed25519 signatures, SHA-256 PoW, timestamps, sequence numbers,
    rate limits and data plausibility
  * selects up to two current tips using Thompson Sampling
  * replicates transactions to the other RSUs using signed PREPARE messages
  * independently validates replicated transactions
  * returns signed VOTE messages
  * declares NETWORK_CONFIRMED only after 2-of-3 RSU quorum AND local CW threshold
  * broadcasts confirmed transactions only after quorum
  * periodically synchronizes missing transactions for crash recovery

IMPORTANT:
  This implementation provides 2-of-3 quorum for three RSUs. It is intended to
  tolerate one RSU being unavailable/crashed. It does NOT claim Byzantine fault
  tolerance with three RSUs.

Vehicle transaction immutable body:
  version, creator, timestamp_ms, sequence, data, approves, nonce, pow_difficulty

Vehicle signature is over the canonical immutable body.
txid = SHA-256(canonical immutable body)
origin_rsu is metadata added by the accepting RSU and is NOT part of txid/signature.
"""
import os
import json
import time
import sqlite3
import hashlib
import threading
import csv
import random
from collections import defaultdict, deque
from pathlib import Path

import paho.mqtt.client as mqtt
import networkx as nx
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# ============================= CONFIG =============================

RSU_ID = os.getenv("RSU_ID", "RSU1")
RSU_IP = os.getenv("RSU_IP", "127.0.0.1")
BROKER_HOST = os.getenv("BROKER_HOST", "127.0.0.1")
BROKER_PORT = int(os.getenv("BROKER_PORT", "1883"))

# Example:
# RSU1: RSU2=10.20.141.168:1883,RSU3=10.20.141.173:1883
# RSU2: RSU1=10.20.141.118:1883,RSU3=10.20.141.173:1883
# RSU3: RSU1=10.20.141.118:1883,RSU2=10.20.141.168:1883
PEERS = {}
for item in os.getenv("PEERS", "").split(","):
    item = item.strip()
    if not item or "=" not in item:
        continue
    pid, hp = item.split("=", 1)
    host, port = hp.rsplit(":", 1)
    PEERS[pid.strip()] = (host.strip(), int(port))

if not PEERS and os.getenv("RSU_COUNT", "3") != "1":
    print("=" * 72)
    print("[FATAL-ISH] PEERS is empty: this RSU will run alone.")
    print("  Nothing will ever be network-confirmed, and every HELLO,")
    print("  PREPARE or VOTE from another RSU will be ignored.")
    print("  You almost certainly did not load the .env file in THIS")
    print("  shell. Start the server like this:")
    print("      set -a; source ./rsu1.env; set +a")
    print("      echo \"$RSU_ID $PEERS\"   # must print the peer list")
    print("      python3 rsu_server.py")
    print("=" * 72)

RSU_COUNT = int(os.getenv("RSU_COUNT", "3"))
QUORUM = int(os.getenv("QUORUM", "2"))

if RSU_COUNT != 3 or QUORUM != 2:
    print("[WARNING] Recommended paper configuration is RSU_COUNT=3, QUORUM=2.")

GENESIS = "GENESIS"
PROTOCOL_VERSION = 1

POW_DIFFICULTY = int(os.getenv("POW_DIFFICULTY", "12"))
CW_THRESHOLD = int(os.getenv("CW_THRESHOLD", "2"))

TIMESTAMP_SKEW_S = float(os.getenv("TIMESTAMP_SKEW_S", "30"))
MAX_TX_PER_VEHICLE_WINDOW = int(os.getenv("MAX_TX_PER_VEHICLE_WINDOW", "20"))
RATE_WINDOW_S = float(os.getenv("RATE_WINDOW_S", "60"))

# Neutral starting trust. PoW alone does not increase trust.
TRUST_INITIAL = 0.50
TRUST_REWARD = float(os.getenv("TRUST_REWARD", "0.01"))
TRUST_PENALTY = float(os.getenv("TRUST_PENALTY", "0.10"))
TRUST_THRESHOLD = float(os.getenv("TRUST_THRESHOLD", "0.30"))

# Data plausibility parameters; adjust to the actual ITS experiment.
MAX_SPEED_KMH = float(os.getenv("MAX_SPEED_KMH", "160"))
MAX_ACCEL_KMH_S = float(os.getenv("MAX_ACCEL_KMH_S", "25"))

SYNC_INTERVAL_S = float(os.getenv("SYNC_INTERVAL_S", "20"))

# ---------------- Tip policy (DAG width) ----------------
# strict   : parent must be a current tip (sequential traffic -> chain)
# adaptive : keep the number of tips around TARGET_TIPS.
#            tips <  target -> "widen": approve a recent, under-approved
#                              non-tip, leaving current tips open
#            tips >= target -> "merge": approve the OLDEST tip (no
#                              starvation) + one Thompson-sampled tip
TIP_POLICY = os.getenv("TIP_POLICY", "adaptive").lower()
TARGET_TIPS = int(os.getenv("TARGET_TIPS", "3"))
TIP_WINDOW_S = float(os.getenv("TIP_WINDOW_S", "30"))
MAX_APPROVERS = int(os.getenv("MAX_APPROVERS", "2"))

# ---------------- Peer handshake ----------------
# ENROLL_PEERS=1: if a peer proves possession of a key that differs from
# (or is missing in) rsu_peer_keys.json, pin it and rewrite the file.
# Lab/bootstrap convenience only - turn it off for evaluation runs.
ENROLL_PEERS = os.getenv("ENROLL_PEERS", "0") == "1"
HELLO_RETRY_S = float(os.getenv("HELLO_RETRY_S", "5"))

# Bumped whenever the HELLO payload changes. A peer that sends a different
# value (or none) is running a different copy of this file.
PROTO_VERSION = 3

# v5: RSUs share the vehicle public-key registry over the HELLO handshake
# (public keys only). Prevents "unknown_vehicle_or_signature" when one RSU
# has an older vehicle_keys.json. Set 0 to require manual distribution.
VEHICLE_KEY_SYNC = os.getenv("VEHICLE_KEY_SYNC", "1") == "1"

# v5: validate a peer's transactions against that peer's clock, measured
# during the handshake, instead of assuming the machines are NTP-synced.
CLOCK_COMPENSATION = os.getenv("CLOCK_COMPENSATION", "1") == "1"
PREPARE_RETRY_S = float(os.getenv("PREPARE_RETRY_S", "5"))
PREPARE_MAX_RETRIES = int(os.getenv("PREPARE_MAX_RETRIES", "6"))

# Print every PREPARE/VOTE decision (set VERBOSE=0 for timing runs).
VERBOSE = os.getenv("VERBOSE", "1") != "0"
SYNC_BATCH_SIZE = int(os.getenv("SYNC_BATCH_SIZE", "500"))

DB_PATH = os.getenv("DB_PATH", f"tinyDLT_{RSU_ID}.db")
LOG_PATH = os.getenv("LOG_PATH", f"logs_{RSU_ID}.csv")
DAG_HTML = os.getenv("DAG_HTML", f"dag_{RSU_ID}.html")

KEY_DIR = Path(os.getenv("KEY_DIR", "."))
KEY_DIR.mkdir(parents=True, exist_ok=True)

RSU_KEY_PATH = KEY_DIR / f"{RSU_ID}_ed25519_private.pem"
PEER_KEYS_PATH = Path(os.getenv("PEER_KEYS_FILE", "rsu_peer_keys.json"))
VEHICLE_KEYS_PATH = Path(os.getenv("VEHICLE_KEYS_FILE", "vehicle_keys.json"))

# ---------------- Local vehicle-facing topics ----------------

TOPIC_TIPS = f"tangle/{RSU_ID}/request_tips"
TOPIC_SUBMIT = f"tangle/{RSU_ID}/submit_tx"
TOPIC_CONFIRMED = f"tangle/{RSU_ID}/confirmed"

# Compatibility topic for existing vehicle firmware.
TOPIC_GLOBAL_CONFIRMED = "tangle/confirmed"

# ---------------- RSU-to-RSU topics ----------------

TOPIC_PREPARE = "tangle/rsu/prepare"
TOPIC_VOTE = "tangle/rsu/vote"
TOPIC_COMMIT = "tangle/rsu/commit"
TOPIC_SYNC_REQUEST = "tangle/rsu/sync_request"
TOPIC_SYNC_RESPONSE = "tangle/rsu/sync_response"
TOPIC_HELLO = "tangle/rsu/hello"

# ============================= STATE ===============================

lock = threading.RLock()

# Edge direction: child/new transaction -> approved parent.
G = nx.DiGraph()
G.add_node(
    GENESIS,
    state="genesis",
    creator="SYSTEM",
    timestamp_ms=0
)

tx_store = {}
tx_quarantined = {}

# txid -> {RSU_ID: ACCEPT/REJECT}
tx_commit_votes = defaultdict(dict)

# txid -> {RSU_ID: signed VOTE message}
tx_vote_messages = defaultdict(dict)

published = set()

# Duplicate PREPARE suppression.
prepare_seen = set()

# Vehicle trust state.
trust_scores = defaultdict(lambda: TRUST_INITIAL)

# Local sequence tracking.
last_sequence = {}

# Recent transaction times for local rate limiting.
recent_tx_times = defaultdict(deque)

# History used by speed plausibility checks.
speed_history = defaultdict(deque)

# Thompson Sampling state per tip.
bandits = defaultdict(lambda: {"alpha": 1.0, "beta": 1.0})

# Peer connections.
peer_clients = {}
peer_public_keys = {}
vehicle_public_keys = {}

server_client = None
start_time = time.time()

# ============================= HELPERS =============================

def now_ms():
    return int(time.time() * 1000)


def canonical(obj):
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    )


def db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def log_event(txid, event, details=""):
    try:
        conn = db()
        conn.execute(
            "INSERT INTO events(time_ms,txid,event,details) VALUES(?,?,?,?)",
            (now_ms(), txid, event, str(details))
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        print(f"[{RSU_ID}] event log error: {exc}")


def csv_log(row):
    fields = [
        "elapsed_s",
        "rsu_id",
        "txid",
        "creator",
        "origin_rsu",
        "event",
        "state",
        "cw",
        "quorum_votes",
        "latency_ms",
        "pow_time_ms",
        "data_score",
        "trust_score",
        "details"
    ]

    path = Path(LOG_PATH)
    new = not path.exists()

    with path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)

        if new:
            writer.writeheader()

        writer.writerow({
            key: row.get(key, "")
            for key in fields
        })


# ============================= RSU CRYPTO ==========================

def load_or_create_rsu_key():
    if RSU_KEY_PATH.exists():
        return serialization.load_pem_private_key(
            RSU_KEY_PATH.read_bytes(),
            password=None
        )

    key = Ed25519PrivateKey.generate()

    RSU_KEY_PATH.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
    )

    print(f"[{RSU_ID}] Generated RSU key: {RSU_KEY_PATH}")

    return key


RSU_PRIVATE = load_or_create_rsu_key()
RSU_PUBLIC = RSU_PRIVATE.public_key()


def raw_public_hex(public_key):
    return public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    ).hex()


def rsu_public_hex():
    return raw_public_hex(RSU_PUBLIC)


def sign_rsu_text(text):
    return RSU_PRIVATE.sign(
        text.encode("utf-8")
    ).hex()


def signed_rsu_message(kind, payload):
    signed_payload = canonical({
        "kind": kind,
        "payload": payload,
        "sender_rsu": RSU_ID
    })

    return {
        "kind": kind,
        "sender_rsu": RSU_ID,
        "signed_payload": signed_payload,
        "signature": sign_rsu_text(signed_payload),
        "payload": payload
    }


def load_keys():
    global peer_public_keys
    global vehicle_public_keys

    if PEER_KEYS_PATH.exists():
        try:
            raw = json.loads(
                PEER_KEYS_PATH.read_text(
                    encoding="utf-8"
                )
            )

            for pid, keyhex in raw.items():

                if pid == RSU_ID:
                    continue

                peer_public_keys[pid] = (
                    Ed25519PublicKey.from_public_bytes(
                        bytes.fromhex(keyhex)
                    )
                )

        except Exception as exc:
            print(
                f"[{RSU_ID}] Peer key load error: {exc}"
            )

    else:
        print(
            f"[{RSU_ID}] WARNING: {PEER_KEYS_PATH} not found"
        )

    if VEHICLE_KEYS_PATH.exists():
        try:
            raw = json.loads(
                VEHICLE_KEYS_PATH.read_text(
                    encoding="utf-8"
                )
            )

            for vid, keyhex in raw.items():

                vehicle_public_keys[vid] = (
                    Ed25519PublicKey.from_public_bytes(
                        bytes.fromhex(keyhex)
                    )
                )

        except Exception as exc:
            print(
                f"[{RSU_ID}] Vehicle key load error: {exc}"
            )

    else:
        print(
            f"[{RSU_ID}] WARNING: {VEHICLE_KEYS_PATH} not found"
        )


_unknown_rsu_warned = set()
_bad_sig_warned = set()

# peer_id -> seconds that peer's clock is BEHIND ours (our_now - their_now)
peer_clock_offset = {}


def verify_rsu_message(msg):
    if not isinstance(msg, dict):
        return False

    sender = msg.get("sender_rsu")
    signature_hex = msg.get("signature")
    signed_payload = msg.get("signed_payload")

    if not sender or not signature_hex or not signed_payload:
        return False

    try:
        if sender == RSU_ID:
            public_key = RSU_PUBLIC
        else:
            public_key = peer_public_keys.get(sender)

        if public_key is None:
            # FIX: make the silent drop visible (printed once per sender).
            if sender not in _unknown_rsu_warned:
                _unknown_rsu_warned.add(sender)
                print(
                    f"[{RSU_ID}] WARNING: dropping {msg.get('kind')} from "
                    f"{sender}: no public key for it in {PEER_KEYS_PATH}"
                )
            return False

        expected = canonical({
            "kind": msg["kind"],
            "payload": msg["payload"],
            "sender_rsu": sender
        })

        if expected != signed_payload:
            return False

        try:
            public_key.verify(
                bytes.fromhex(signature_hex),
                signed_payload.encode("utf-8")
            )
        except InvalidSignature:
            # FIX: a key exists but does not match the sender's real key.
            if sender not in _bad_sig_warned:
                _bad_sig_warned.add(sender)
                print(
                    f"[{RSU_ID}] WARNING: bad signature on "
                    f"{msg.get('kind')} from {sender}: the key for "
                    f"{sender} in {PEER_KEYS_PATH} does not match that "
                    f"RSU's 'RSU pubkey' banner value"
                )
            return False

        return True

    except (
        InvalidSignature,
        ValueError,
        KeyError,
        TypeError
    ):
        return False


# ========================== VEHICLE TRANSACTION ====================

def immutable_body(tx):
    """
    Immutable vehicle transaction content.

    origin_rsu is deliberately excluded because it is RSU metadata.
    id is excluded because it is derived from this body.
    signature is excluded because it authenticates this body.
    """
    return {
        "version": int(
            tx.get("version", PROTOCOL_VERSION)
        ),
        "creator": str(tx["creator"]),
        "timestamp_ms": int(tx["timestamp_ms"]),
        "sequence": int(tx["sequence"]),
        "data": tx["data"],
        "approves": list(
            tx.get("approves", [])
        ),
        "nonce": int(tx["nonce"]),
        "pow_difficulty": int(
            tx.get(
                "pow_difficulty",
                POW_DIFFICULTY
            )
        )
    }


def transaction_id(tx):
    body = immutable_body(tx)

    return hashlib.sha256(
        canonical(body).encode("utf-8")
    ).hexdigest()


_vehicle_keys_mtime = [0.0]


def reload_vehicle_keys_if_changed(creator):
    try:
        mtime = VEHICLE_KEYS_PATH.stat().st_mtime
    except OSError:
        return None
    if mtime == _vehicle_keys_mtime[0]:
        return None
    _vehicle_keys_mtime[0] = mtime
    try:
        raw = json.loads(VEHICLE_KEYS_PATH.read_text(encoding="utf-8"))
        for vid, keyhex in raw.items():
            vehicle_public_keys[vid] = Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(keyhex)
            )
        print(f"[{RSU_ID}] reloaded {VEHICLE_KEYS_PATH} ({len(raw)} vehicles)")
    except Exception as exc:
        print(f"[{RSU_ID}] vehicle key reload error: {exc}")
    return vehicle_public_keys.get(creator)


def verify_vehicle_signature(tx):
    creator = tx.get("creator", "")
    signature_hex = tx.get("signature", "")

    public_key = vehicle_public_keys.get(
        creator
    )

    if public_key is None:
        # vehicle_keys.json may have gained this vehicle since startup
        public_key = reload_vehicle_keys_if_changed(creator)

    if public_key is None:
        return (
            False,
            "unknown_vehicle_or_signature"
        )

    if not signature_hex:
        return (
            False,
            "missing_vehicle_signature"
        )

    try:
        public_key.verify(
            bytes.fromhex(signature_hex),
            canonical(
                immutable_body(tx)
            ).encode("utf-8")
        )

        return True, "ok"

    except (
        InvalidSignature,
        ValueError,
        TypeError
    ):
        return False, "bad_vehicle_signature"


def pow_preimage(tx):
    body = immutable_body(tx)

    body.pop("nonce", None)

    return canonical(body)


def has_valid_pow(tx):
    try:
        difficulty = int(
            tx["pow_difficulty"]
        )

        if difficulty < 0 or difficulty > 256:
            return False

        digest = hashlib.sha256(
            (
                pow_preimage(tx)
                + str(int(tx["nonce"]))
            ).encode("utf-8")
        ).hexdigest()

        full_hex = difficulty // 4
        remainder = difficulty % 4

        if not digest.startswith(
            "0" * full_hex
        ):
            return False

        if remainder == 0:
            return True

        return (
            int(
                digest[full_hex],
                16
            )
            <
            (1 << (4 - remainder))
        )

    except Exception:
        return False


# ============================= DATABASE ============================

def init_db():
    conn = db()

    conn.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        txid TEXT PRIMARY KEY,
        creator TEXT NOT NULL,
        origin_rsu TEXT NOT NULL,
        timestamp_ms INTEGER NOT NULL,
        sequence INTEGER NOT NULL,
        data_json TEXT NOT NULL,
        approves_json TEXT NOT NULL,
        nonce INTEGER NOT NULL,
        pow_difficulty INTEGER NOT NULL,
        pow_time_ms REAL,
        signature TEXT,
        first_seen_ms INTEGER,
        local_accept_ms INTEGER,
        quorum_ms INTEGER,
        state TEXT,
        cumulative_weight INTEGER,
        data_score REAL,
        validation_reason TEXT
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS votes (
        txid TEXT,
        rsu_id TEXT,
        decision TEXT,
        reason TEXT,
        received_ms INTEGER,
        PRIMARY KEY(txid, rsu_id)
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS trust (
        time_ms INTEGER,
        vehicle_id TEXT,
        score REAL,
        reason TEXT
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS events (
        time_ms INTEGER,
        txid TEXT,
        event TEXT,
        details TEXT
    )
    """)

    conn.commit()
    conn.close()


def store_transaction(
    tx,
    state,
    data_score=0.0,
    reason="",
    local_accept_ms=None,
    quorum_ms=None
):
    conn = db()

    conn.execute("""
    INSERT OR REPLACE INTO transactions(
        txid,
        creator,
        origin_rsu,
        timestamp_ms,
        sequence,
        data_json,
        approves_json,
        nonce,
        pow_difficulty,
        pow_time_ms,
        signature,
        first_seen_ms,
        local_accept_ms,
        quorum_ms,
        state,
        cumulative_weight,
        data_score,
        validation_reason
    )
    VALUES(
        ?,?,?,?,?,?,?,?,?,?,
        ?,?,?,?,?,?,?,?
    )
    """, (
        tx["id"],
        tx["creator"],
        tx.get(
            "origin_rsu",
            RSU_ID
        ),
        int(tx["timestamp_ms"]),
        int(tx["sequence"]),
        json.dumps(
            tx["data"],
            sort_keys=True
        ),
        json.dumps(
            tx.get("approves", [])
        ),
        int(tx["nonce"]),
        int(tx["pow_difficulty"]),
        float(
            tx.get(
                "pow_time_ms",
                0.0
            )
        ),
        tx.get(
            "signature",
            ""
        ),
        int(
            tx.get(
                "_first_seen_ms",
                now_ms()
            )
        ),
        local_accept_ms,
        quorum_ms,
        state,
        cumulative_weight(
            tx["id"]
        ) if tx["id"] in G else 0,
        float(data_score),
        reason
    ))

    conn.commit()
    conn.close()


def store_vote(
    txid,
    rsu_id,
    decision,
    reason
):
    conn = db()

    conn.execute("""
    INSERT OR REPLACE INTO votes(
        txid,
        rsu_id,
        decision,
        reason,
        received_ms
    )
    VALUES(?,?,?,?,?)
    """, (
        txid,
        rsu_id,
        decision,
        reason,
        now_ms()
    ))

    conn.commit()
    conn.close()


# ========================== TRUST / DATA ===========================

def update_trust(
    vehicle_id,
    delta,
    reason
):
    with lock:

        old = float(
            trust_scores[
                vehicle_id
            ]
        )

        new = max(
            0.0,
            min(
                1.0,
                old + float(delta)
            )
        )

        trust_scores[
            vehicle_id
        ] = new

    conn = db()

    conn.execute(
        """
        INSERT INTO trust(
            time_ms,
            vehicle_id,
            score,
            reason
        )
        VALUES(?,?,?,?)
        """,
        (
            now_ms(),
            vehicle_id,
            new,
            reason
        )
    )

    conn.commit()
    conn.close()

    return new


def data_plausibility(tx):
    """
    Plausibility is not physical truth.

    Supported:
      {"speed_kmh": number, "event": "..."}
      {"speed": number, "event": "..."}
      optional latitude/longitude
      scalar string event
    """

    data = tx.get("data")
    creator = tx.get(
        "creator",
        ""
    )

    score = 1.0

    if isinstance(data, dict):

        speed = data.get(
            "speed_kmh",
            data.get("speed")
        )

        if speed is not None:

            try:
                speed = float(speed)

            except (
                ValueError,
                TypeError
            ):
                return (
                    0.0,
                    "invalid_speed"
                )

            if not (
                0.0
                <= speed
                <= MAX_SPEED_KMH
            ):
                return (
                    0.0,
                    "speed_out_of_range"
                )

            hist = speed_history[
                creator
            ]

            if hist:

                previous_speed, previous_ts = hist[-1]

                dt = max(
                    0.001,
                    (
                        int(tx["timestamp_ms"])
                        - previous_ts
                    ) / 1000.0
                )

                acceleration = (
                    abs(
                        speed
                        - previous_speed
                    )
                    / dt
                )

                if acceleration > MAX_ACCEL_KMH_S:
                    score *= 0.5

            hist.append(
                (
                    speed,
                    int(tx["timestamp_ms"])
                )
            )

            while (
                hist
                and
                int(tx["timestamp_ms"])
                - hist[0][1]
                > 60000
            ):
                hist.popleft()

        event = str(
            data.get(
                "event",
                ""
            )
        ).strip().lower()

        if (
            event
            and
            event not in {
                "clear",
                "accident",
                "congestion",
                "hazard",
                "normal"
            }
        ):
            score *= 0.5

        if (
            "latitude" in data
            and
            "longitude" in data
        ):
            try:
                latitude = float(
                    data["latitude"]
                )
                longitude = float(
                    data["longitude"]
                )

                if not (
                    -90 <= latitude <= 90
                    and
                    -180 <= longitude <= 180
                ):
                    return (
                        0.0,
                        "invalid_location"
                    )

            except (
                ValueError,
                TypeError
            ):
                return (
                    0.0,
                    "invalid_location"
                )

    elif isinstance(data, str):

        if not data.strip():
            return (
                0.0,
                "empty_event"
            )

    if score >= 0.8:
        return (
            score,
            "plausible"
        )

    return (
        score,
        "weak_plausibility"
    )


# ============================= DAG =================================

def add_genesis_if_needed():
    with lock:
        if GENESIS not in G:
            G.add_node(
                GENESIS,
                state="genesis",
                creator="SYSTEM",
                timestamp_ms=0
            )


def current_tips():
    with lock:
        return [
            node
            for node in G.nodes
            if (
                node != GENESIS
                and
                # Edges are child -> parent, so a tip is a node that
                # nobody approves yet: in_degree == 0 (FIX: was out_degree).
                G.in_degree(node) == 0
            )
        ]


def node_age_s(node):
    attrs = G.nodes[node]
    seen = attrs.get("seen_ms") or attrs.get("timestamp_ms") or 0
    return (now_ms() - int(seen)) / 1000.0


def width_candidates():
    """
    Recent non-tip transactions that still have room for another approver.
    Approving one of these adds weight to it without closing a current tip.
    """
    with lock:
        under = [
            n for n in G.nodes
            if n != GENESIS
            and 0 < G.in_degree(n) < MAX_APPROVERS
            and node_age_s(n) <= TIP_WINDOW_S
        ]
        if under:
            return under
        # Fallback: any recent non-tip, least-approved first.
        recent = [
            n for n in G.nodes
            if n != GENESIS
            and G.in_degree(n) > 0
            and node_age_s(n) <= TIP_WINDOW_S
        ]
        recent.sort(key=lambda n: G.in_degree(n))
        return recent[:3]


def valid_local_parents(parents):
    if not isinstance(
        parents,
        list
    ):
        return (
            False,
            "invalid_parent_type"
        )

    if len(parents) > 2:
        return (
            False,
            "too_many_parents"
        )

    if len(set(parents)) != len(parents):
        return (
            False,
            "duplicate_parents"
        )

    for parent in parents:

        if parent == GENESIS:
            continue

        if parent not in G:
            return (
                False,
                "missing_parent"
            )

        # FIX: a parent is still a tip if nothing approves it yet.
        if G.in_degree(parent) == 0:
            continue

        if TIP_POLICY == "strict":
            return (
                False,
                "parent_not_tip"
            )

        # adaptive: a recently seen non-tip is also acceptable. This is
        # what lets concurrent vehicles that were handed the same tip all
        # be accepted, which is where natural DAG width comes from.
        if node_age_s(parent) > TIP_WINDOW_S:
            return (
                False,
                "parent_too_old"
            )

    return True, "ok"


def valid_remote_parents(
    parents,
    txid
):
    if not isinstance(
        parents,
        list
    ):
        return (
            False,
            "invalid_parent_type"
        )

    if len(parents) > 2:
        return (
            False,
            "too_many_parents"
        )

    if len(set(parents)) != len(parents):
        return (
            False,
            "duplicate_parents"
        )

    for parent in parents:

        if parent == txid:
            return (
                False,
                "self_parent"
            )

        if (
            parent != GENESIS
            and
            parent not in G
        ):
            return (
                False,
                "missing_parent"
            )

    return True, "ok"


def thompson_select(
    candidates
):
    if not candidates:
        return []

    samples = []

    for tip in candidates:

        alpha = max(
            1e-9,
            bandits[tip]["alpha"]
        )

        beta = max(
            1e-9,
            bandits[tip]["beta"]
        )

        sample = random.betavariate(
            alpha,
            beta
        )

        samples.append(
            (
                sample,
                tip
            )
        )

    samples.sort(
        reverse=True
    )

    return [
        tip
        for _, tip
        in samples[:2]
    ]


def select_two_tips():
    tips = current_tips()

    if not tips:
        return [GENESIS]

    if TIP_POLICY == "strict":

        if len(tips) == 1:
            return [tips[0]]

        return thompson_select(
            tips
        )

    with lock:

        if len(tips) < TARGET_TIPS:
            # WIDEN: leave the current tips open, add weight elsewhere.
            candidates = width_candidates()

            if candidates:
                return thompson_select(candidates)

            return [GENESIS]

        # MERGE: the oldest tip is always taken (bounded waiting time),
        # the second parent is chosen by Thompson Sampling.
        # FIX: node_age_s grows with age, so the oldest tip is the max.
        # min() picked the newest tip and could starve old ones.
        oldest = max(tips, key=node_age_s)
        others = [t for t in tips if t != oldest]

        return [oldest] + thompson_select(others)[:1]


def update_bandit_rewards(
    parents
):
    with lock:

        for parent in parents:

            if parent != GENESIS:
                bandits[parent]["alpha"] += 1.0


def cumulative_weight(
    txid
):
    if (
        txid == GENESIS
        or
        txid not in G
    ):
        return 0

    # Edge direction is child -> parent.
    # Therefore nx.ancestors(txid) are descendants/approvers.
    return (
        1
        +
        len(
            nx.ancestors(
                G,
                txid
            )
        )
    )


def update_dag_states():
    with lock:

        for node in list(
            G.nodes
        ):

            if node == GENESIS:
                G.nodes[node][
                    "state"
                ] = "genesis"
                continue

            cw = cumulative_weight(
                node
            )

            if node in published:

                G.nodes[node][
                    "state"
                ] = "network_confirmed"

            elif G.in_degree(node) == 0:  # FIX: was out_degree

                G.nodes[node][
                    "state"
                ] = "tip"

            elif cw >= CW_THRESHOLD:

                G.nodes[node][
                    "state"
                ] = "locally_supported"

            else:

                G.nodes[node][
                    "state"
                ] = "approved"


# ============================= VALIDATION ==========================

def timestamp_valid(tx, origin_rsu=None):
    try:

        timestamp = (
            int(
                tx["timestamp_ms"]
            )
            / 1000.0
        )

        # v5: a transaction carries the clock of the RSU that accepted it
        # first. If that peer's clock differs from ours, correct for the
        # offset measured during the handshake instead of rejecting every
        # remote transaction as timestamp_invalid.
        offset = 0.0

        if (
            CLOCK_COMPENSATION
            and origin_rsu
            and origin_rsu != RSU_ID
        ):
            offset = peer_clock_offset.get(origin_rsu, 0.0)

        return (
            abs(
                time.time()
                - offset
                - timestamp
            )
            <= TIMESTAMP_SKEW_S
        )

    except Exception:
        return False


def sequence_valid(
    tx,
    remote=False
):
    creator = tx["creator"]

    try:
        sequence = int(
            tx["sequence"]
        )

    except Exception:
        return False

    if remote:

        # Peer/recovery messages can arrive out of order.
        # A sequence number must nevertheless be unique for a vehicle.
        conn = db()

        row = conn.execute(
            """
            SELECT 1
            FROM transactions
            WHERE creator=?
              AND sequence=?
            LIMIT 1
            """,
            (
                creator,
                sequence
            )
        ).fetchone()

        conn.close()

        return row is None

    return (
        sequence
        >
        int(
            last_sequence.get(
                creator,
                -1
            )
        )
    )


def rate_valid(tx):
    creator = tx["creator"]
    now = time.time()

    queue = recent_tx_times[
        creator
    ]

    while (
        queue
        and
        now - queue[0]
        > RATE_WINDOW_S
    ):
        queue.popleft()

    if (
        len(queue)
        >= MAX_TX_PER_VEHICLE_WINDOW
    ):
        return False

    queue.append(now)

    return True


def validate_transaction(
    tx,
    remote=False,
    require_local_tips=True
):
    required = [
        "creator",
        "timestamp_ms",
        "sequence",
        "data",
        "approves",
        "nonce",
        "pow_difficulty",
        "signature"
    ]

    for key in required:

        if key not in tx:
            return (
                False,
                0.0,
                f"missing_{key}"
            )

    try:

        expected_id = transaction_id(
            tx
        )

    except Exception:
        return (
            False,
            0.0,
            "malformed_transaction"
        )

    if tx.get("id") != expected_id:
        return (
            False,
            0.0,
            "txid_mismatch"
        )

    if tx["id"] in tx_store:
        return (
            False,
            0.0,
            "duplicate_txid"
        )

    signature_ok, signature_reason = (
        verify_vehicle_signature(tx)
    )

    if not signature_ok:
        return (
            False,
            0.0,
            signature_reason
        )

    if not timestamp_valid(
        tx,
        origin_rsu=tx.get("origin_rsu") if remote else None
    ):
        return (
            False,
            0.0,
            "timestamp_invalid"
        )

    if not sequence_valid(
        tx,
        remote=remote
    ):
        return (
            False,
            0.0,
            "replay_sequence"
        )

    if (
        not remote
        and
        not rate_valid(tx)
    ):
        return (
            False,
            0.0,
            "rate_limit"
        )

    if int(
        tx["pow_difficulty"]
    ) != POW_DIFFICULTY:
        return (
            False,
            0.0,
            "unexpected_pow_difficulty"
        )

    if not has_valid_pow(tx):
        return (
            False,
            0.0,
            "invalid_pow"
        )

    if require_local_tips:

        parents_ok, parent_reason = (
            valid_local_parents(
                tx["approves"]
            )
        )

    else:

        parents_ok, parent_reason = (
            valid_remote_parents(
                tx["approves"],
                tx["id"]
            )
        )

    if not parents_ok:
        return (
            False,
            0.0,
            parent_reason
        )

    score, data_reason = (
        data_plausibility(tx)
    )

    if score < 0.5:
        return (
            False,
            score,
            data_reason
        )

    return (
        True,
        score,
        "valid"
    )


# ============================= PEER NETWORK ========================

def connect_peer(
    peer_id,
    host,
    port
):
    if peer_id == RSU_ID:
        return

    if peer_id in peer_clients:
        return

    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=(
            f"{RSU_ID}_to_{peer_id}"
        )
    )

    def on_connect(
        c,
        userdata,
        flags,
        reason_code,
        properties=None
    ):
        print(
            f"[{RSU_ID}] "
            f"peer {peer_id} connected: "
            f"{reason_code}"
        )

        if not reason_code.is_failure:
            # re-arm the handshake after every (re)connect
            peer_handshake[peer_id]["out"] = False
            peer_handshake[peer_id]["last_sent"] = 0.0

    def on_disconnect(
        c,
        userdata,
        disconnect_flags,
        reason_code,
        properties=None
    ):
        print(
            f"[{RSU_ID}] "
            f"peer {peer_id} disconnected: "
            f"{reason_code}"
        )

    client.on_connect = on_connect
    client.on_disconnect = on_disconnect

    # FIX: connect_async + loop_start keeps retrying if the peer broker
    # is not reachable yet (the old code gave up after one attempt and
    # then silently never sent PREPARE/VOTE to that peer).
    client.reconnect_delay_set(
        min_delay=1,
        max_delay=10
    )

    try:

        client.connect_async(
            host,
            port,
            60
        )

        client.loop_start()

    except Exception as exc:

        print(
            f"[{RSU_ID}] "
            f"peer {peer_id} "
            f"connection setup failed: {exc}"
        )

    peer_clients[
        peer_id
    ] = client


_peer_fail_printed = {}

# peer_id -> {"out": bool (peer answered us), "in": bool (peer reached us),
#             "last_sent": float}
peer_handshake = defaultdict(
    lambda: {"out": False, "in": False, "last_sent": 0.0}
)

# txid -> (attempts, last_sent_time)
prepare_retries = {}


def vehicle_key_map():
    """Public keys only - safe to share with peer RSUs."""
    return {
        vid: raw_public_hex(key)
        for vid, key in sorted(vehicle_public_keys.items())
    }


def merge_vehicle_keys(sender, announced):
    """
    Adopt vehicle public keys a peer knows and we do not. Conflicting
    keys for the same vehicle are never overwritten - that is a real
    disagreement and is reported instead.
    """
    if not VEHICLE_KEY_SYNC or not isinstance(announced, dict):
        return

    learned = []
    conflicts = []

    with lock:
        for vid, keyhex in announced.items():
            try:
                key = Ed25519PublicKey.from_public_bytes(
                    bytes.fromhex(keyhex)
                )
            except Exception:
                continue

            known = vehicle_public_keys.get(vid)

            if known is None:
                vehicle_public_keys[vid] = key
                learned.append(vid)

            elif raw_public_hex(known) != keyhex:
                conflicts.append(vid)

        if learned:
            current = vehicle_key_map()
            tmp = VEHICLE_KEYS_PATH.with_suffix(".tmp")
            tmp.write_text(
                json.dumps(current, indent=4, sort_keys=True),
                encoding="utf-8"
            )
            tmp.replace(VEHICLE_KEYS_PATH)
            try:
                _vehicle_keys_mtime[0] = VEHICLE_KEYS_PATH.stat().st_mtime
            except OSError:
                pass

    if learned:
        print(
            f"[{RSU_ID}] vehicle registry: learned "
            f"{', '.join(sorted(learned))} from {sender} "
            f"(written to {VEHICLE_KEYS_PATH})"
        )

    if conflicts:
        print(
            f"[{RSU_ID}] WARNING: {sender} announces DIFFERENT keys for "
            f"{', '.join(sorted(conflicts))}. Kept mine; those vehicles "
            f"will be rejected by one of us. Delete the stale "
            f"VEHICLE*_ed25519_private.pem / vehicle_keys.json and "
            f"redistribute one registry."
        )


def vehicle_keys_digest():
    try:
        raw = json.loads(VEHICLE_KEYS_PATH.read_text(encoding="utf-8"))
        return hashlib.sha256(canonical(raw).encode("utf-8")).hexdigest()[:16]
    except Exception:
        return "missing"


def server_digest():
    """sha256 of this source file: two RSUs must run the same build."""
    try:
        return hashlib.sha256(
            Path(__file__).read_bytes()
        ).hexdigest()[:12]
    except Exception:
        return "unknown"


def hello_payload(reply):
    return {
        "proto": PROTO_VERSION,
        "server_sha": server_digest(),
        "pubkey": rsu_public_hex(),
        "ts_ms": now_ms(),
        "reply": reply,
        "config": {
            "POW_DIFFICULTY": POW_DIFFICULTY,
            "CW_THRESHOLD": CW_THRESHOLD,
            "QUORUM": QUORUM,
            "RSU_COUNT": RSU_COUNT,
            "TIP_POLICY": TIP_POLICY,
            "TIMESTAMP_SKEW_S": TIMESTAMP_SKEW_S,
        },
        "vehicle_keys": vehicle_keys_digest(),
        "vehicle_map": (
            vehicle_key_map() if VEHICLE_KEY_SYNC else {}
        ),
        "peers": sorted(PEERS),
    }


_id_collision_warned = [0.0]


def warn_id_collision(kind):
    """
    Someone else on this network signs messages as us. Almost always a
    second rsu_server.py started without sourcing its .env (RSU_ID then
    defaults to RSU1), or a copied folder that still holds another RSU's
    private key.
    """
    now = time.time()
    if now - _id_collision_warned[0] < 30:
        return
    _id_collision_warned[0] = now
    print(
        f"[{RSU_ID}] *** ID COLLISION: received a {kind} signed as "
        f"{RSU_ID}, but that is us. Another process is running with "
        f"RSU_ID={RSU_ID} and the same private key. Stop it: "
        f"pgrep -af rsu_server.py  on every machine, keep exactly one "
        f"per RSU, and always start it with "
        f"'set -a; source ./rsuX.env; set +a'. ***"
    )


_hello_warned = set()


def _reply_to_hello(sender, payload):
    """Answer a peer's HELLO so its own handshake can complete."""
    state = peer_handshake[sender]
    state["in"] = True
    if payload.get("reply"):
        state["out"] = True
        resend_pending_prepares(sender)
    else:
        send_hello(sender, reply=True)


def send_hello(peer_id, reply=False):
    message = signed_rsu_message("HELLO", hello_payload(reply))
    peer_handshake[peer_id]["last_sent"] = time.time()
    return publish_peer(peer_id, TOPIC_HELLO, message)


def pin_peer_key(peer_id, keyhex):
    with lock:
        peer_public_keys[peer_id] = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(keyhex)
        )
        try:
            current = json.loads(PEER_KEYS_PATH.read_text(encoding="utf-8"))
        except Exception:
            current = {}
        current[peer_id] = keyhex
        current[RSU_ID] = rsu_public_hex()
        tmp = PEER_KEYS_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(current, indent=4, sort_keys=True))
        tmp.replace(PEER_KEYS_PATH)
    _bad_sig_warned.discard(peer_id)
    _unknown_rsu_warned.discard(peer_id)


_hello_fail_printed = set()


def process_hello(msg):
    """
    Startup handshake. Checks, per peer and per direction:
      * the peer really holds the key it announces (signature check)
      * that key equals the pinned key in rsu_peer_keys.json
      * clock offset, protocol config and vehicle key set agree
      * the peer can publish to OUR broker (votes travel that way)
    """
    if not isinstance(msg, dict) or msg.get("kind") != "HELLO":
        return

    sender = msg.get("sender_rsu")
    payload = msg.get("payload") or {}

    if not sender:
        return

    if sender == RSU_ID:
        warn_id_collision("HELLO")
        return

    if sender not in PEERS:
        print(
            f"[{RSU_ID}] HELLO from {sender} ignored: not in PEERS "
            f"({list(PEERS)}). Add {sender}=<ip>:1883 to PEERS."
        )
        return

    announced = str(payload.get("pubkey", ""))

    # 1. proof of possession of the announced key
    try:
        expected = canonical({
            "kind": "HELLO", "payload": payload, "sender_rsu": sender
        })
        if expected != msg.get("signed_payload"):
            raise ValueError("payload mismatch")
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(announced)).verify(
            bytes.fromhex(msg.get("signature", "")),
            expected.encode("utf-8"),
        )
    except Exception as exc:
        print(f"[{RSU_ID}] HELLO from {sender} has an invalid signature ({exc})")
        return

    # 2. compare with the pinned key
    pinned = peer_public_keys.get(sender)
    pinned_hex = raw_public_hex(pinned) if pinned is not None else None

    if pinned_hex != announced:
        problem = (
            "is MISSING from" if pinned_hex is None
            else f"is WRONG in (file has {pinned_hex[:12]}..., peer uses "
                 f"{announced[:12]}...)"
        )
        if ENROLL_PEERS:
            pin_peer_key(sender, announced)
            print(
                f"[{RSU_ID}] HANDSHAKE: key for {sender} {problem} "
                f"{PEER_KEYS_PATH} -> ENROLLED {announced[:12]}... "
                f"(file updated)"
            )
        else:
            if (sender, announced) in _hello_fail_printed:
                return
            _hello_fail_printed.add((sender, announced))
            print(
                f"[{RSU_ID}] HANDSHAKE FAILED: key for {sender} {problem} "
                f"{PEER_KEYS_PATH}. Every {sender} vote will be dropped.\n"
                f"          Fix: put  \"{sender}\": \"{announced}\"  in "
                f"{PEER_KEYS_PATH} on every RSU, or restart with "
                f"ENROLL_PEERS=1"
            )
            return

    # 3. same build?
    their_proto = payload.get("proto")
    if their_proto != PROTO_VERSION:
        if ("proto", sender) not in _hello_warned:
            _hello_warned.add(("proto", sender))
            print(
                f"[{RSU_ID}] HANDSHAKE FAILED: {sender} runs a DIFFERENT "
                f"rsu_server.py (its HELLO protocol is "
                f"{their_proto if their_proto is not None else 'absent'}, "
                f"mine is {PROTO_VERSION}). Copy this exact file to "
                f"{sender}, delete its tinyDLT_*.db*, and restart it. "
                f"The checks below are skipped until then."
            )
        _reply_to_hello(sender, payload)
        return

    if payload.get("server_sha") != server_digest():
        if ("sha", sender) not in _hello_warned:
            _hello_warned.add(("sha", sender))
            print(
                f"[{RSU_ID}] HANDSHAKE WARNING: {sender} runs a different "
                f"build of rsu_server.py ({payload.get('server_sha')} vs "
                f"mine {server_digest()}). Same protocol, but the two "
                f"nodes may behave differently."
            )

    # 4. environment checks (printed once per distinct problem)
    offset_s = (now_ms() - int(payload.get("ts_ms", 0))) / 1000.0
    peer_clock_offset[sender] = offset_s

    if abs(offset_s) > TIMESTAMP_SKEW_S / 2 and (
        ("clock", sender) not in _hello_warned
    ):
        _hello_warned.add(("clock", sender))
        print(
            f"[{RSU_ID}] HANDSHAKE WARNING: {sender}'s clock is "
            f"{offset_s:+.1f}s off mine (limit {TIMESTAMP_SKEW_S}s). "
            + (
                "Compensating for it, but fix the clocks: "
                if CLOCK_COMPENSATION else
                "Remote transactions will be rejected as "
                "timestamp_invalid. Fix the clocks: "
            )
            + "sudo timedatectl set-ntp true  (on both machines)"
        )

    merge_vehicle_keys(sender, payload.get("vehicle_map"))

    theirs = payload.get("config", {})
    mine = hello_payload(False)["config"]
    diffs = {
        k: (mine[k], theirs.get(k))
        for k in mine if mine[k] != theirs.get(k)
    }
    if diffs and ("config", sender, str(diffs)) not in _hello_warned:
        _hello_warned.add(("config", sender, str(diffs)))
        print(
            f"[{RSU_ID}] HANDSHAKE WARNING: config differs from {sender} "
            f"(mine, theirs): {diffs}"
        )

    if payload.get("vehicle_keys") != vehicle_keys_digest() and (
        ("vk", sender, payload.get("vehicle_keys")) not in _hello_warned
    ):
        _hello_warned.add(("vk", sender, payload.get("vehicle_keys")))
        theirs_ids = set(payload.get("vehicle_map") or {})
        mine_ids = set(vehicle_public_keys)
        print(
            f"[{RSU_ID}] HANDSHAKE WARNING: vehicle registries differ from "
            f"{sender}. Known only to me: "
            f"{sorted(mine_ids - theirs_ids) or '-'}; only to {sender}: "
            f"{sorted(theirs_ids - mine_ids) or '-'}. Transactions from a "
            f"vehicle the other side does not know are rejected as "
            f"unknown_vehicle_or_signature."
        )

    if RSU_ID not in payload.get("peers", []) and (
        ("peers", sender) not in _hello_warned
    ):
        _hello_warned.add(("peers", sender))
        print(
            f"[{RSU_ID}] HANDSHAKE WARNING: {sender} does not list {RSU_ID} "
            f"in its PEERS, so it will ignore our messages."
        )

    state = peer_handshake[sender]
    first_in = not state["in"]
    state["in"] = True

    if payload.get("reply"):
        was_up = state["out"]
        state["out"] = True

        if not was_up:
            print(
                f"[{RSU_ID}] HANDSHAKE OK with {sender}: keys match, both "
                f"brokers reachable (clock offset {offset_s:+.2f}s)"
            )

        resend_pending_prepares(sender)
    else:
        if not send_hello(sender, reply=True):
            print(
                f"[{RSU_ID}] HANDSHAKE: got {sender}'s HELLO but cannot "
                f"answer - {RSU_ID} cannot reach {sender}'s broker"
            )
        elif first_in and VERBOSE:
            print(f"[{RSU_ID}] HELLO from {sender} verified, replied")


def hello_loop():
    """Keep saying HELLO until each peer has answered."""
    warned = set()
    while True:
        time.sleep(1)
        for peer_id in PEERS:
            state = peer_handshake[peer_id]
            if state["out"]:
                continue
            if time.time() - state["last_sent"] < HELLO_RETRY_S:
                continue
            client = peer_clients.get(peer_id)
            if client is None or not client.is_connected():
                continue
            if state["last_sent"] and peer_id not in warned:
                warned.add(peer_id)
                print(
                    f"[{RSU_ID}] HANDSHAKE PENDING with {peer_id}: no reply "
                    f"yet. Either {peer_id} is not running this server "
                    f"version, rejects our key (see its terminal), or "
                    f"cannot reach {RSU_ID}'s broker at {RSU_IP}:"
                    f"{BROKER_PORT} (votes would be lost). Retrying..."
                )
            send_hello(peer_id)


_retry_printed = [0.0]


def resend_pending_prepares(peer_id=None, force=False):
    """
    Re-send PREPARE for local transactions that are still missing a peer
    vote. A peer that already stored the transaction just re-sends its
    vote; this recovers votes lost to key mismatches or broker outages.
    """
    now = time.time()
    with lock:
        pending = []
        for txid, tx in tx_store.items():
            if txid in published:
                continue
            if tx.get("origin_rsu") != RSU_ID:
                continue
            votes = tx_commit_votes.get(txid, {})
            missing = [
                p for p in PEERS
                if p not in votes and (peer_id is None or p == peer_id)
            ]
            if not missing:
                continue
            attempts, last = prepare_retries.get(txid, (0, 0.0))
            if not force and (
                attempts >= PREPARE_MAX_RETRIES
                or now - last < PREPARE_RETRY_S
            ):
                continue
            prepare_retries[txid] = (attempts + 1, now)
            pending.append(dict(tx))

    for tx in pending:
        replicate_prepare(tx)

    now_print = time.time()

    if pending and VERBOSE and now_print - _retry_printed[0] > 30:
        _retry_printed[0] = now_print
        print(
            f"[{RSU_ID}] re-sent PREPARE for {len(pending)} tx still "
            f"waiting for votes"
        )


def publish_peer(
    peer_id,
    topic,
    payload
):
    client = peer_clients.get(
        peer_id
    )

    if client is None or not client.is_connected():
        now = time.time()
        if now - _peer_fail_printed.get(peer_id, 0) > 10:
            _peer_fail_printed[peer_id] = now
            print(
                f"[{RSU_ID}] WARNING: cannot send {topic} to "
                f"{peer_id}: not connected to its broker "
                f"{PEERS.get(peer_id)}"
            )
        return False

    try:

        result = client.publish(
            topic,
            json.dumps(payload),
            qos=1
        )

        return (
            result.rc
            ==
            mqtt.MQTT_ERR_SUCCESS
        )

    except Exception as exc:

        print(
            f"[{RSU_ID}] "
            f"publish to {peer_id} "
            f"failed: {exc}"
        )

        return False


def build_dependency_bundle(
    tx,
    limit=200
):
    bundle = {}

    queue = list(
        tx.get(
            "approves",
            []
        )
    )

    while (
        queue
        and
        len(bundle) < limit
    ):

        tid = queue.pop(0)

        if (
            tid == GENESIS
            or
            tid in bundle
        ):
            continue

        parent = tx_store.get(
            tid
        )

        if parent is None:
            continue

        bundle[tid] = parent

        queue.extend(
            parent.get(
                "approves",
                []
            )
        )

    return list(
        bundle.values()
    )


def replicate_prepare(tx):
    # first transmission counts as attempt 0 for the retry timer
    prepare_retries.setdefault(tx["id"], (0, time.time()))

    payload = {
        "tx": tx,
        "dependencies":
            build_dependency_bundle(tx)
    }

    message = signed_rsu_message(
        "PREPARE",
        payload
    )

    for peer_id in PEERS:
        publish_peer(
            peer_id,
            TOPIC_PREPARE,
            message
        )


def send_vote(
    origin_rsu,
    txid,
    decision,
    reason
):
    message = signed_rsu_message(
        "VOTE",
        {
            "txid": txid,
            "decision": decision,
            "reason": reason
        }
    )

    if origin_rsu == RSU_ID:

        handle_vote(
            message
        )

    else:

        sent = publish_peer(
            origin_rsu,
            TOPIC_VOTE,
            message
        )

        if VERBOSE:
            print(
                f"[{RSU_ID}] VOTE -> {origin_rsu} "
                f"tx={str(txid)[:12]} {decision} ({reason}) "
                f"{'sent' if sent else 'NOT SENT'}"
            )


def broadcast_commit(
    txid,
    tx,
    votes
):
    message = signed_rsu_message(
        "COMMIT",
        {
            "txid": txid,
            "tx": tx,
            "votes": votes
        }
    )

    for peer_id in PEERS:

        publish_peer(
            peer_id,
            TOPIC_COMMIT,
            message
        )


def send_sync_request(
    peer_id
):
    with lock:
        known = sorted(
            tx_store.keys()
        )

    message = signed_rsu_message(
        "SYNC_REQUEST",
        {
            "requester": RSU_ID,
            "known_txids": known
        }
    )

    publish_peer(
        peer_id,
        TOPIC_SYNC_REQUEST,
        message
    )


# ============================= DAG INSERT ==========================

def local_accept(
    tx,
    data_score,
    reason,
    state="LOCAL_ACCEPTED"
):
    tx = dict(tx)

    txid = tx["id"]
    accept_ms = now_ms()

    with lock:

        if txid in tx_store:
            return False

        # Never fabricate a missing parent.
        for parent in tx.get(
            "approves",
            []
        ):

            if (
                parent != GENESIS
                and
                parent not in G
            ):
                return False

        tx_store[txid] = tx

        last_sequence[
            tx["creator"]
        ] = max(
            int(
                last_sequence.get(
                    tx["creator"],
                    -1
                )
            ),
            int(
                tx["sequence"]
            )
        )

        G.add_node(
            txid,
            creator=tx["creator"],
            timestamp_ms=int(
                tx["timestamp_ms"]
            ),
            data=tx["data"],
            seen_ms=now_ms(),
            state="locally_accepted",
            origin_rsu=tx.get(
                "origin_rsu",
                RSU_ID
            )
        )

        for parent in tx.get(
            "approves",
            []
        ):
            G.add_edge(
                txid,
                parent
            )

        update_bandit_rewards(
            tx.get(
                "approves",
                []
            )
        )

        update_dag_states()

        # This is the local RSU's signed vote.
        self_vote = signed_rsu_message(
            "VOTE",
            {
                "txid": txid,
                "decision": "ACCEPT",
                "reason": reason
            }
        )

        tx_commit_votes[
            txid
        ][RSU_ID] = "ACCEPT"

        tx_vote_messages[
            txid
        ][RSU_ID] = self_vote

    store_transaction(
        tx,
        state,
        data_score,
        reason,
        local_accept_ms=accept_ms
    )

    store_vote(
        txid,
        RSU_ID,
        "ACCEPT",
        reason
    )

    # Trust reward is tied to valid protocol + strong plausibility,
    # not to PoW alone.
    if data_score >= 0.8:

        update_trust(
            tx["creator"],
            TRUST_REWARD,
            "valid_protocol_and_plausible_data"
        )

    log_event(
        txid,
        "LOCAL_ACCEPT",
        reason
    )

    csv_log({
        "elapsed_s":
            time.time() - start_time,
        "rsu_id":
            RSU_ID,
        "txid":
            txid,
        "creator":
            tx["creator"],
        "origin_rsu":
            tx.get(
                "origin_rsu",
                RSU_ID
            ),
        "event":
            "LOCAL_ACCEPT",
        "state":
            state,
        "cw":
            cumulative_weight(txid),
        "quorum_votes":
            1,
        "latency_ms":
            "",
        "pow_time_ms":
            tx.get(
                "pow_time_ms",
                0
            ),
        "data_score":
            data_score,
        "trust_score":
            trust_scores[
                tx["creator"]
            ],
        "details":
            reason
    })

    return True


# ============================= QUORUM ==============================

def maybe_quorum(txid):
    with lock:

        tx = tx_store.get(
            txid
        )

        if (
            tx is None
            or
            txid in published
        ):
            return

        votes = dict(
            tx_commit_votes.get(
                txid,
                {}
            )
        )

        accepts = sorted([
            rsu
            for rsu, decision
            in votes.items()
            if decision == "ACCEPT"
        ])

        rejects = sorted([
            rsu
            for rsu, decision
            in votes.items()
            if decision == "REJECT"
        ])

        # Independent RSU quorum.
        if len(accepts) < QUORUM:
            return

        # DAG support is a separate condition.
        cw = cumulative_weight(
            txid
        )

        if cw < CW_THRESHOLD:
            return

        # Publish only once.
        published.add(
            txid
        )

        commit_ms = now_ms()

        tx["_quorum_votes"] = accepts

        vote_messages = {
            rsu:
                tx_vote_messages[
                    txid
                ][rsu]
            for rsu in accepts
            if rsu in tx_vote_messages[
                txid
            ]
        }

    conn = db()

    conn.execute(
        """
        UPDATE transactions
        SET state=?,
            quorum_ms=?,
            cumulative_weight=?
        WHERE txid=?
        """,
        (
            "QUORUM_CONFIRMED",
            commit_ms,
            cw,
            txid
        )
    )

    conn.commit()
    conn.close()

    update_dag_states()

    broadcast_commit(
        txid,
        tx,
        vote_messages
    )

    confirmation_message = {
        "id": txid,
        "txid": txid,
        "data": tx["data"],
        "creator": tx["creator"],
        "origin_rsu":
            tx.get(
                "origin_rsu",
                RSU_ID
            ),
        "confirmation":
            f"{QUORUM}-of-{RSU_COUNT}-rsu-quorum",
        "cumulative_weight":
            cw,
        "quorum_votes":
            accepts
    }

    # RSU-specific vehicle topic.
    server_client.publish(
        TOPIC_CONFIRMED,
        json.dumps(
            confirmation_message
        ),
        qos=1
    )

    # Compatibility with existing ESP32 firmware.
    server_client.publish(
        TOPIC_GLOBAL_CONFIRMED,
        json.dumps(
            confirmation_message
        ),
        qos=1
    )

    latency_ms = (
        commit_ms
        -
        int(
            tx["timestamp_ms"]
        )
    )

    log_event(
        txid,
        "NETWORK_CONFIRMED",
        json.dumps({
            "accepts":
                accepts,
            "rejects":
                rejects,
            "cw":
                cw,
            "quorum":
                QUORUM
        })
    )

    csv_log({
        "elapsed_s":
            time.time() - start_time,
        "rsu_id":
            RSU_ID,
        "txid":
            txid,
        "creator":
            tx["creator"],
        "origin_rsu":
            tx.get(
                "origin_rsu",
                RSU_ID
            ),
        "event":
            "NETWORK_CONFIRMED",
        "state":
            "QUORUM_CONFIRMED",
        "cw":
            cw,
        "quorum_votes":
            len(accepts),
        "latency_ms":
            latency_ms,
        "pow_time_ms":
            tx.get(
                "pow_time_ms",
                0
            ),
        "data_score":
            data_plausibility(
                tx
            )[0],
        "trust_score":
            trust_scores[
                tx["creator"]
            ],
        "details":
            ",".join(accepts)
    })

    print(
        f"[{RSU_ID}] "
        f"NETWORK CONFIRMED "
        f"{txid[:12]}... "
        f"quorum={accepts} "
        f"CW={cw}"
    )


def handle_vote(msg):
    if not verify_rsu_message(
        msg
    ):
        return

    sender = msg[
        "sender_rsu"
    ]

    if sender == RSU_ID:
        warn_id_collision(msg.get("kind"))
        return

    if sender not in PEERS:
        print(
            f"[{RSU_ID}] WARNING: ignoring {msg.get('kind')} from "
            f"{sender}: not listed in PEERS ({list(PEERS)})"
        )
        return

    payload = msg.get(
        "payload",
        {}
    )

    txid = payload.get(
        "txid"
    )

    decision = payload.get(
        "decision"
    )

    if VERBOSE:
        print(
            f"[{RSU_ID}] VOTE <- {sender} "
            f"tx={str(txid)[:12]} {decision} "
            f"({payload.get('reason', '')})"
        )

    if txid not in tx_store:
        if VERBOSE:
            print(f"[{RSU_ID}]   ignored: tx not known here")
        return

    if decision not in {
        "ACCEPT",
        "REJECT"
    }:
        return

    with lock:

        tx_commit_votes[
            txid
        ][sender] = decision

        tx_vote_messages[
            txid
        ][sender] = msg

    store_vote(
        txid,
        sender,
        decision,
        payload.get(
            "reason",
            ""
        )
    )

    maybe_quorum(
        txid
    )


# ============================= PREPARE =============================

def install_dependencies(
    dependencies
):
    """
    Install cryptographically valid ancestry.
    Missing parents are never fabricated.
    """

    dependencies = (
        dependencies
        or
        []
    )

    candidates = []

    for dep in dependencies:

        if not isinstance(
            dep,
            dict
        ):
            continue

        tid = dep.get(
            "id"
        )

        if (
            not tid
            or
            tid == GENESIS
            or
            tid in tx_store
        ):
            continue

        try:

            if transaction_id(
                dep
            ) != tid:
                continue

            signature_ok, _ = (
                verify_vehicle_signature(
                    dep
                )
            )

            if not signature_ok:
                continue

            if not timestamp_valid(
                dep
            ):
                continue

            if int(
                dep.get(
                    "pow_difficulty",
                    -1
                )
            ) != POW_DIFFICULTY:
                continue

            if not has_valid_pow(
                dep
            ):
                continue

            score, _ = (
                data_plausibility(
                    dep
                )
            )

            candidates.append(
                (
                    dict(dep),
                    score
                )
            )

        except Exception:
            continue

    changed = True

    while changed:

        changed = False

        for dep, score in candidates:

            tid = dep["id"]

            if tid in tx_store:
                continue

            parents = dep.get(
                "approves",
                []
            )

            if all(
                parent == GENESIS
                or
                parent in G
                for parent in parents
            ):

                with lock:

                    tx_store[
                        tid
                    ] = dep

                    G.add_node(
                        tid,
                        creator=dep[
                            "creator"
                        ],
                        timestamp_ms=int(
                            dep[
                                "timestamp_ms"
                            ]
                        ),
                        data=dep[
                            "data"
                        ],
                        seen_ms=now_ms(),
                        state=
                            "replicated_dependency",
                        origin_rsu=
                            dep.get(
                                "origin_rsu",
                                "unknown"
                            )
                    )

                    for parent in parents:

                        G.add_edge(
                            tid,
                            parent
                        )

                    update_dag_states()

                store_transaction(
                    dep,
                    "REPLICATED_DEPENDENCY",
                    score,
                    "signed_ancestry"
                )

                changed = True


def process_prepare(
    msg
):
    if (
        not isinstance(
            msg,
            dict
        )
        or
        msg.get("kind")
        !=
        "PREPARE"
    ):
        return

    if not verify_rsu_message(
        msg
    ):
        return

    sender = msg[
        "sender_rsu"
    ]

    if sender == RSU_ID:
        warn_id_collision(msg.get("kind"))
        return

    if sender not in PEERS:
        print(
            f"[{RSU_ID}] WARNING: ignoring {msg.get('kind')} from "
            f"{sender}: not listed in PEERS ({list(PEERS)})"
        )
        return

    payload = msg.get(
        "payload",
        {}
    )

    tx = dict(
        payload.get(
            "tx",
            {}
        )
    )

    if not tx:
        return

    txid = tx.get(
        "id"
    )

    if not txid:
        return

    key = (
        sender,
        txid
    )

    with lock:

        retransmission = key in prepare_seen

        if retransmission and txid not in tx_store:
            # We saw this PREPARE before but did not store it (e.g. it
            # was rejected). Validate again below; no second penalty.
            pass

        elif retransmission:

            if txid in tx_store:

                # Re-send a vote only if the stored transaction passes
                # independent cryptographic/ancestry validation.
                known_tx = dict(
                    tx_store[txid]
                )

                crypt_ok = (
                    transaction_id(
                        known_tx
                    )
                    ==
                    txid
                    and
                    verify_vehicle_signature(
                        known_tx
                    )[0]
                    and
                    timestamp_valid(
                        known_tx
                    )
                    and
                    int(
                        known_tx.get(
                            "pow_difficulty",
                            -1
                        )
                    )
                    ==
                    POW_DIFFICULTY
                    and
                    has_valid_pow(
                        known_tx
                    )
                )

                parents_ok, _ = (
                    valid_remote_parents(
                        known_tx.get(
                            "approves",
                            []
                        ),
                        txid
                    )
                )

                if crypt_ok and parents_ok:

                    send_vote(
                        sender,
                        txid,
                        "ACCEPT",
                        "already_known_validated"
                    )

            return

        prepare_seen.add(
            key
        )

    install_dependencies(
        payload.get(
            "dependencies",
            []
        )
    )

    tx["_first_seen_ms"] = now_ms()

    if txid in tx_store:

        known_tx = dict(
            tx_store[txid]
        )

        crypt_ok = (
            transaction_id(
                known_tx
            )
            ==
            txid
            and
            verify_vehicle_signature(
                known_tx
            )[0]
            and
            timestamp_valid(
                known_tx
            )
            and
            int(
                known_tx.get(
                    "pow_difficulty",
                    -1
                )
            )
            ==
            POW_DIFFICULTY
            and
            has_valid_pow(
                known_tx
            )
        )

        parents_ok, _ = (
            valid_remote_parents(
                known_tx.get(
                    "approves",
                    []
                ),
                txid
            )
        )

        if crypt_ok and parents_ok:

            send_vote(
                sender,
                txid,
                "ACCEPT",
                "already_known_validated"
            )

        else:

            send_vote(
                sender,
                txid,
                "REJECT",
                "known_transaction_invalid"
            )

        return

    ok, score, reason = (
        validate_transaction(
            tx,
            remote=True,
            require_local_tips=False
        )
    )

    if not ok:

        if reason == "missing_parent":

            tx_quarantined[
                txid
            ] = tx

        creator = tx.get(
            "creator",
            "unknown"
        )

        if not retransmission and reason in {
            "invalid_pow",
            "bad_vehicle_signature",
            "unknown_vehicle_or_signature",
            "timestamp_invalid",
            "replay_sequence"
        }:

            update_trust(
                creator,
                -TRUST_PENALTY,
                reason
            )

        send_vote(
            sender,
            txid,
            "REJECT",
            reason
        )

        csv_log({
            "elapsed_s":
                time.time() - start_time,
            "rsu_id":
                RSU_ID,
            "txid":
                txid,
            "creator":
                creator,
            "origin_rsu":
                sender,
            "event":
                "PEER_REJECT",
            "state":
                "REJECTED",
            "cw":
                "",
            "quorum_votes":
                "",
            "latency_ms":
                "",
            "pow_time_ms":
                tx.get(
                    "pow_time_ms",
                    0
                ),
            "data_score":
                score,
            "trust_score":
                trust_scores[
                    creator
                ],
            "details":
                reason
        })

        return

    tx["origin_rsu"] = tx.get(
        "origin_rsu",
        sender
    )

    accepted = local_accept(
        tx,
        score,
        "independent_peer_validation",
        state="PEER_ACCEPTED"
    )

    if accepted:

        send_vote(
            sender,
            txid,
            "ACCEPT",
            "independent_validation"
        )

        maybe_quorum(
            txid
        )


# ============================= COMMIT ==============================

def process_commit(
    msg
):
    if (
        not isinstance(
            msg,
            dict
        )
        or
        msg.get("kind")
        !=
        "COMMIT"
    ):
        return

    if not verify_rsu_message(
        msg
    ):
        return

    sender = msg[
        "sender_rsu"
    ]

    if sender == RSU_ID:
        warn_id_collision(msg.get("kind"))
        return

    if sender not in PEERS:
        print(
            f"[{RSU_ID}] WARNING: ignoring {msg.get('kind')} from "
            f"{sender}: not listed in PEERS ({list(PEERS)})"
        )
        return

    payload = msg.get(
        "payload",
        {}
    )

    tx = payload.get(
        "tx"
    )

    txid = payload.get(
        "txid"
    )

    votes = payload.get(
        "votes",
        {}
    )

    if not tx or not txid:
        return

    if tx.get("id") != txid:
        return

    # Never trust the COMMIT message alone.
    if txid not in tx_store:

        tx_copy = dict(
            tx
        )

        ok, score, reason = (
            validate_transaction(
                tx_copy,
                remote=True,
                require_local_tips=False
            )
        )

        if not ok:

            log_event(
                txid,
                "COMMIT_REJECTED",
                reason
            )

            return

        tx_copy[
            "origin_rsu"
        ] = tx_copy.get(
            "origin_rsu",
            sender
        )

        local_accept(
            tx_copy,
            score,
            "commit_sync",
            state="PEER_ACCEPTED"
        )

    # Verify every included vote independently.
    for rsu, vote_msg in votes.items():

        if (
            rsu not in PEERS
            and
            rsu != RSU_ID
        ):
            continue

        if not isinstance(
            vote_msg,
            dict
        ):
            continue

        if vote_msg.get(
            "kind"
        ) != "VOTE":
            continue

        if vote_msg.get(
            "sender_rsu"
        ) != rsu:
            continue

        if not verify_rsu_message(
            vote_msg
        ):
            continue

        vote_payload = (
            vote_msg.get(
                "payload",
                {}
            )
        )

        if vote_payload.get(
            "txid"
        ) != txid:
            continue

        decision = vote_payload.get(
            "decision"
        )

        if decision not in {
            "ACCEPT",
            "REJECT"
        }:
            continue

        with lock:

            tx_commit_votes[
                txid
            ][rsu] = decision

            tx_vote_messages[
                txid
            ][rsu] = vote_msg

        store_vote(
            txid,
            rsu,
            decision,
            vote_payload.get(
                "reason",
                ""
            )
        )

    # Local RSU must have independently validated the transaction too.
    maybe_quorum(
        txid
    )


# ============================= SYNC ================================

def process_sync_request(
    msg
):
    if (
        not isinstance(
            msg,
            dict
        )
        or
        msg.get("kind")
        !=
        "SYNC_REQUEST"
    ):
        return

    if not verify_rsu_message(
        msg
    ):
        return

    requester = msg[
        "sender_rsu"
    ]

    if requester not in PEERS:
        return

    known = set(
        msg.get(
            "payload",
            {}
        ).get(
            "known_txids",
            []
        )
    )

    with lock:

        missing = [
            tx
            for tid, tx
            in tx_store.items()
            if tid not in known
        ]

    batch = missing[
        :SYNC_BATCH_SIZE
    ]

    response = signed_rsu_message(
        "SYNC_RESPONSE",
        {
            "target":
                requester,
            "transactions":
                batch
        }
    )

    publish_peer(
        requester,
        TOPIC_SYNC_RESPONSE,
        response
    )


def process_sync_response(
    msg
):
    if (
        not isinstance(
            msg,
            dict
        )
        or
        msg.get("kind")
        !=
        "SYNC_RESPONSE"
    ):
        return

    if not verify_rsu_message(
        msg
    ):
        return

    payload = msg.get(
        "payload",
        {}
    )

    if payload.get(
        "target"
    ) != RSU_ID:
        return

    for tx in payload.get(
        "transactions",
        []
    ):

        if not isinstance(
            tx,
            dict
        ):
            continue

        txid = tx.get(
            "id"
        )

        if (
            not txid
            or
            txid in tx_store
        ):
            continue

        tx_copy = dict(
            tx
        )

        ok, score, reason = (
            validate_transaction(
                tx_copy,
                remote=True,
                require_local_tips=False
            )
        )

        if not ok:
            continue

        tx_copy[
            "origin_rsu"
        ] = tx_copy.get(
            "origin_rsu",
            msg[
                "sender_rsu"
            ]
        )

        if local_accept(
            tx_copy,
            score,
            "recovery_sync",
            state="PEER_ACCEPTED"
        ):
            maybe_quorum(
                txid
            )


# ======================= QUARANTINE RECOVERY =======================

def retry_quarantined():
    while True:

        time.sleep(5)

        with lock:
            items = list(
                tx_quarantined.items()
            )

        for txid, tx in items:

            ok, score, reason = (
                validate_transaction(
                    tx,
                    remote=True,
                    require_local_tips=False
                )
            )

            if not ok:
                continue

            if local_accept(
                tx,
                score,
                "quarantine_release",
                state="PEER_ACCEPTED"
            ):

                with lock:

                    tx_quarantined.pop(
                        txid,
                        None
                    )

                origin = tx.get(
                    "origin_rsu"
                )

                if (
                    origin
                    and
                    origin != RSU_ID
                ):

                    send_vote(
                        origin,
                        txid,
                        "ACCEPT",
                        "quarantine_release"
                    )

                maybe_quorum(
                    txid
                )


# ============================= LOCAL SUBMISSION ====================

def process_local_submission(
    tx
):
    tx = dict(tx)

    tx.setdefault(
        "version",
        PROTOCOL_VERSION
    )

    tx["_first_seen_ms"] = now_ms()

    try:

        # The RSU never changes immutable vehicle content.
        # If id is absent, derive it from the signed body.
        tx["id"] = (
            tx.get("id")
            or
            transaction_id(tx)
        )

    except Exception as exc:

        log_event(
            "unknown",
            "REJECTED",
            f"malformed_transaction:{exc}"
        )

        return

    tx["origin_rsu"] = RSU_ID

    ok, score, reason = (
        validate_transaction(
            tx,
            remote=False,
            require_local_tips=True
        )
    )

    if not ok:

        creator = tx.get(
            "creator",
            "unknown"
        )

        if reason in {
            "invalid_pow",
            "bad_vehicle_signature",
            "unknown_vehicle_or_signature",
            "timestamp_invalid",
            "replay_sequence",
            "rate_limit",
            "unexpected_pow_difficulty"
        }:

            update_trust(
                creator,
                -TRUST_PENALTY,
                reason
            )

        if reason == "missing_parent":

            tx_quarantined[
                tx["id"]
            ] = tx

        log_event(
            tx["id"],
            "REJECTED",
            reason
        )

        csv_log({
            "elapsed_s":
                time.time() - start_time,
            "rsu_id":
                RSU_ID,
            "txid":
                tx["id"],
            "creator":
                creator,
            "origin_rsu":
                RSU_ID,
            "event":
                "REJECTED",
            "state":
                "REJECTED",
            "cw":
                "",
            "quorum_votes":
                "",
            "latency_ms":
                "",
            "pow_time_ms":
                tx.get(
                    "pow_time_ms",
                    0
                ),
            "data_score":
                score,
            "trust_score":
                trust_scores[
                    creator
                ],
            "details":
                reason
        })

        print(
            f"[{RSU_ID}] "
            f"REJECT "
            f"{tx['id'][:12]}... "
            f"reason={reason}"
        )

        return

    accepted = local_accept(
        tx,
        score,
        reason,
        state="LOCAL_ACCEPTED"
    )

    if accepted:

        # Replicate to independent RSUs.
        replicate_prepare(
            tx
        )

        # 1/3 local vote is already stored.
        # Quorum will be reached when peer votes arrive.
        maybe_quorum(
            tx["id"]
        )


# ============================= MQTT ================================

def on_message(
    client,
    userdata,
    msg
):
    try:

        payload = json.loads(
            msg.payload.decode(
                "utf-8"
            )
        )

    except Exception:
        return

    if msg.topic == TOPIC_TIPS:

        vehicle_id = payload.get(
            "client",
            "unknown"
        )

        tips = select_two_tips()

        client.publish(
            f"tangle/tips/{vehicle_id}",
            json.dumps({
                "tips":
                    tips,
                "rsu":
                    RSU_ID
            }),
            qos=1
        )

        return

    if msg.topic == TOPIC_SUBMIT:

        process_local_submission(
            payload
        )

        return

    if msg.topic == TOPIC_PREPARE:

        process_prepare(
            payload
        )

        return

    if msg.topic == TOPIC_VOTE:

        handle_vote(
            payload
        )

        return

    if msg.topic == TOPIC_COMMIT:

        process_commit(
            payload
        )

        return

    if msg.topic == TOPIC_SYNC_REQUEST:

        process_sync_request(
            payload
        )

        return

    if msg.topic == TOPIC_HELLO:

        process_hello(
            payload
        )

        return

    if msg.topic == TOPIC_SYNC_RESPONSE:

        process_sync_response(
            payload
        )

        return


# ============================= RECOVERY =============================

def quorum_loop():
    while True:

        time.sleep(1)

        with lock:
            candidates = list(
                tx_store.keys()
            )

        for txid in candidates:

            maybe_quorum(
                txid
            )

        resend_pending_prepares()


def recovery_loop():
    while True:

        time.sleep(
            SYNC_INTERVAL_S
        )

        for peer_id in list(
            PEERS
        ):

            if peer_id not in peer_clients:

                host, port = PEERS[
                    peer_id
                ]

                connect_peer(
                    peer_id,
                    host,
                    port
                )

            send_sync_request(
                peer_id
            )


# ============================= VISUALIZATION =======================

def export_dag_html():
    try:

        from pyvis.network import Network

        net = Network(
            height="850px",
            width="100%",
            directed=True
        )

        with lock:

            nodes = list(
                G.nodes(
                    data=True
                )
            )

            edges = list(
                G.edges()
            )

        for node, attrs in nodes:

            state = attrs.get(
                "state",
                "unknown"
            )

            cw = cumulative_weight(
                node
            )

            label = (
                "GENESIS"
                if node == GENESIS
                else node[:12]
            )

            net.add_node(
                node,
                label=label,
                title=(
                    f"State={state}"
                    f"<br>CW={cw}"
                ),
                color={
                    "genesis":
                        "gold",
                    "tip":
                        "red",
                    "approved":
                        "orange",
                    "locally_supported":
                        "green",
                    "locally_accepted":
                        "blue",
                    "network_confirmed":
                        "darkgreen",
                    "replicated_dependency":
                        "lightblue",
                    "peer_accepted":
                        "green"
                }.get(
                    state,
                    "gray"
                )
            )

        for child, parent in edges:

            net.add_edge(
                child,
                parent
            )

        net.save_graph(
            DAG_HTML
        )

    except Exception as exc:

        print(
            f"[{RSU_ID}] "
            f"DAG export skipped: "
            f"{exc}"
        )


def metrics_loop():
    while True:

        time.sleep(10)

        with lock:

            n = len(
                tx_store
            )

            tips = len(
                current_tips()
            )

            confirmed = len(
                published
            )

            avg_cw = (
                sum(
                    cumulative_weight(
                        txid
                    )
                    for txid
                    in tx_store
                )
                / n
                if n
                else 0.0
            )

            peers = {
                pid: (
                    ("up" if c.is_connected() else "DOWN")
                    + ("/ok" if peer_handshake[pid]["out"] else "/no-handshake")
                )
                for pid, c in peer_clients.items()
            }

            wait_votes = 0
            wait_cw = 0

            for txid in tx_store:
                if txid in published:
                    continue
                accepts = sum(
                    1 for d in tx_commit_votes.get(txid, {}).values()
                    if d == "ACCEPT"
                )
                if accepts < QUORUM:
                    wait_votes += 1
                elif cumulative_weight(txid) < CW_THRESHOLD:
                    wait_cw += 1

        print(
            f"[{RSU_ID}] "
            f"tx={n} "
            f"tips={tips} "
            f"network_confirmed={confirmed} "
            f"avg_CW={avg_cw:.2f} "
            f"waiting_votes={wait_votes} "
            f"waiting_CW={wait_cw} "
            f"peers={peers}"
        )


# ============================= MAIN =================================

def main():
    global server_client

    load_keys()

    init_db()

    add_genesis_if_needed()

    update_dag_states()

    server_client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=f"{RSU_ID}_local"
    )

    server_client.on_message = on_message

    def on_connect(
        client,
        userdata,
        flags,
        reason_code,
        properties=None
    ):
        print(
            f"[{RSU_ID}] "
            f"local broker connected: "
            f"{reason_code}"
        )

    server_client.on_connect = on_connect

    server_client.connect(
        BROKER_HOST,
        BROKER_PORT,
        60
    )

    subscriptions = [
        (TOPIC_TIPS, 1),
        (TOPIC_SUBMIT, 1),
        (TOPIC_PREPARE, 1),
        (TOPIC_VOTE, 1),
        (TOPIC_COMMIT, 1),
        (TOPIC_SYNC_REQUEST, 1),
        (TOPIC_SYNC_RESPONSE, 1),
        (TOPIC_HELLO, 1)
    ]

    for topic, qos in subscriptions:

        server_client.subscribe(
            topic,
            qos=qos
        )

    server_client.loop_start()

    # Direct outbound connections to the other RSUs.
    for peer_id, (
        host,
        port
    ) in PEERS.items():

        connect_peer(
            peer_id,
            host,
            port
        )

    print()
    print("=" * 72)
    print(" TinyDLT — 3-RSU DAG SERVER")
    print("=" * 72)
    print(
        f" RSU ID       : {RSU_ID}"
    )
    print(
        f" RSU IP       : {RSU_IP}"
    )
    print(
        f" Local broker : "
        f"{BROKER_HOST}:{BROKER_PORT}"
    )
    print(
        f" Peers        : {PEERS}"
    )
    print(
        f" Quorum       : "
        f"{QUORUM}/{RSU_COUNT}"
    )
    print(
        f" CW threshold : "
        f"{CW_THRESHOLD}"
    )
    print(
        f" PoW          : "
        f"{POW_DIFFICULTY} bits"
    )
    print(
        f" Tip policy   : {TIP_POLICY}"
        + (f" (target tips={TARGET_TIPS}, window={TIP_WINDOW_S:g}s)"
           if TIP_POLICY != "strict" else "")
    )
    print(
        f" Enroll peers : {'ON (lab mode)' if ENROLL_PEERS else 'off'}"
    )
    print(
        f" Key sync     : "
        f"{'vehicle registry shared with peers' if VEHICLE_KEY_SYNC else 'off'}"
    )
    print(
        f" Clock        : "
        f"{'per-peer offset compensation ON' if CLOCK_COMPENSATION else 'strict (NTP required)'}"
    )
    print(
        f" DB           : {DB_PATH}"
    )
    print(
        f" CSV          : {LOG_PATH}"
    )
    print(
        f" RSU pubkey   : "
        f"{rsu_public_hex()}"
    )
    print("=" * 72)
    print()

    threading.Thread(
        target=recovery_loop,
        daemon=True
    ).start()

    threading.Thread(
        target=quorum_loop,
        daemon=True
    ).start()

    threading.Thread(
        target=hello_loop,
        daemon=True
    ).start()

    threading.Thread(
        target=retry_quarantined,
        daemon=True
    ).start()

    threading.Thread(
        target=metrics_loop,
        daemon=True
    ).start()

    try:

        while True:

            time.sleep(30)

            export_dag_html()

    except KeyboardInterrupt:

        print(
            f"\n[{RSU_ID}] stopping..."
        )

    finally:

        try:

            server_client.loop_stop()
            server_client.disconnect()

        except Exception:
            pass

        for client in peer_clients.values():

            try:

                client.loop_stop()
                client.disconnect()

            except Exception:
                pass


if __name__ == "__main__":
    main()
