#!/usr/bin/env python3
"""
Fold a REAL deployment run into the results tree
================================================

experiment_runner.py drives a local testbed: it spawns its own RSU
processes and its own brokers, so it cannot orchestrate your three
machines and the ESP32. For hardware runs you start everything by hand,
then copy the logs here and run this script. The analyser then treats
them exactly like testbed runs.

On each RSU machine, after the run:

    scp ~/multirsu/logs_RSU1.csv  you@analysis-host:~/tinydlt/incoming/
    scp ~/multirsu/perf_RSU1.csv  you@analysis-host:~/tinydlt/incoming/
    scp ~/multirsu/tinyDLT_RSU1.db you@analysis-host:~/tinydlt/incoming/

Then:

    python3 collect_hardware_run.py --src incoming \
        --cell 3rsu-hardware --load load-esp32 --rep 1 \
        --rsu-count 3 --quorum 2 --vehicles 1 --interval 7

    python3 analyse_results.py

Attack runs with the ESP32: the firmware knows which transactions it
corrupted but nothing writes that down, so pass --attack-vehicle and
--attack-type and this script marks every transaction from that vehicle
as malicious in labels.csv. Run one attack type per run.
"""

import argparse
import csv
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True,
                    help="directory holding the copied logs_*/perf_*/*.db")
    ap.add_argument("--cell", default="hardware",
                    help="configuration name, e.g. 3rsu-hardware")
    ap.add_argument("--load", default="load-hardware")
    ap.add_argument("--rep", type=int, default=1)
    ap.add_argument("--experiment", default="hardware")
    ap.add_argument("--rsu-count", type=int, required=True)
    ap.add_argument("--quorum", type=int, required=True)
    ap.add_argument("--vehicles", type=int, default=1)
    ap.add_argument("--interval", type=float, default=None,
                    help="nominal seconds between transactions per vehicle")
    ap.add_argument("--attack-vehicle", default=None,
                    help="vehicle id that misbehaved during this run")
    ap.add_argument("--attack-type", default="none")
    ap.add_argument("--fault", action="append", default=[],
                    metavar="T:ACTION:RSU",
                    help="fault event, seconds from the start of the run, "
                         "e.g. --fault 120:kill:RSU3 "
                         "--fault 180:restart:RSU3 (repeatable). "
                         "Actions: kill, restart, partition, heal.")
    ap.add_argument("--note", default="")
    args = ap.parse_args()

    src = Path(args.src)
    out = (ROOT / "results" / args.experiment / args.cell /
           args.load / f"rep{args.rep}")
    out.mkdir(parents=True, exist_ok=True)

    copied = []
    for pattern in ("logs_RSU*.csv", "perf_RSU*.csv", "tinyDLT_RSU*.db",
                    "labels.csv"):
        for f in sorted(src.glob(pattern)):
            shutil.copy(f, out / f.name)
            copied.append(f.name)

    logs = sorted(out.glob("logs_RSU*.csv"))
    if not logs:
        present = sorted(p.name for p in src.iterdir()) if src.exists() else None
        msg = [f"\nNo logs_RSU*.csv found in: {src.resolve()}"]
        if present is None:
            msg.append("  That folder does not exist.")
        elif not present:
            msg.append("  The folder exists but is EMPTY - the logs were "
                       "never copied into it.")
        else:
            msg.append("  It contains: " + ", ".join(present))
        here = sorted(Path(".").glob("logs_RSU*.csv"))
        if here:
            msg.append("  But the current folder has: "
                       + ", ".join(p.name for p in here)
                       + "\n  -> copy them into the incoming folder first.")
        raise SystemExit("\n".join(msg))

    # duration and transaction count from the logs themselves
    duration, creators, txids = 0.0, set(), {}
    for f in logs:
        with f.open(newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                try:
                    duration = max(duration, float(row["elapsed_s"]))
                except (ValueError, KeyError):
                    pass
                if row.get("creator"):
                    creators.add(row["creator"])
                if row.get("txid") and row.get("creator"):
                    txids[row["txid"]] = row["creator"]

    # ground truth for an attack run, if there is no labels.csv already
    if args.attack_vehicle and not (out / "labels.csv").exists():
        with (out / "labels.csv").open("w", newline="",
                                       encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=[
                "txid", "creator", "attack", "submit_ms",
                "pow_time_ms", "submitted"])
            w.writeheader()
            for txid, creator in txids.items():
                w.writerow({
                    "txid": txid,
                    "creator": creator,
                    "attack": (args.attack_type
                               if creator == args.attack_vehicle
                               else "none"),
                    "submit_ms": "",
                    "pow_time_ms": "",
                    "submitted": 1,
                })
        copied.append("labels.csv (reconstructed)")

    faults = []
    for spec in args.fault:
        try:
            t_s, action, rsu = spec.split(":")
            faults.append({"t_s": float(t_s), "action": action, "rsu": rsu})
        except ValueError:
            raise SystemExit(f"bad --fault {spec!r}, expected T:ACTION:RSU")

    (out / "run.json").write_text(json.dumps({
        "rsu_count": args.rsu_count,
        "quorum": args.quorum,
        "vehicles": args.vehicles,
        "transactions": len(txids),
        "interval_s": args.interval,
        "duration_s": round(duration, 2),
        "faults": faults,
        "source": "hardware",
        "config": args.cell,
        "attack": args.attack_type,
        "creators": sorted(creators),
        "note": args.note,
    }, indent=2))

    print(f"wrote {out}")
    print(f"  files    : {', '.join(copied)}")
    print(f"  duration : {duration:.1f}s over {len(txids)} transactions")
    print(f"  vehicles : {sorted(creators)}")
    if not list(out.glob("perf_RSU*.csv")):
        print("  NOTE: no perf_RSU*.csv - F3 (CPU vs ledger size) and F8 "
              "(tip-set size) need the instrumented rsu_server.py.")


if __name__ == "__main__":
    main()
