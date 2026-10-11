#!/usr/bin/env python3
"""
make_preview.py — SYNTHETIC PREVIEW GENERATOR

Produces FAKE runs so you can see the shape of every figure before
spending hours on the real experiments. It takes the distributions from
your one real run and resamples them with jitter; it invents the cells
you have not measured at all (1rsu, 2rsu, load sweep, faults, attacks).

NOTHING THIS SCRIPT WRITES IS A MEASUREMENT.

Everything lands in preview_results/ (never results/), every run.json is
marked "synthetic": true, and analyse_results.py stamps every figure
built from it with a SYNTHETIC watermark. Delete the whole preview_
directory before you analyse real runs.

    python3 make_preview.py --real-run <dir with your run-1 csv/db files>
    python3 analyse_results.py --results preview_results --preview
"""

import argparse
import json
import random
import sqlite3
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "preview_results"
RSUS = ["RSU1", "RSU2", "RSU3"]
rng = np.random.default_rng(20260923)


def load_real(src):
    ev = {}
    for rid in RSUS:
        f = src / f"logs_{rid}.csv"
        if f.exists():
            ev[rid] = pd.read_csv(f)
    perf = {}
    for rid in RSUS:
        f = src / f"perf_{rid}.csv"
        if f.exists():
            p = pd.read_csv(f)
            # keep only the LAST session in the file (the others are
            # leftovers from earlier runs)
            starts = p.index[p["t_s"].diff() < 0].tolist()
            if starts:
                p = p.loc[starts[-1]:].reset_index(drop=True)
            perf[rid] = p
    if not ev:
        raise SystemExit(f"no logs_RSU*.csv in {src}")
    return ev, perf


def jitter(series, scale=0.12):
    v = pd.to_numeric(series, errors="coerce")
    noise = rng.normal(1.0, scale, len(v))
    return (v * noise).clip(lower=0)


def write_run(cell, load, rep, ev, perf, meta, labels=None,
              experiment="configs"):
    d = OUT / experiment / cell / load / f"rep{rep}"
    d.mkdir(parents=True, exist_ok=True)

    for rid, frame in ev.items():
        frame.to_csv(d / f"logs_{rid}.csv", index=False)
        confirmed = frame[frame["event"] == "NETWORK_CONFIRMED"]["txid"]
        con = sqlite3.connect(d / f"tinyDLT_{rid}.db")
        con.execute("CREATE TABLE IF NOT EXISTS transactions "
                    "(txid TEXT PRIMARY KEY, state TEXT)")
        con.executemany("INSERT OR REPLACE INTO transactions VALUES (?,?)",
                        [(t, "QUORUM_CONFIRMED") for t in confirmed])
        con.commit()
        con.close()
    for rid, frame in perf.items():
        frame.to_csv(d / f"perf_{rid}.csv", index=False)
    if labels is not None:
        labels.to_csv(d / "labels.csv", index=False)

    meta = {**meta, "synthetic": True,
            "WARNING": "FABRICATED PREVIEW DATA - NOT A MEASUREMENT"}
    (d / "run.json").write_text(json.dumps(meta, indent=2))


def resample(ev, perf, *, rate=1.0, latency=1.0, cpu=1.0, keep=1.0,
             tag=""):
    """Perturb a real run into a plausible different one."""
    new_ev, new_perf = {}, {}
    for rid, frame in ev.items():
        f = frame.copy()
        if keep < 1.0:
            confirmed = f[f["event"] == "NETWORK_CONFIRMED"]
            drop = confirmed.sample(frac=1 - keep, random_state=rng.integers(1e6))
            f = f.drop(drop.index)
        for col, sc in (("latency_ms", latency), ("cw_wait_ms", latency),
                        ("quorum_wait_ms", 1.0), ("pow_time_ms", 1.0)):
            if col in f.columns:
                f[col] = jitter(f[col] * sc)
        if "elapsed_s" in f.columns and rate != 1.0:
            f["elapsed_s"] = f["elapsed_s"] / rate
        f["txid"] = f["txid"].astype(str) + tag
        new_ev[rid] = f
    for rid, p in perf.items():
        q = p.copy()
        if "cpu_s" in q.columns:
            q["cpu_s"] = jitter(q["cpu_s"] * cpu, 0.05)
        if "t_s" in q.columns and rate != 1.0:
            q["t_s"] = q["t_s"] / rate
        new_perf[rid] = q
    return new_ev, new_perf


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--real-run", required=True,
                    help="directory holding your real run-1 logs/perf/db")
    ap.add_argument("--reps", type=int, default=4)
    args = ap.parse_args()

    ev0, perf0 = load_real(Path(args.real_run))
    print(f"loaded real run: {sum(len(f) for f in ev0.values())} event rows")

    # ---- configs: 3rsu reps, plus invented 1rsu / 2rsu ----------------
    for rep in range(1, args.reps + 1):
        ev, perf = resample(ev0, perf0, tag=f"-c3r{rep}")
        write_run("3rsu", "load-esp32", rep, ev, perf,
                  {"rsu_count": 3, "quorum": 2, "vehicles": 3,
                   "interval_s": 7, "duration_s": 1300,
                   "config": "3rsu", "source": "SYNTHETIC"})

        for cell, n, cpu in (("1rsu", 1, 0.45), ("2rsu", 2, 0.75)):
            sub = {k: v for k, v in ev.items() if k in RSUS[:n]}
            subp = {k: v for k, v in perf.items() if k in RSUS[:n]}
            e2, p2 = resample(sub, subp, latency=0.97 if n > 1 else 0.92,
                              cpu=cpu, tag=f"-c{n}r{rep}")
            write_run(cell, "load-esp32", rep, e2, p2,
                      {"rsu_count": n, "quorum": n, "vehicles": 3,
                       "interval_s": 7, "duration_s": 1300,
                       "config": cell, "source": "SYNTHETIC"})

    # ---- load sweep: invented saturation behaviour ---------------------
    for interval, rate, keep in ((10, 0.7, 1.0), (5, 1.4, 1.0),
                                 (2, 3.5, 0.98), (1, 7.0, 0.90),
                                 (0.5, 12.0, 0.62)):
        for rep in range(1, args.reps + 1):
            ev, perf = resample(ev0, perf0, rate=rate,
                                latency=max(0.15, 1.6 / rate) + 0.2 * (rate > 8),
                                keep=keep, cpu=1.0,
                                tag=f"-l{interval}r{rep}")
            write_run("3rsu", f"load-{interval}s", rep, ev, perf,
                      {"rsu_count": 3, "quorum": 2, "vehicles": 3,
                       "interval_s": interval, "duration_s": 1300 / rate,
                       "config": "3rsu", "source": "SYNTHETIC"},
                      experiment="load")

    # ---- faults: gap then recovery ------------------------------------
    for cell, sched in (
            ("partition", [{"t_s": 300, "action": "partition", "rsu": "RSU3"},
                           {"t_s": 420, "action": "heal", "rsu": "RSU3"}]),
            ("unit-failure", [{"t_s": 300, "action": "kill", "rsu": "RSU3"},
                              {"t_s": 420, "action": "restart", "rsu": "RSU3"}])):
        for rep in range(1, args.reps + 1):
            ev, perf = resample(ev0, perf0, tag=f"-f{cell[:4]}{rep}")
            # RSU3 records nothing during the outage, then catches up
            f = ev["RSU3"]
            out = (f["elapsed_s"] > 300) & (f["elapsed_s"] < 420)
            caught = f[out].copy()
            caught["elapsed_s"] = 425 + rng.uniform(0, 8, len(caught))
            caught["details"] = "recovery_sync"
            ev["RSU3"] = pd.concat([f[~out], caught]).sort_values("elapsed_s")
            write_run(cell, "load-esp32", rep, ev, perf,
                      {"rsu_count": 3, "quorum": 2, "vehicles": 3,
                       "interval_s": 7, "duration_s": 1300,
                       "config": "3rsu", "scenario": cell,
                       "faults": sched, "source": "SYNTHETIC"},
                      experiment="faults")

    # ---- attacks: one attacker vehicle per cell ------------------------
    reason = {"invalid_pow": "invalid_pow",
              "bad_signature": "bad_vehicle_signature",
              "replay_sequence": "replay_sequence",
              "implausible_data": "speed_out_of_range"}
    for attack, rsn in reason.items():
        for rep in range(1, args.reps + 1):
            ev, perf = resample(ev0, perf0, tag=f"-a{attack[:4]}{rep}")
            rows = []
            for rid, f in ev.items():
                mine = f[f["state"] == "LOCAL_ACCEPTED"].copy()
                n_att = max(6, int(0.35 * len(mine)))
                att = mine.sample(n=min(n_att, len(mine)),
                                  random_state=int(rng.integers(1e6))).copy()
                att["creator"] = "vehicle_att"
                att["event"] = "REJECTED"
                att["state"] = "REJECTED"
                att["details"] = rsn
                # trust decays with each rejection
                att = att.sort_values("elapsed_s")
                att["trust_score"] = np.clip(
                    0.5 - 0.1 * np.arange(len(att)), 0.0, 1.0)
                ev[rid] = pd.concat([f, att]).sort_values("elapsed_s")
                rows.append(att)
            att_all = pd.concat(rows)
            honest = pd.concat(ev.values())
            honest = honest[(honest["state"] == "LOCAL_ACCEPTED")]
            labels = pd.DataFrame({
                "txid": list(att_all["txid"]) + list(honest["txid"]),
                "creator": ["vehicle_att"] * len(att_all) +
                           list(honest["creator"]),
                "attack": [attack] * len(att_all) + ["none"] * len(honest),
                "submit_ms": 0, "pow_time_ms": 0, "submitted": 1,
            })
            write_run(attack, "load-esp32", rep, ev, perf,
                      {"rsu_count": 3, "quorum": 2, "vehicles": 4,
                       "interval_s": 7, "duration_s": 1300,
                       "config": "3rsu", "attack": attack,
                       "attackers": 1, "source": "SYNTHETIC"},
                      labels=labels, experiment="attacks")

    n = len(list(OUT.glob("*/*/*/*/run.json")))
    print(f"wrote {n} SYNTHETIC runs to {OUT}")
    print("Analyse with:  python3 analyse_results.py "
          "--results preview_results --preview")
    print("DELETE preview_results/ before analysing real measurements.")


if __name__ == "__main__":
    main()
