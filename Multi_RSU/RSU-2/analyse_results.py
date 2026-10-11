#!/usr/bin/env python3
"""
TinyDLT results analyser
========================

Reads results/<experiment>/<config>/<load>/rep<k>/ and writes:

    figures/F1_throughput_latency.{png,pdf}
    figures/F2_saturation.{png,pdf}
    figures/F3_cpu_vs_ledger.{png,pdf}
    figures/F4_replica_agreement.{png,pdf}
    figures/F5_availability_recovery.{png,pdf}
    figures/F6_trust_and_detection.{png,pdf}
    figures/F7_pow_time_energy.{png,pdf}
    figures/F8_tip_set_size.{png,pdf}
    figures/F9_rejections_by_stage.{png,pdf}
    tables/T1_per_run_raw.csv
    tables/T2_aggregated_ci95.csv
    tables/T3_replica_agreement.csv

Every figure is derived from the logs only - nothing is hard-coded or
assumed. Where a quantity cannot be measured directly (energy), the
assumption is stated in the axis label and set by a CLI flag.
"""

import argparse
import json
import math
import sqlite3
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
FIGS = ROOT / "figures"
TABLES = ROOT / "tables"

# Which validation stage each rejection reason belongs to (F9).
STAGE = {
    "missing_field": "1. structure",
    "txid_mismatch": "1. structure",
    "duplicate": "1. structure",
    "unknown_vehicle_or_signature": "2. authentication",
    "bad_vehicle_signature": "2. authentication",
    "unknown_vehicle": "2. authentication",
    "low_trust": "3. trust",
    "timestamp_invalid": "4. freshness",
    "replay_sequence": "5. replay/rate",
    "rate_limit": "5. replay/rate",
    "invalid_pow": "6. proof-of-work",
    "unexpected_pow_difficulty": "6. proof-of-work",
    "parent_not_tip": "7. DAG parents",
    "parent_too_old": "7. DAG parents",
    "missing_parent": "7. DAG parents",
    "unknown_parent": "7. DAG parents",
    "speed_out_of_range": "8. plausibility",
    "implausible_acceleration": "8. plausibility",
    "weak_plausibility": "8. plausibility",
}


def stage_of(reason):
    r = str(reason).strip()
    return STAGE.get(r, f"9. other ({r})" if r else "9. other")


def ci95(values):
    """Mean and half-width of the 95% CI (t-distribution)."""
    v = np.asarray([x for x in values if x is not None and not pd.isna(x)],
                   dtype=float)
    n = len(v)
    if n == 0:
        return math.nan, math.nan, 0
    if n == 1:
        return float(v[0]), math.nan, 1
    try:
        from scipy import stats
        t = stats.t.ppf(0.975, n - 1)
    except Exception:
        t = 2.0
    return float(v.mean()), float(t * v.std(ddof=1) / math.sqrt(n)), n


# --------------------------------------------------------------------
# loading
# --------------------------------------------------------------------

def load_runs():
    runs = []
    for meta_path in sorted(RESULTS.glob("*/*/*/*/run.json")):
        d = meta_path.parent
        meta = json.loads(meta_path.read_text())
        rec = {
            "dir": d,
            "experiment": d.parts[-4],
            "cell": d.parts[-3],
            "load": d.parts[-2],
            "rep": d.name,
            "meta": meta,
            "events": {},
            "perf": {},
            "confirmed_sets": {},
        }
        for f in sorted(d.glob("logs_RSU*.csv")):
            rid = f.stem.replace("logs_", "")
            try:
                rec["events"][rid] = pd.read_csv(f)
            except Exception:
                pass
        for f in sorted(d.glob("perf_RSU*.csv")):
            rid = f.stem.replace("perf_", "")
            try:
                rec["perf"][rid] = pd.read_csv(f)
            except Exception:
                pass
        for f in sorted(d.glob("tinyDLT_RSU*.db")):
            rid = f.stem.replace("tinyDLT_", "")
            try:
                con = sqlite3.connect(f)
                rec["confirmed_sets"][rid] = {
                    r[0] for r in con.execute(
                        "SELECT txid FROM transactions "
                        "WHERE state='QUORUM_CONFIRMED'")
                }
                con.close()
            except Exception:
                pass
        lab = d / "labels.csv"
        if lab.exists():
            try:
                rec["labels"] = pd.read_csv(lab)
            except Exception:
                rec["labels"] = None
        else:
            rec["labels"] = None
        runs.append(rec)
    return runs


# --------------------------------------------------------------------
# T1: one row per RSU per repetition
# --------------------------------------------------------------------

def build_t1(runs):
    rows = []
    for r in runs:
        meta = r["meta"]
        duration = meta.get("duration_s", np.nan)
        for rid, ev in r["events"].items():
            if ev.empty:
                continue
            conf = ev[ev["event"] == "NETWORK_CONFIRMED"]
            local = ev[(ev["event"] == "LOCAL_ACCEPT") &
                       (ev["state"] == "LOCAL_ACCEPTED")]
            peer = ev[(ev["event"] == "LOCAL_ACCEPT") &
                      (ev["state"] == "PEER_ACCEPTED")]
            rej = ev[ev["event"].isin(["REJECTED", "PEER_REJECT"])]

            span = ev["elapsed_s"].max() - ev["elapsed_s"].min()
            span = span if span and span > 0 else duration

            lat = pd.to_numeric(
                conf["latency_ms"] if "latency_ms" in conf.columns
                else pd.Series(dtype=float), errors="coerce").dropna()
            def numcol(frame, name):
                if name not in frame.columns:
                    return pd.Series(dtype=float)
                return pd.to_numeric(frame[name], errors="coerce").dropna()

            own = conf
            if "origin_rsu" in conf.columns:
                own = conf[conf["origin_rsu"] == rid]
            qw = numcol(own, "quorum_wait_ms")
            cww = numcol(own, "cw_wait_ms")
            cw_share = np.nan
            if "binding_constraint" in own.columns and len(own):
                cw_share = (own["binding_constraint"] == "cw").mean()

            # Measured offered rate from the vehicle side. 1/interval is
            # only nominal: at short intervals the simulator itself is
            # limited by PoW and the tip round trip, so the nominal value
            # overstates what was actually offered.
            offered_measured = np.nan
            lab = r.get("labels")
            if lab is not None and len(lab) > 1:
                span_l = (lab["submit_ms"].max() - lab["submit_ms"].min()) / 1000
                if span_l > 0:
                    offered_measured = len(lab) / span_l
            pw = pd.to_numeric(ev.get("pow_time_ms"), errors="coerce")
            pw = pw[pw > 0].dropna()

            perf = r["perf"].get(rid)
            cpu_per_conf, mean_tips, max_tips, rss = (np.nan,) * 4
            if perf is not None and len(perf) > 2:
                dcpu = perf["cpu_s"].iloc[-1] - perf["cpu_s"].iloc[0]
                dconf = perf["confirmed"].iloc[-1] - perf["confirmed"].iloc[0]
                cpu_per_conf = (dcpu / dconf * 1000) if dconf > 0 else np.nan
                mean_tips = perf["tips"].mean()
                max_tips = perf["tips"].max()
                rss = perf["rss_mb"].iloc[-1]

            rows.append({
                "experiment": r["experiment"],
                "cell": r["cell"],
                "load": r["load"],
                "rep": r["rep"],
                "rsu": rid,
                "rsu_count": meta.get("rsu_count"),
                "quorum": meta.get("quorum"),
                "offered_interval_s": meta.get("interval_s"),
                "offered_rate_nominal_tps": (1.0 / meta["interval_s"]
                                             if meta.get("interval_s")
                                             else np.nan),
                "offered_rate_measured_tps": offered_measured,
                "duration_s": round(span, 2) if span else np.nan,
                "local_accepted": len(local),
                "peer_accepted": len(peer),
                "rejected": len(rej),
                "confirmed": len(conf),
                "accepted_rate_tps": (len(local) + len(peer)) / span if span else np.nan,
                "confirmed_rate_tps": len(conf) / span if span else np.nan,
                "latency_ms_median": lat.median() if len(lat) else np.nan,
                "latency_ms_mean": lat.mean() if len(lat) else np.nan,
                "latency_ms_p95": lat.quantile(0.95) if len(lat) else np.nan,
                "quorum_wait_ms_median": qw.median() if len(qw) else np.nan,
                "cw_wait_ms_median": cww.median() if len(cww) else np.nan,
                "binding_cw_share": cw_share,
                "pow_ms_median": pw.median() if len(pw) else np.nan,
                "cpu_ms_per_confirmed": cpu_per_conf,
                "mean_tips": mean_tips,
                "max_tips": max_tips,
                "rss_mb": rss,
            })
    return pd.DataFrame(rows)


def build_t2(t1):
    metrics = ["confirmed_rate_tps", "accepted_rate_tps",
               "latency_ms_median", "latency_ms_p95",
               "quorum_wait_ms_median", "cw_wait_ms_median",
               "binding_cw_share", "offered_rate_measured_tps",
               "pow_ms_median", "cpu_ms_per_confirmed",
               "mean_tips", "rejected"]
    rows = []
    for (exp, cell, load), grp in t1.groupby(["experiment", "cell", "load"]):
        # one value per repetition: average across RSUs within a run first
        per_rep = grp.groupby("rep")[metrics].mean()
        rec = {"experiment": exp, "cell": cell, "load": load,
               "reps": len(per_rep)}
        for m in metrics:
            mean, hw, n = ci95(per_rep[m])
            rec[f"{m}_mean"] = mean
            rec[f"{m}_ci95"] = hw
            rec[f"{m}_n"] = n
        rows.append(rec)
    return pd.DataFrame(rows)


def build_t3(runs):
    rows = []
    for r in runs:
        sets = r["confirmed_sets"]
        if len(sets) < 2:
            continue
        ids = sorted(sets)
        union = set().union(*sets.values())
        inter = set(sets[ids[0]]).intersection(*[sets[i] for i in ids[1:]])
        pairs = []
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                a, b = sets[ids[i]], sets[ids[j]]
                u = len(a | b)
                pairs.append(len(a & b) / u if u else 1.0)
        rows.append({
            "experiment": r["experiment"], "cell": r["cell"],
            "load": r["load"], "rep": r["rep"],
            "rsus": len(ids),
            **{f"confirmed_{i}": len(sets[i]) for i in ids},
            "union": len(union),
            "intersection": len(inter),
            "disagreement": len(union) - len(inter),
            "jaccard_min": min(pairs) if pairs else np.nan,
            "jaccard_mean": float(np.mean(pairs)) if pairs else np.nan,
            "agreement_ratio": len(inter) / len(union) if union else np.nan,
        })
    return pd.DataFrame(rows)


# --------------------------------------------------------------------
# figures
# --------------------------------------------------------------------

def save(fig, name):
    FIGS.mkdir(exist_ok=True)
    for ext in ("png", "pdf"):
        fig.savefig(FIGS / f"{name}.{ext}", dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"  {name}")


def f1(t1, show_baselines=True):
    # Measured baselines (your own runs of another system on the same
    # hardware) live under results/baseline/ and are plotted beside the
    # proposed system, because they ARE comparable.
    d = t1[t1["experiment"].isin(["configs", "baseline", "hardware"])]
    if d.empty:
        return
    per_rep = d.groupby(["cell", "rep"])[
        ["confirmed_rate_tps", "latency_ms_median",
         "quorum_wait_ms_median"]].mean().reset_index()
    cells = sorted(per_rep["cell"].unique())

    fig, ax = plt.subplots(1, 3, figsize=(14, 4))
    for k, (metric, label) in enumerate([
            ("confirmed_rate_tps", "Confirmed throughput (tx/s)"),
            ("latency_ms_median", "Median confirmation latency (ms)")]):
        means, errs = [], []
        for c in cells:
            m, h, _ = ci95(per_rep[per_rep["cell"] == c][metric])
            means.append(m)
            errs.append(0 if math.isnan(h) else h)
        ax[k].bar(cells, means, yerr=errs, capsize=4,
                  color="#4C72B0" if k == 0 else "#DD8452")
        ax[k].set_ylabel(label)
        ax[k].set_xlabel("Configuration")
        ax[k].grid(axis="y", alpha=0.3)
        ax[k].tick_params(axis="x", rotation=15)
    # third panel: where the latency actually goes
    q_means, q_errs, t_means = [], [], []
    for c in cells:
        g = per_rep[per_rep["cell"] == c]
        qm, qh, _ = ci95(g["quorum_wait_ms_median"])
        tm, _, _ = ci95(g["latency_ms_median"])
        q_means.append(qm)
        q_errs.append(0 if math.isnan(qh) else qh)
        t_means.append(tm)
    x = np.arange(len(cells))
    ax[2].bar(x, t_means, 0.55, label="Total (incl. approver wait)",
              color="#CCCCCC")
    ax[2].bar(x, q_means, 0.55, yerr=q_errs, capsize=4,
              label="RSU quorum (from RSU arrival)", color="#4C72B0")
    ax[2].set_xticks(x)
    ax[2].set_xticklabels(cells, rotation=15)
    ax[2].set_yscale("log")
    ax[2].set_ylabel("Median latency (ms, log scale)")
    ax[2].set_xlabel("Configuration")
    ax[2].legend(fontsize=8)
    ax[2].grid(axis="y", alpha=0.3)

    # Reported baselines from other papers: dashed reference lines only,
    # with the citation in the label and the conditions in the caption.
    # They are NOT bars: the setups are not comparable.
    if show_baselines:
        import baselines as B
        # F1 throughput is bounded by the OFFERED load (one vehicle every
        # few seconds), not by system capacity, so a published capacity
        # ceiling next to it compares two different quantities. Those
        # belong on F2 against the saturation point. Here: latency only,
        # and only entries you have verified against the source paper.
        for k, metric in ((1, "latency_ms"),):
            rows = [b for b in B.for_metric(metric) if b.get("verified")]
            for i, b in enumerate(rows):
                ax[k].axhline(b["value"], ls="--", lw=1.2,
                              color=f"C{i + 2}",
                              label=f"{b['system']}: {b['value']:g} "
                                    f"[reported, other setup]")
            if rows:
                ax[k].set_yscale("log")
                ax[k].legend(fontsize=6, loc="best")
                B.warn_unverified(rows, f"F1 panel {k + 1}")

    n_reps = per_rep.groupby("cell")["rep"].nunique().min()
    ci_note = ("mean, 95% CI" if n_reps >= 2
               else "n=1 run - NO confidence interval yet")
    fig.suptitle(f"F1  Confirmed throughput and confirmation latency "
                 f"({ci_note})")
    fig.tight_layout()
    save(fig, "F1_throughput_latency")


def f2(t1):
    d = t1[t1["experiment"] == "load"]
    if d.empty:
        return
    d = d.copy()
    d["offered"] = d["offered_rate_measured_tps"].fillna(
        d["offered_rate_nominal_tps"])
    per_rep = d.groupby(["load", "rep"])[
        ["accepted_rate_tps", "confirmed_rate_tps",
         "offered"]].mean().reset_index()
    per_rep = per_rep.sort_values("offered")
    xs = sorted(per_rep["offered"].dropna().unique())

    fig, ax = plt.subplots(figsize=(6.5, 4.2))
    for metric, label, style in [
            ("accepted_rate_tps", "Accepted", "o-"),
            ("confirmed_rate_tps", "Confirmed", "s--")]:
        means, errs = [], []
        for x in xs:
            m, h, _ = ci95(per_rep[per_rep["offered"] == x][metric])
            means.append(m)
            errs.append(0 if math.isnan(h) else h)
        ax.errorbar(xs, means, yerr=errs, fmt=style, capsize=3, label=label)
    ax.plot(xs, xs, ":", color="gray", label="Offered (ideal)")
    ax.set_xlabel("Measured offered load (tx/s, from the vehicle side)")
    ax.set_ylabel("Rate (tx/s)")
    ax.set_title("F2  Saturation curve, 3-RSU configuration")
    ax.legend()
    ax.grid(alpha=0.3)
    save(fig, "F2_saturation")


def f3(runs):
    """CPU per confirmed transaction vs. ledger size, per RSU."""
    fig, ax = plt.subplots(figsize=(7, 4.4))
    points = {}
    for r in runs:
        if r["experiment"] not in ("configs", "hardware"):
            continue
        for rid, perf in r["perf"].items():
            if len(perf) < 5:
                continue
            p = perf.copy()
            p["d_cpu"] = p["cpu_s"].diff()
            p["d_conf"] = p["confirmed"].diff()
            p = p[p["d_conf"] > 0]
            if p.empty:
                continue
            y = p["d_cpu"] / p["d_conf"] * 1000
            points.setdefault(rid, []).append((p["tx_count"], y))
    if not points:
        plt.close(fig)
        return

    for i, (rid, chunks) in enumerate(sorted(points.items())):
        xs = pd.concat([c[0] for c in chunks])
        ys = pd.concat([c[1] for c in chunks])
        color = f"C{i}"
        ax.scatter(xs, ys, s=10, alpha=0.3, color=color)
        # binned median shows the trend without the per-interval noise
        bins = np.linspace(xs.min(), xs.max(), 9)
        idx = np.digitize(xs, bins)
        bx, by = [], []
        for b in range(1, len(bins) + 1):
            m = ys[idx == b]
            if len(m) >= 3:
                bx.append(xs[idx == b].median())
                by.append(m.median())
        ax.plot(bx, by, "-o", color=color, lw=2, ms=4,
                label=f"{rid} (binned median)")

    ax.set_xlabel("Ledger size (transactions held by the RSU)")
    ax.set_ylabel("CPU per confirmed transaction (ms)")
    ax.set_title("F3  RSU confirmation CPU cost vs. ledger size")
    ax.legend(fontsize=8)
    ax.grid(alpha=0.3)
    save(fig, "F3_cpu_vs_ledger")


def f4(t3):
    if t3.empty:
        return
    d = t3[t3["experiment"].isin(["configs", "load", "faults"])]
    if d.empty:
        return
    grp = d.groupby("cell")
    cells = sorted(grp.groups)
    means, errs = [], []
    for c in cells:
        m, h, _ = ci95(grp.get_group(c)["agreement_ratio"])
        means.append(m)
        errs.append(0 if math.isnan(h) else h)

    fig, ax = plt.subplots(figsize=(6.5, 4.2))
    ax.bar(cells, means, yerr=errs, capsize=4, color="#55A868")
    ax.axhline(1.0, color="gray", ls=":")
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("Confirmed-set agreement  |∩| / |∪|")
    ax.set_xlabel("Configuration / scenario")
    ax.set_title("F4  Replica agreement across RSUs (mean, 95% CI)")
    ax.tick_params(axis="x", rotation=15)
    ax.grid(axis="y", alpha=0.3)
    save(fig, "F4_replica_agreement")


def f5(runs):
    picked = [r for r in runs if r["experiment"] == "faults"]
    if not picked:
        return
    scenarios = sorted({r["cell"] for r in picked})
    fig, axes = plt.subplots(len(scenarios), 1,
                             figsize=(7.5, 3.4 * len(scenarios)),
                             squeeze=False)
    for k, sc in enumerate(scenarios):
        ax = axes[k][0]
        r = [x for x in picked if x["cell"] == sc][0]
        for rid, ev in sorted(r["events"].items()):
            conf = ev[ev["event"] == "NETWORK_CONFIRMED"]
            if conf.empty:
                continue
            ax.step(conf["elapsed_s"], range(1, len(conf) + 1),
                    where="post", label=rid)
        for f in r["meta"].get("faults", []):
            color = {"partition": "red", "kill": "red",
                     "heal": "green", "restart": "green"}.get(f["action"], "gray")
            ax.axvline(f["t_s"], color=color, ls="--", alpha=0.7)
            ax.text(f["t_s"], 0.02, f" {f['action']} {f['rsu']}",
                    rotation=90, fontsize=7, color=color,
                    transform=ax.get_xaxis_transform(), va="bottom")
        ax.set_title(f"F5  Availability and recovery - {sc}")
        ax.set_xlabel("Time (s)")
        ax.set_ylabel("Cumulative confirmations")
        ax.legend(fontsize=8)
        ax.grid(alpha=0.3)
    fig.tight_layout()
    save(fig, "F5_availability_recovery")


def detection_rates(run):
    """TPR/FPR from ground truth vs. what the RSU did with each txid."""
    lab = run.get("labels")
    if lab is None or lab.empty:
        return None
    ev = pd.concat(run["events"].values()) if run["events"] else None
    if ev is None or ev.empty:
        return None
    rejected = set(ev[ev["event"].isin(["REJECTED", "PEER_REJECT"])]["txid"])
    accepted = set(ev[ev["event"] == "LOCAL_ACCEPT"]["txid"])

    lab = lab[lab["submitted"] == 1]
    mal = lab[lab["attack"] != "none"]
    hon = lab[lab["attack"] == "none"]
    seen_mal = mal[mal["txid"].isin(rejected | accepted)]
    seen_hon = hon[hon["txid"].isin(rejected | accepted)]

    tp = seen_mal["txid"].isin(rejected).sum()
    fn = len(seen_mal) - tp
    fp = seen_hon["txid"].isin(rejected).sum()
    tn = len(seen_hon) - fp
    return {
        "attack": run["meta"].get("attack", run["cell"]),
        "rep": run["rep"],
        "malicious": len(seen_mal), "honest": len(seen_hon),
        "TP": int(tp), "FN": int(fn), "FP": int(fp), "TN": int(tn),
        "TPR": tp / len(seen_mal) if len(seen_mal) else np.nan,
        "FPR": fp / len(seen_hon) if len(seen_hon) else np.nan,
    }


def f6(runs):
    att = [r for r in runs if r["experiment"] == "attacks"]
    if not att:
        return
    rates = [x for x in (detection_rates(r) for r in att) if x]
    rates = pd.DataFrame(rates)

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))

    # left: trust trajectories from one representative run per attack
    ax = axes[0]
    for r in att:
        if r["rep"] != "rep1":
            continue
        ev = r["events"].get("RSU1")
        if ev is None or "trust_score" not in ev:
            continue
        attackers = set()
        if r.get("labels") is not None:
            attackers = set(
                r["labels"][r["labels"]["attack"] != "none"]["creator"])
        for creator, g in ev.dropna(subset=["trust_score"]).groupby("creator"):
            if not attackers or creator not in attackers:
                continue
            ax.plot(g["elapsed_s"], g["trust_score"],
                    label=f"{r['meta'].get('attack', r['cell'])}")
    # one honest baseline
    for r in att:
        if r["rep"] != "rep1":
            continue
        ev = r["events"].get("RSU1")
        if ev is None or r.get("labels") is None:
            continue
        attackers = set(r["labels"][r["labels"]["attack"] != "none"]["creator"])
        honest = ev[(~ev["creator"].isin(attackers)) &
                    ev["trust_score"].notna()]
        if not honest.empty:
            g = honest[honest["creator"] == honest["creator"].iloc[0]]
            ax.plot(g["elapsed_s"], g["trust_score"], "k--",
                    label="honest vehicle")
            break
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Trust score")
    ax.set_title("Trust trajectories (attacker vs. honest)")
    ax.legend(fontsize=8)
    ax.grid(alpha=0.3)

    # right: TPR / FPR per attack type
    ax = axes[1]
    if not rates.empty:
        cells = sorted(rates["attack"].unique())
        x = np.arange(len(cells))
        for off, metric, color in [(-0.2, "TPR", "#4C72B0"),
                                   (0.2, "FPR", "#C44E52")]:
            means, errs = [], []
            for c in cells:
                m, h, _ = ci95(rates[rates["attack"] == c][metric])
                means.append(m)
                errs.append(0 if math.isnan(h) else h)
            ax.bar(x + off, means, 0.4, yerr=errs, capsize=3,
                   label=metric, color=color)
        ax.set_xticks(x)
        ax.set_xticklabels(cells, rotation=15)
        ax.set_ylim(0, 1.05)
        ax.set_ylabel("Rate")
        ax.set_title("Detection rate by attack type")
        ax.legend()
        ax.grid(axis="y", alpha=0.3)
    fig.suptitle("F6  Vehicle trust trajectories and attack detection")
    fig.tight_layout()
    save(fig, "F6_trust_and_detection")

    TABLES.mkdir(exist_ok=True)
    rates.to_csv(TABLES / "T4_detection_rates.csv", index=False)


def f7(runs, profile_key, board_overhead):
    """PoW time and the datasheet-derived energy interval per transaction."""
    from energy_model import ENERGY_PROFILES, energy_for_row, describe

    profile = dict(ENERGY_PROFILES[profile_key])
    profile["board_overhead_mA"] = board_overhead

    rows = []
    seen = set()          # one sample per (run, txid)
    for r in runs:
        for rid, ev in r["events"].items():
            if ev.empty or "pow_time_ms" not in ev.columns:
                continue
            # Only the RSU that received the submission holds the
            # device-side fields; peers get the replicated copy.
            own = ev
            if "origin_rsu" in ev.columns:
                own = ev[ev["origin_rsu"] == rid]
            # If this RSU received nothing directly (e.g. only a peer's
            # log was collected), fall back to the replicated copies:
            # they carry the same device-side fields.
            if own.empty:
                own = ev
            for _, row in own.iterrows():
                # Each transaction appears on several rows (LOCAL_ACCEPT,
                # NETWORK_CONFIRMED) and on every RSU. Counting rows
                # instead of transactions inflated n about four-fold.
                key = (str(r["dir"]), row.get("txid"))
                if key in seen:
                    continue
                seen.add(key)
                if pd.to_numeric(pd.Series([row.get("pow_time_ms")]),
                                 errors="coerce").fillna(0).iloc[0] <= 0:
                    continue
                dev = str(row.get("device", "") or profile_key)
                if dev and dev in ENERGY_PROFILES and dev != profile_key:
                    p = dict(ENERGY_PROFILES[dev])
                    p["board_overhead_mA"] = board_overhead
                else:
                    p = profile
                lo, hi, parts = energy_for_row(row, p)
                rows.append({"txid": row.get("txid", ""),
                             "_has_sign": int(pd.notna(
                                 pd.to_numeric(pd.Series(
                                     [row.get("sign_time_ms")]),
                                     errors="coerce").iloc[0])),
                             "pow_ms": float(row["pow_time_ms"]),
                             "E_lo_mJ": lo, "E_hi_mJ": hi, **{
                                 f"{k}_lo": v[0] for k, v in parts.items()},
                             **{f"{k}_hi": v[1] for k, v in parts.items()}})
    if not rows:
        return
    d = pd.DataFrame(rows)

    # FIX: one transaction appears on several rows - LOCAL_ACCEPT and
    # NETWORK_CONFIRMED at the origin, plus the replicated copies at every
    # peer RSU. Counting rows counted each transaction 2-4 times. Keep one
    # row per txid, preferring the one carrying the device timings.
    if "txid" in d.columns:
        d = (d.sort_values("_has_sign", ascending=False)
              .drop_duplicates(subset="txid", keep="first"))
    d = d.drop(columns=[c for c in ("txid", "_has_sign") if c in d.columns])

    fig, axes = plt.subplots(1, 3, figsize=(15, 4.2))

    axes[0].hist(d["pow_ms"], bins=40, color="#4C72B0")
    axes[0].set_xlabel("PoW solve time (ms)")
    axes[0].set_ylabel("Transactions")
    axes[0].set_title(f"PoW time  (n={len(d)}, "
                      f"median={d['pow_ms'].median():.1f} ms)")
    axes[0].grid(alpha=0.3)

    axes[1].hist([d["E_lo_mJ"], d["E_hi_mJ"]], bins=30,
                 color=["#55A868", "#C44E52"],
                 label=["lower bound", "upper bound"])
    axes[1].set_xlabel("Energy per transaction (mJ)")
    axes[1].set_ylabel("Transactions")
    axes[1].set_title("Datasheet energy interval")
    axes[1].legend(fontsize=8)
    axes[1].grid(alpha=0.3)

    phases = [c[:-3] for c in d.columns if c.endswith("_lo")
              and c not in ("E_lo_mJ",)]
    phases = [p_ for p_ in phases if p_ != "E"]
    if phases:
        lo_means = [d[f"{p_}_lo"].mean() for p_ in phases]
        hi_means = [d[f"{p_}_hi"].mean() for p_ in phases]
        x = np.arange(len(phases))
        axes[2].bar(x - 0.2, lo_means, 0.4, label="lower", color="#55A868")
        axes[2].bar(x + 0.2, hi_means, 0.4, label="upper", color="#C44E52")
        axes[2].set_xticks(x)
        axes[2].set_xticklabels(phases, rotation=15)
        axes[2].set_ylabel("Mean energy per transaction (mJ)")
        axes[2].set_title("Where the energy goes")
        axes[2].legend(fontsize=8)
        axes[2].grid(axis="y", alpha=0.3)

    import baselines as B
    erows = B.for_metric("energy_mj")
    for i, b in enumerate(erows):
        axes[1].axvline(b["value"], ls="--", lw=1.2, color=f"C{i + 2}",
                        label=f"{b['system']} [reported]")
    if erows:
        axes[1].legend(fontsize=6)
        B.warn_unverified(erows, "F7 energy panel")

    fig.suptitle("F7  Proof-of-work time and datasheet-derived energy "
                 f"interval  [{profile['name']}]")
    fig.tight_layout()
    save(fig, "F7_pow_time_energy")

    TABLES.mkdir(exist_ok=True)
    summary = d.describe().T
    summary.to_csv(TABLES / "T5_energy_per_transaction.csv")
    print(describe(profile))
    print(f"  energy per transaction: {d['E_lo_mJ'].mean():.2f} - "
          f"{d['E_hi_mJ'].mean():.2f} mJ (mean of bounds, n={len(d)})")


def f8(runs):
    fig, ax = plt.subplots(figsize=(7, 4.2))
    drawn = 0
    for r in runs:
        if (r["experiment"] not in ("configs", "hardware")
                or r["rep"] != "rep1"):
            continue
        perf = r["perf"].get("RSU1")
        if perf is None or perf.empty:
            continue
        # Drop the idle lead-in before the first transaction arrived
        # (boot, handshakes, NTP); it is setup time, not DAG behaviour.
        active = perf[perf["tx_count"] > 0]
        if active.empty:
            continue
        t0 = active["t_s"].iloc[0]
        ax.plot(active["t_s"] - t0, active["tips"],
                label=r["cell"], alpha=0.85)
        ax.axhline(active["tips"].mean(), ls=":", color="gray",
                   label=f"mean {active['tips'].mean():.2f}")
        drawn += 1
    if not drawn:
        plt.close(fig)
        return
    ax.set_xlabel("Time since first transaction (s)")
    ax.set_ylabel("Tip-set size")
    ax.set_title("F8  DAG width (tip-set size) over time, RSU1")
    ax.legend(fontsize=8)
    ax.grid(alpha=0.3)
    save(fig, "F8_tip_set_size")


def f9(runs):
    """Rejections by validation stage, broken down by exact reason."""
    counts, received = {}, 0
    for r in runs:
        for rid, ev in r["events"].items():
            # denominator: every transaction this RSU received directly
            # Only submissions this RSU received from a vehicle count:
            # replicated copies (state PEER_ACCEPTED) are the same
            # transactions seen again and would inflate the denominator.
            direct = ev[
                ((ev["event"] == "LOCAL_ACCEPT") &
                 (ev["state"] != "PEER_ACCEPTED")) |
                (ev["event"] == "REJECTED")
            ]
            received += direct["txid"].nunique()
            rej = ev[ev["event"].isin(["REJECTED", "PEER_REJECT"])]
            for reason in rej["details"].fillna(""):
                reason = str(reason).strip() or "unspecified"
                key = f"{stage_of(reason)}  -  {reason}"
                counts[key] = counts.get(key, 0) + 1
    if not counts:
        return
    items = sorted(counts.items())
    fig, ax = plt.subplots(figsize=(8.5, max(3, 0.55 * len(items) + 1.5)))
    bars = ax.barh([k for k, _ in items], [v for _, v in items],
                   color="#C44E52")
    for bar, (_, v) in zip(bars, items):
        pct = f"  {v}" + (f"  ({100 * v / received:.1f}% of received)"
                          if received else "")
        ax.text(bar.get_width(), bar.get_y() + bar.get_height() / 2,
                pct, va="center", fontsize=8)
    ax.set_xlabel("Rejected transactions")
    ax.set_title("F9  Rejections by validation stage and reason (all runs)")
    ax.grid(axis="x", alpha=0.3)
    ax.set_xlim(0, max(v for _, v in items) * 1.45)
    fig.tight_layout()
    save(fig, "F9_rejections_by_stage")


# --------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-baselines", action="store_true",
                    help="omit the reported-baseline reference lines")
    ap.add_argument("--device", default="esp32",
                    choices=["esp32", "esp8266"],
                    help="datasheet profile for the vehicle node; a run "
                         "that reports its own device field overrides it")
    ap.add_argument("--board-overhead-ma", type=float, default=0.0,
                    help="extra current drawn by the dev board (USB "
                         "bridge, regulator, LEDs) on top of the chip "
                         "datasheet figures")
    args = ap.parse_args()

    runs = load_runs()
    if not runs:
        print("No results found under", RESULTS)
        print("For hardware runs, register each run first with "
              "collect_hardware_run.py (it creates results/...).")
        return
    print(f"Loaded {len(runs)} runs")

    TABLES.mkdir(exist_ok=True)
    t1 = build_t1(runs)
    t1.to_csv(TABLES / "T1_per_run_raw.csv", index=False)
    t2 = build_t2(t1)
    t2.to_csv(TABLES / "T2_aggregated_ci95.csv", index=False)
    t3 = build_t3(runs)
    t3.to_csv(TABLES / "T3_replica_agreement.csv", index=False)
    print(f"Tables: T1={len(t1)} rows, T2={len(t2)} rows, T3={len(t3)} rows")

    print("Figures:")
    f1(t1, show_baselines=not args.no_baselines)
    f2(t1)
    f3(runs)
    f4(t3)
    f5(runs)
    f6(runs)
    f7(runs, args.device, args.board_overhead_ma)
    f8(runs)
    f9(runs)


if __name__ == "__main__":
    main()
