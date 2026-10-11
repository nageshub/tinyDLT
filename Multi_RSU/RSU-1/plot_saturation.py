#!/usr/bin/env python3
"""
plot_saturation.py - Figures 5 and 6 of the tinyDLT paper.

Run on RSU1 from ~/Documents/multirsu:
    python3 plot_saturation.py                        # current results/
    python3 plot_saturation.py --compare results_fix  # overlay a second set
                                                      # (e.g. bounded-CW rerun)
Writes
  F5_saturation_time.png  time-resolved load runs, 30-s windows:
                          (a) confirmed throughput (mean over RSUs)
                          (b) CPU utilisation of the busiest RSU
                          (c) median tip wait reported by the vehicles
  F6_cost_vs_ledger.png   CPU per confirmed transaction vs ledger size,
                          every configs/load run, with linear and quadratic
                          fits (Eq. 16), one panel per RSU
and prints the numbers behind both figures.
"""
import argparse, glob, json, os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

WIN = 30.0
ap = argparse.ArgumentParser()
ap.add_argument("--results", default="results")
ap.add_argument("--label", default="measured implementation")
ap.add_argument("--compare", default=None)
ap.add_argument("--compare-label", default="bounded weight test")
args = ap.parse_args()

def num(s):
    return pd.to_numeric(s, errors="coerce")

def runs_in(root):
    out = []
    for mp in sorted(glob.glob(f"{root}/*/*/*/rep*/run.json")):
        d = os.path.dirname(mp)
        exp, cell, load, rep = d.split(os.sep)[-4:]
        if exp not in ("configs", "load") or cell != "3rsu":
            continue
        meta = json.load(open(mp))
        z = 7.5 if exp == "configs" else meta.get("vehicles", 3) * float(meta["interval_s"])
        perf = {os.path.basename(f)[5:-4]: pd.read_csv(f)
                for f in sorted(glob.glob(f"{d}/perf_RSU*.csv"))}
        logs = {os.path.basename(f)[5:-4]: pd.read_csv(f, low_memory=False)
                for f in sorted(glob.glob(f"{d}/logs_RSU*.csv"))}
        out.append(dict(name=f"{exp}/{load}/{rep}", exp=exp, z=z, perf=perf, logs=logs))
    return out

def active(p):
    p = p.copy()
    for c in ("t_s", "confirmed", "cpu_s", "tx_count"):
        p[c] = num(p[c])
    p = p.dropna(subset=["t_s", "confirmed", "cpu_s"]).sort_values("t_s")
    if (p["confirmed"] > 0).sum() < 3:
        return None, None
    t0 = p.loc[p["confirmed"] > 0, "t_s"].iloc[0]
    last = p.index[p["confirmed"].diff() > 0][-1]
    return p.loc[:last][p.loc[:last, "t_s"] >= t0], t0

def time_series(run):
    """Per 30-s window: X (mean over RSUs), U (max over RSUs), tip wait."""
    per = []
    t0s = {}
    for rid, p in run["perf"].items():
        a, t0 = active(p)
        if a is None:
            continue
        t0s[rid] = t0
        a = a.assign(w=((a["t_s"] - t0) // WIN).astype(int))
        for w, g in a.groupby("w"):
            if len(g) < 2:
                continue
            dt = g["t_s"].iloc[-1] - g["t_s"].iloc[0]
            if dt <= 0:
                continue
            per.append(dict(rsu=rid, w=w,
                            X=(g["confirmed"].iloc[-1] - g["confirmed"].iloc[0]) / dt,
                            U=(g["cpu_s"].iloc[-1] - g["cpu_s"].iloc[0]) / dt,
                            n=g["tx_count"].mean()))
    per = pd.DataFrame(per)
    if per.empty:
        return None
    ts = per.groupby("w").agg(X=("X", "mean"), U=("U", "max"), n=("n", "mean"))
    tips = []
    for rid, lg in run["logs"].items():
        if rid not in t0s:
            continue
        own = lg[(lg["event"] == "NETWORK_CONFIRMED") & (lg["origin_rsu"] == rid)]
        t = num(own["elapsed_s"]) - t0s[rid]
        tips.append(pd.DataFrame({"w": (t // WIN), "tip": num(own.get("tip_wait_ms"))}))
    if tips:
        tp = pd.concat(tips).dropna()
        ts["tip_ms"] = tp.groupby("w")["tip"].median()
    ts["t_min"] = (ts.index + 0.5) * WIN / 60
    return ts.iloc[:-1] if len(ts) > 2 else ts       # drop partial last window

def cost_points(runs):
    pts = []
    for r in runs:
        for rid, p in r["perf"].items():
            a, t0 = active(p)
            if a is None:
                continue
            a = a.assign(w=((a["t_s"] - t0) // WIN).astype(int))
            for _, g in a.groupby("w"):
                dc = g["confirmed"].iloc[-1] - g["confirmed"].iloc[0]
                du = g["cpu_s"].iloc[-1] - g["cpu_s"].iloc[0]
                if dc >= 5:
                    pts.append((rid, g["tx_count"].mean(), 1000 * du / dc))
    return pd.DataFrame(pts, columns=["rsu", "n", "D_ms"])

sets = [(args.label, runs_in(args.results), "-")]
if args.compare:
    sets.append((args.compare_label, runs_in(args.compare), "--"))

plt.rcParams.update({"font.family": "serif", "font.size": 8.5})

# ------------------------------------------------------------ Figure 5
fig, ax = plt.subplots(1, 3, figsize=(7.6, 2.7))
cmap = plt.get_cmap("viridis")
print("=== Figure 5 data (30-s windows) ===")
for label, runs, ls in sets:
    zs = sorted({r["z"] for r in runs})  # colour by interval
    for r in sorted(runs, key=lambda r: r["z"]):
        ts = time_series(r)
        if ts is None:
            continue
        col = cmap(zs.index(r["z"]) / max(1, len(zs) - 1) * 0.85)
        lab = (f"Z = {r['z']:.2f} s" if r["exp"] == "load" else "U(5,10) s") + \
              ("" if len(sets) == 1 else f" ({label})")
        ax[0].plot(ts.t_min, ts.X, ls, color=col, lw=1.2, label=lab)
        ax[1].plot(ts.t_min, ts.U, ls, color=col, lw=1.2)
        if "tip_ms" in ts:
            ax[2].plot(ts.t_min, ts.tip_ms / 1000, ls, color=col, lw=1.2)
        print(f"{label:28s} {r['name']:28s} first/last window: "
              f"X {ts.X.iloc[0]:.2f}->{ts.X.iloc[-1]:.2f} tx/s, "
              f"U {ts.U.iloc[0]:.2f}->{ts.U.iloc[-1]:.2f}, "
              f"ledger {ts.n.iloc[0]:.0f}->{ts.n.iloc[-1]:.0f}")
ax[1].axhline(1.0, color="0.4", ls=":", lw=1)
ax[0].set_ylabel("Confirmed throughput (tx/s)")
ax[1].set_ylabel("CPU, busiest RSU (cores)")
ax[2].set_ylabel("Median tip wait (s)")
for a_, t in zip(ax, ("(a) Throughput", "(b) RSU utilisation", "(c) Tip wait")):
    a_.set_xlabel("Time since first confirmation (min)")
    a_.set_title(t, fontsize=9)
    a_.grid(alpha=0.3)
    a_.set_xlim(left=0)
    a_.set_ylim(bottom=0)
ax[0].legend(fontsize=6, frameon=False, loc="upper right")
fig.tight_layout(w_pad=1.2)
fig.savefig("F5_saturation_time.png", dpi=300)
print("wrote F5_saturation_time.png")

# ------------------------------------------------------------ Figure 6
pts_sets = [(label, cost_points(runs), ls) for label, runs, ls in sets]
rsus = sorted(set().union(*[set(p.rsu) for _, p, _ in pts_sets]))
fig, ax = plt.subplots(1, len(rsus), figsize=(7.2, 2.5), sharey=True)
ax = np.atleast_1d(ax)
print("\n=== Figure 6 fits: D(n) per RSU ===")
for i, rid in enumerate(rsus):
    for k, (label, pts, ls) in enumerate(pts_sets):
        p = pts[pts.rsu == rid]
        if p.empty:
            continue
        ax[i].scatter(p.n, p.D_ms, s=5, alpha=0.4,
                      color=("#1f4e79" if k == 0 else "#c55a11"),
                      label=label if i == 0 else None)
        n, d = p.n.values, p.D_ms.values
        grid = np.linspace(0, n.max(), 200)
        for form, x, xg, sty in (("linear", n, grid, ":"), ("quadratic", n ** 2, grid ** 2, "-")):
            A = np.vstack([np.ones_like(x), x]).T
            coef, *_ = np.linalg.lstsq(A, d, rcond=None)
            r2 = 1 - ((d - A @ coef) ** 2).sum() / ((d - d.mean()) ** 2).sum()
            unit, scale = (("ms/tx", 1) if form == "linear" else ("us/tx^2", 1000))
            print(f"{rid} {label:28s} {form:9s} a={coef[0]:7.1f} ms  "
                  f"slope={scale * coef[1]:.4f} {unit:7s} R2={r2:.3f}")
            if k == 0 or form == "quadratic":
                ax[i].plot(grid, coef[0] + coef[1] * xg, sty, lw=1,
                           color=("k" if k == 0 else "#c55a11"),
                           label=(f"{form} fit" if (i == 0 and k == 0) else None))
    ax[i].set_title(rid, fontsize=9)
    ax[i].set_xlabel("Ledger size (transactions)")
    ax[i].grid(alpha=0.3)
ax[0].set_ylabel("CPU per confirmed tx (ms)")
ax[0].legend(fontsize=6.5, frameon=False, loc="upper left")
fig.tight_layout()
fig.savefig("F6_cost_vs_ledger.png", dpi=300)
print("wrote F6_cost_vs_ledger.png")
