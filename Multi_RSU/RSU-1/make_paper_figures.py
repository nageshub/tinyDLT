#!/usr/bin/env python3
"""
make_paper_figures.py - clean paper figures from ONE result set (the
patched server). Run inside the folder that holds the patched-server runs:

    cd ~/Documents/multirsu_fix          # or wherever those runs are
    python3 analyse_results.py --device esp32    # writes tables/T2_...
    python3 make_paper_figures.py

Writes
  Fig5_load.png / .pdf   (a) throughput vs per-vehicle interval, with the
                         closed-loop prediction of Eq. (13);
                         (b) latency components vs throughput, with the
                         model E[L]/lambda + Delta/2
  Fig6_rsu_cost.png/.pdf (a) RSU CPU per confirmed transaction vs ledger
                         size, all RSUs; (b) busiest-RSU utilisation over
                         time for every load
and prints every number shown, so the text can quote them.
"""
import argparse, glob, json, os, re
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ap = argparse.ArgumentParser()
ap.add_argument("--results", default="results")
ap.add_argument("--t2", default="tables/T2_aggregated_ci95.csv")
ap.add_argument("--delta", type=float, default=1.0,
                help="period of the confirmation re-check timer (s)")
args = ap.parse_args()
M, WIN, DEFAULT_Z = 3, 30.0, 7.5

plt.rcParams.update({"font.family": "serif", "font.size": 9,
                     "axes.titlesize": 9.5, "legend.fontsize": 7.5})

def num(s):
    return pd.to_numeric(s, errors="coerce")

def per_vehicle_z(load, meta):
    """Per-vehicle interval, robust to either --interval convention."""
    if load == "load-esp32":
        return DEFAULT_Z
    tag = float(re.findall(r"[\d.]+", load)[0])          # aggregate label
    v = meta.get("vehicles", M) or M
    if meta.get("interval_is_aggregate"):
        return v * float(meta["interval_s"])
    iv = float(meta.get("interval_s", tag))
    return iv if abs(iv - v * tag) < abs(iv - tag) else v * iv

runs = []
for mp in sorted(glob.glob(f"{args.results}/*/3rsu/*/rep*/run.json")):
    d = os.path.dirname(mp)
    exp, cell, load, rep = d.split(os.sep)[-4:]
    if exp not in ("configs", "load"):
        continue
    meta = json.load(open(mp))
    runs.append(dict(exp=exp, load=load, z=per_vehicle_z(load, meta),
        perf={os.path.basename(f)[5:-4]: pd.read_csv(f)
              for f in sorted(glob.glob(f"{d}/perf_RSU*.csv"))},
        logs={os.path.basename(f)[5:-4]: pd.read_csv(f, low_memory=False)
              for f in sorted(glob.glob(f"{d}/logs_RSU*.csv"))}))
if not runs:
    raise SystemExit(f"no 3-RSU configs/load runs under {args.results}/")
runs.sort(key=lambda r: r["z"])
print(f"{len(runs)} runs:", ", ".join(f"{r['load']} (Z={r['z']:.2f} s)" for r in runs))

t2 = pd.read_csv(args.t2)
t2 = t2[((t2.experiment == "configs") & (t2.cell == "3rsu")) | (t2.experiment == "load")]
def t2row(load):
    r = t2[t2.load == load]
    return r.iloc[0] if len(r) else None
def ci(r, col):
    c = col.replace("_mean", "_ci95")
    v = r.get(c, np.nan) if r is not None else np.nan
    return 0.0 if pd.isna(v) else float(v)

def device_times(r):
    ev = pd.concat(r["logs"].values(), ignore_index=True)
    c = ev[ev["event"] == "NETWORK_CONFIRMED"].drop_duplicates("txid")
    return sum(num(c.get(k)).mean() for k in
               ("tip_wait_ms", "pow_time_ms", "sign_time_ms")) / 1000

def active(p):
    p = p.copy()
    for col in ("t_s", "confirmed", "cpu_s", "tx_count"):
        p[col] = num(p[col])
    p = p.dropna(subset=["t_s", "confirmed", "cpu_s"]).sort_values("t_s")
    if (p["confirmed"] > 0).sum() < 3:
        return None, None
    t0 = p.loc[p["confirmed"] > 0, "t_s"].iloc[0]
    last = p.index[p["confirmed"].diff() > 0][-1]
    a = p.loc[:last]
    return a[a["t_s"] >= t0], t0

colours = plt.get_cmap("viridis")(np.linspace(0, 0.85, len(runs)))
def lab(r):
    return "U(5, 10) s (default)" if r["exp"] == "configs" else f"Z = {r['z']:.1f} s"

# ============================================================ Figure 5
fig, (a, b) = plt.subplots(1, 2, figsize=(7.2, 3.3))
rows = []
for r in runs:
    t = t2row(r["load"])
    if t is None:
        print("  (not in T2, skipped in Fig. 5):", r["load"]); continue
    pred = M / (r["z"] + device_times(r))
    rows.append(dict(z=r["z"], acc=t.accepted_rate_tps_mean, conf=t.confirmed_rate_tps_mean,
                     acc_ci=ci(t, "accepted_rate_tps_mean"), conf_ci=ci(t, "confirmed_rate_tps_mean"),
                     pred=pred, lat=t.latency_ms_median_mean / 1000,
                     lat_ci=ci(t, "latency_ms_median_mean") / 1000,
                     cw=t.cw_wait_ms_median_mean / 1000, cw_ci=ci(t, "cw_wait_ms_median_mean") / 1000,
                     tq=t.quorum_wait_ms_median_mean / 1000, tq_ci=ci(t, "quorum_wait_ms_median_mean") / 1000,
                     model=t.mean_tips_mean / t.confirmed_rate_tps_mean + args.delta / 2))
f5 = pd.DataFrame(rows).sort_values("z")
zg = np.logspace(np.log10(0.15), np.log10(10), 200)
a.plot(zg, np.minimum(M / zg, 16), ":", color="0.45", lw=1, label="Nominal offered load M/Z")
a.plot(f5.z, f5.pred, "-", color="0.25", lw=1, marker="x", ms=6, label="Eq. (13), measured device times")
a.errorbar(f5.z, f5.acc, yerr=f5.acc_ci, fmt="o", ms=8, mfc="none", mew=1.4, color="#1f4e79",
           capsize=2, label="Accepted")
a.errorbar(f5.z, f5.conf, yerr=f5.conf_ci, fmt="s", ms=3.5, color="#c55a11", capsize=2, label="Confirmed")
a.set_xscale("log"); a.set_xlim(0.15, 10); a.set_ylim(0, max(4.5, f5.pred.max() * 1.25))
a.set_xticks([0.2, 0.5, 1, 2, 5, 10]); a.set_xticklabels(["0.2", "0.5", "1", "2", "5", "10"])
a.set_xlabel("Per-vehicle interval Z (s)"); a.set_ylabel("Rate (tx/s)")
a.set_title("(a) Throughput"); a.grid(alpha=0.3, which="both")

lam = f5.conf
b.errorbar(lam, f5.lat, yerr=f5.lat_ci, fmt="o", ms=5, color="#1f4e79", capsize=2, label="End-to-end latency")
b.errorbar(lam, f5.cw, yerr=f5.cw_ci, fmt="s", ms=4.5, color="#c55a11", capsize=2, label="Approval wait")
b.plot(lam, f5.model, "x", ms=7, mew=1.6, color="k", label="Model E[L]/λ + Δ/2")
b.errorbar(lam, f5.tq, yerr=f5.tq_ci, fmt="^", ms=4.5, color="#548235", capsize=2, label="Quorum time")
b.set_yscale("log"); b.set_xlim(0, lam.max() * 1.1)
b.set_xlabel("Confirmed throughput λ (tx/s)"); b.set_ylabel("Median time (s)")
b.set_title("(b) Latency components"); b.grid(alpha=0.3, which="both")

ha, la = a.get_legend_handles_labels(); hb, lb = b.get_legend_handles_labels()
fig.legend(ha + hb, la + lb, loc="lower center", ncol=4, frameon=False)
fig.tight_layout(rect=[0, 0.13, 1, 1])
for ext in ("png", "pdf"):
    fig.savefig(f"Fig5_load.{ext}", dpi=300)
print("\nFig. 5 numbers")
for _, x in f5.iterrows():
    print(f"  Z={x.z:4.1f}s  accepted={x.acc:.3f}  confirmed={x.conf:.3f}  Eq13={x.pred:.3f} "
          f"({100 * (x.pred / x.conf - 1):+.1f}%)  latency={x.lat:.2f}s  approval={x.cw:.2f}s  "
          f"model={x.model:.2f}s ({100 * (x.model / x.cw - 1):+.1f}%)  Tq={x.tq:.2f}s")

# ============================================================ Figure 6
fig, (a, b) = plt.subplots(1, 2, figsize=(7.2, 3.3))
rsu_col = {"RSU1": "#1f4e79", "RSU2": "#c55a11", "RSU3": "#548235"}
pts = []
for r in runs:
    for rid, p in r["perf"].items():
        act, t0 = active(p)
        if act is None:
            continue
        act = act.assign(w=((act["t_s"] - t0) // WIN).astype(int))
        for _, g in act.groupby("w"):
            dc = g["confirmed"].iloc[-1] - g["confirmed"].iloc[0]
            du = g["cpu_s"].iloc[-1] - g["cpu_s"].iloc[0]
            if dc >= 5:
                pts.append((rid, g["tx_count"].mean(), 1000 * du / dc))
pts = pd.DataFrame(pts, columns=["rsu", "n", "D"])
print("\nFig. 6(a) CPU per confirmed transaction")
for rid, g in pts.groupby("rsu"):
    a.scatter(g.n, g.D, s=7, alpha=0.45, color=rsu_col.get(rid, "0.3"), label=f"{rid} (30-s windows)")
    slope, icpt = np.polyfit(g.n, g.D, 1)
    xs = np.array([0, g.n.max()])
    a.plot(xs, icpt + slope * xs, "-", lw=1.4, color=rsu_col.get(rid, "0.3"))
    print(f"  {rid}: mean {g.D.mean():.1f} ms, linear fit {icpt:.1f} ms + {1000 * slope:.2f} us/tx, "
          f"n up to {g.n.max():.0f}")
a.set_ylim(0, max(60, pts.D.quantile(0.99) * 1.5))
a.set_xlabel("Ledger size (transactions)"); a.set_ylabel("CPU per confirmed transaction (ms)")
a.set_title("(a) RSU cost vs ledger size"); a.grid(alpha=0.3)
a.legend(loc="upper right", frameon=False, markerscale=1.8)

print("\nFig. 6(b) busiest-RSU utilisation")
for r, col in zip(runs, colours):
    per = []
    for rid, p in r["perf"].items():
        act, t0 = active(p)
        if act is None:
            continue
        act = act.assign(w=((act["t_s"] - t0) // WIN).astype(int))
        for w, g in act.groupby("w"):
            dt = g["t_s"].iloc[-1] - g["t_s"].iloc[0]
            if dt > 0 and len(g) >= 2:
                per.append((w, (g["cpu_s"].iloc[-1] - g["cpu_s"].iloc[0]) / dt))
    if not per:
        continue
    u = pd.DataFrame(per, columns=["w", "U"]).groupby("w")["U"].max()
    u = u.iloc[:-1] if len(u) > 2 else u
    b.plot((u.index + 0.5) * WIN / 60, u.values, color=col, lw=1.4, label=lab(r))
    print(f"  {lab(r):22s} max {u.max():.3f} cores, mean {u.mean():.3f}")
b.set_ylim(0, max(0.25, 1.2 * max(l.get_ydata().max() for l in b.get_lines()))); b.set_xlim(left=0)
b.set_xlabel("Time since first confirmation (min)"); b.set_ylabel("CPU, busiest RSU (cores)")
b.set_title("(b) RSU utilisation over time"); b.grid(alpha=0.3)
b.legend(loc="upper right", ncol=2, frameon=False, fontsize=7)
fig.tight_layout()
for ext in ("png", "pdf"):
    fig.savefig(f"Fig6_rsu_cost.{ext}", dpi=300)
print("\nwrote Fig5_load.png/.pdf and Fig6_rsu_cost.png/.pdf")
