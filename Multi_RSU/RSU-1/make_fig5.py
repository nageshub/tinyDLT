#!/usr/bin/env python3
"""
make_fig5.py - Figure 5 of the tinyDLT paper (load sweep, time-resolved).

    python3 make_fig5.py [tables_dir] [out.png]

Reads, from tables_dir (default: tables/):
  T2_aggregated_ci95.csv  (analyse_results.py)
  check_B.csv, check_C_fit.csv  (check_load_runs.py, which now writes them)
Panels: (a) confirmed throughput in each third of each run,
        (b) RSU CPU per confirmation vs ledger size with the Eq. (16) fits
            and the saturation thresholds 1/lambda of Eq. (14),
        (c) boards' tip wait vs ingress-RSU utilisation with t0/(1-U),
        (d) latency components vs run-average throughput with Eq. (11).
"""
import sys, os
import numpy as np, pandas as pd
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FixedLocator, ScalarFormatter, NullLocator

tdir = sys.argv[1] if len(sys.argv) > 1 else "tables"
out = sys.argv[2] if len(sys.argv) > 2 else "F5_load_sweep.png"
M = 3
T2 = pd.read_csv(os.path.join(tdir, "T2_aggregated_ci95.csv"))
B = pd.read_csv(os.path.join(tdir, "check_B.csv"))
C = pd.read_csv(os.path.join(tdir, "check_C_fit.csv"))
B["cell"] = B.run.str.split("/").str[2]
B["exp"] = B.run.str.split("/").str[0]

def z_of(cell, exp):
    return 7.5 if exp == "configs" else M * float(cell.split("-")[1].rstrip("s"))

plt.rcParams.update({"font.family": "serif", "font.size": 8.5})
fig, ax = plt.subplots(2, 2, figsize=(7.0, 5.6))
a, b, c, d = ax.ravel()
cells = (B.groupby(["exp", "cell"]).size().reset_index()
         .assign(Z=lambda f: [z_of(r.cell, r.exp) for r in f.itertuples()])
         .sort_values("Z"))
cmap = plt.get_cmap("viridis")
colors = {r.cell: cmap(i / max(1, len(cells) - 1)) for i, r in enumerate(cells.itertuples())}

# (a) throughput per third
for r in cells.itertuples():
    g = B[B.cell == r.cell].groupby("third").X_tps.mean()
    lbl = "U(5, 10) s" if r.exp == "configs" else f"Z = {r.Z:.2f} s"
    a.plot(g.index, g.values, "-o", ms=4, color=colors[r.cell], label=lbl)
a.set_xticks([1, 2, 3]); a.set_xticklabels(["0–3.3", "3.3–6.7", "6.7–10"])
a.set_xlabel("Interval of the 10-min run (min)")
a.set_ylabel("Confirmed throughput (tx/s)")
a.set_ylim(0, 4); a.set_title("(a) Throughput over the run", fontsize=9)
a.legend(fontsize=6.5, frameon=False, loc="lower left"); a.grid(alpha=0.3)

# (b) CPU per confirmation vs ledger size
mk = {"RSU1": "o", "RSU2": "s", "RSU3": "^"}
for rsu, g in B.groupby("rsu"):
    b.scatter(g.ledger_n, g.D_ms, marker=mk.get(rsu, "o"), s=16, facecolor="none",
              edgecolor="0.25", label=f"{rsu} (thirds)")
n = np.linspace(0, 1700, 200)
for r in C[C.model == "quadratic"].itertuples():
    b.plot(n, r.a_ms + r.slope * 1e-3 * n ** 2, lw=1, label=f"{r.rsu} fit, R² = {r.r2:.3f}")
for lam, ls in ((2.5, "--"), (1.0, ":")):
    b.axhline(1000 / lam, color="#c00000", ls=ls, lw=1)
    b.text(30, 1000 / lam + 15, f"1/λ, λ = {lam} tx/s", color="#c00000", fontsize=6.5)
b.set_xlim(0, 1700); b.set_ylim(0, 1100)
b.set_xlabel("Ledger size n (transactions)"); b.set_ylabel("CPU per confirmation D (ms)")
b.set_title("(b) Cost growth, Eq. (16)", fontsize=9)
b.legend(fontsize=6, frameon=False, loc="upper left", bbox_to_anchor=(0.0, 0.88)); b.grid(alpha=0.3)

# (c) tip wait vs utilisation
t = B.dropna(subset=["tip_wait_ms"])
t = t[t.U_cores > 0.05]
x = 1 / (1 - t.U_cores.values); y = t.tip_wait_ms.values
t0 = (x * y).sum() / (x * x).sum()
r2 = 1 - ((y - t0 * x) ** 2).sum() / ((y - y.mean()) ** 2).sum()
for r in cells.itertuples():
    g = t[t.cell == r.cell]
    if len(g):
        c.scatter(g.U_cores, g.tip_wait_ms, s=20, color=colors[r.cell])
u = np.linspace(0, 0.985, 200)
c.plot(u, t0 / (1 - u), "k-", lw=1, label=f"$t_0/(1-U)$, $t_0$ = {t0:.0f} ms, R² = {r2:.2f}")
c.set_xlim(0, 1); c.set_ylim(0, 2000)
c.set_xlabel("Ingress-RSU utilisation U (cores)"); c.set_ylabel("Tip wait at the vehicle (ms)")
c.set_title("(c) Back-pressure through the tip request", fontsize=9)
c.legend(fontsize=6.5, frameon=False, loc="upper left"); c.grid(alpha=0.3)

# (d) latency components (run averages from T2)
rows = T2[((T2.experiment == "configs") & (T2.cell == "3rsu")) | (T2.experiment == "load")]
rows = rows[rows.rejected_mean.fillna(0) < 5]
lam = rows.confirmed_rate_tps_mean
d.plot(lam, rows.latency_ms_median_mean / 1000, "o", ms=5, color="#1f4e79", label="End-to-end (median)")
d.plot(lam, rows.cw_wait_ms_median_mean / 1000, "s", ms=4, color="#c55a11", label="Approval wait (median)")
d.plot(lam, rows.mean_tips_mean / lam, "x", ms=6, mew=1.5, color="k", label="Eq. (11): $E[L]/\\lambda$")
d.plot(lam, rows.quorum_wait_ms_median_mean / 1000, "^", ms=4, color="#548235", label="Quorum time $T_q$ (median)")
d.set_xscale("log"); d.set_yscale("log")
d.xaxis.set_major_locator(FixedLocator([0.3, 0.5, 1, 2, 3])); d.xaxis.set_minor_locator(NullLocator())
d.xaxis.set_major_formatter(ScalarFormatter()); d.set_xlim(0.28, 3.3)
d.set_xlabel("Confirmed throughput λ, run average (tx/s)"); d.set_ylabel("Time (s)")
d.set_title("(d) Latency components", fontsize=9)
d.legend(fontsize=6.5, frameon=False, loc="center", bbox_to_anchor=(0.47, 0.45)); d.grid(alpha=0.3, which="both")

fig.tight_layout(); fig.savefig(out, dpi=300)
print("wrote", out, f"  t0 = {t0:.1f} ms, R2 = {r2:.3f}, points = {len(y)}")
