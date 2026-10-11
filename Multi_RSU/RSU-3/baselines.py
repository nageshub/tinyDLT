#!/usr/bin/env python3
"""
Baseline registry for comparison overlays
=========================================

Two kinds of baseline, and they are NOT equally strong.

1. MEASURED baselines (strong). You run another system on YOUR hardware,
   under YOUR workload, and its logs go into the results tree as
   `results/baseline/<system>/...`. Same machines, same vehicles, same
   traffic: a fair comparison. The analyser plots these as bars beside
   the proposed system in F1.

2. REPORTED baselines (weak, contextual only). Numbers published in
   other papers, measured on other hardware with other workloads. They
   belong on the plot as a dashed reference line with the citation in
   the label, never as a bar in the same series as your measurements.
   A reviewer who sees "our 0.9 tx/s vs Fabric's 185 tx/s" plotted as
   equals will reject the paper; the same two numbers, labelled with
   their conditions, make a legitimate point about operating regimes.

Every entry below carries `source` and `conditions`. `verified` starts
False: set it to True only once YOU have opened the paper and confirmed
the number and the conditions. The analyser prints a warning listing
every unverified entry it plotted, and the warning text names the
figure, so nothing silently ends up in a manuscript unchecked.

Add the works you actually cite in your related-work section. A baseline
you do not cite in the text should not be on the plot.
"""

REPORTED_BASELINES = [
    {
        "key": "fabric-generic",
        "system": "Hyperledger Fabric (permissioned, server cluster)",
        "metric": "throughput_tps",
        "value": 185.0,
        "conditions": "8-core CPU server, 300 TPS offered load, "
                      "Caliper benchmark; not a vehicular workload",
        "source": "Performance analysis of a Hyperledger Fabric "
                  "framework: throughput, latency and scalability "
                  "(IEEE, 2019) - VERIFY page/table before citing",
        "verified": False,
    },
    {
        "key": "fabric-generic-latency",
        "system": "Hyperledger Fabric (permissioned, server cluster)",
        "metric": "latency_ms",
        "value": 285.0,
        "conditions": "same run as above, 300 TPS offered load",
        "source": "as above - VERIFY before citing",
        "verified": False,
    },
    {
        "key": "bitcoin-pow",
        "system": "Bitcoin (public PoW)",
        "metric": "throughput_tps",
        "value": 7.0,
        "conditions": "public mainnet, widely quoted ceiling",
        "source": "commonly cited; give a primary reference in your "
                  "related work - VERIFY",
        "verified": False,
    },
    {
        "key": "ethereum-public",
        "system": "Ethereum (public PoS)",
        "metric": "throughput_tps",
        "value": 15.0,
        "conditions": "public mainnet, widely quoted ceiling; testnet "
                      "and private PoA numbers are much higher",
        "source": "commonly cited; give a primary reference - VERIFY",
        "verified": False,
    },
    # Add your own related-work entries here, e.g. the IOTA-based VANET
    # schemes and the blockchain-ITS papers you cite. Template:
    # {
    #     "key": "author2023-iota-vanet",
    #     "system": "IOTA-based VANET (Author et al., 2023)",
    #     "metric": "latency_ms",          # or throughput_tps, energy_mj
    #     "value": 1234.0,
    #     "conditions": "N RSUs, M vehicles, simulated in <tool>",
    #     "source": "Author et al., <venue>, <year>, DOI ...",
    #     "verified": True,
    # },
]

METRIC_LABELS = {
    "throughput_tps": "Confirmed throughput (tx/s)",
    "latency_ms": "Confirmation latency (ms)",
    "energy_mj": "Energy per transaction (mJ)",
}


def for_metric(metric):
    return [b for b in REPORTED_BASELINES if b["metric"] == metric]


def unverified(entries):
    return [b for b in entries if not b.get("verified")]


def warn_unverified(entries, figure):
    bad = unverified(entries)
    if not bad:
        return
    print(f"  WARNING: {figure} shows {len(bad)} UNVERIFIED reported "
          f"baseline(s). Open the paper, confirm the value and the "
          f"conditions, then set verified=True in baselines.py:")
    for b in bad:
        print(f"    - {b['key']}: {b['value']} ({b['source']})")


if __name__ == "__main__":
    for m, label in METRIC_LABELS.items():
        rows = for_metric(m)
        if not rows:
            continue
        print(f"\n{label}")
        for b in rows:
            mark = "ok " if b.get("verified") else "UNVERIFIED"
            print(f"  [{mark}] {b['value']:>8}  {b['system']}")
            print(f"              {b['conditions']}")
