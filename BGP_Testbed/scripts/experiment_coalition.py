#!/usr/bin/env python3
"""Experiment 1 -- attacker coalition: how many exact-prefix censors (per tier) are
needed until 100% of the network is hijacked.

For each run (victim placement) and each attacker tier, deploy scenarios with k = 1, 2, ...
censors drawn from that tier (incrementally, seeded), all exact-prefix hijacking the SAME
target, and record the hijack rate. The smallest k reaching 100% is the coalition size.

Reuses the live pipeline (generate_topology.py + evaluate_hijack_impact.py) and the
scenario-building primitives from generate_random_scenarios.py. Targets are taken from the
random-runs manifest when present, so placements match the main study.

LIMITATION: censor numbering caps at censor9 -- the router-id 9N.9N.9N.9N is only valid for
N <= 9. So k is capped at 9: tier1 (3 AS) and tier2 (7 AS) fit fully, tier3 (19 AS) is
capped at 9. If tier3 has not reached 100% by k=9, report it as a saturation/lower bound.

NOTE on the metric: censors are not counted as sources, so the denominator shrinks with k;
"100%" means 100% of the remaining non-censor ASes route via some censor.

Output CSV (results/coalition.csv):
    run, tier, k, target, censors, total, hijacked, legit, no_route, hijack_rate, error
"""
import argparse
import csv
import os
import random
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from generate_random_scenarios import (  # noqa: E402
    normalize_base_topology, build_tier_maps, replace_node, replace_links,
    FlowSeq, dump_yaml, load_yaml,
)

MAX_CENSOR_NUM = 9  # router-id 9N.9N.9N.9N is only valid for N <= 9
SUMMARY_RE = re.compile(
    r"Summary: total=(\d+) hijacked=(\d+) legit=(\d+) no-route=(\d+) other=(\d+) hijack_rate=([0-9.]+)%"
)
TMP = os.path.join("scenarios", "_exp_coalition.yaml")


def run_cmd(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def parse_summary(out):
    m = SUMMARY_RE.search(out or "")
    return m.groups() if m else None  # (total, hij, legit, no_route, other, rate)


def build_coalition_scenario(base, censor_ases, target):
    """Turn the first len(censor_ases) ASes into censor1..censorK, all exact-hijacking target."""
    routers = list(base["routers"])
    tiers = {k: list(v) for k, v in base["tiers"].items()}
    links = [list(p) for p in base["links"]]
    censors = []
    for i, as_name in enumerate(censor_ases, start=1):
        cname = f"censor{i}"
        routers = [r for r in routers if r != as_name]
        tiers = {k: replace_node(v, as_name, cname) for k, v in tiers.items()}
        links = replace_links(links, as_name, cname)
        censors.append({
            "name": cname, "target_router": target,
            "attack_type": "hijack", "prefix_type": "exact", "isp_mode": True,
        })
    return {
        "name": base["name"],
        "routers": routers,
        "tiers": tiers,
        "tier_policy": base.get("tier_policy", {}),
        "links": [FlowSeq(p) for p in links],
        "censors": censors,
        "policies": [],
    }


def deploy(path, sudo):
    cmd = ["python3", "scripts/generate_topology.py", "--scenario", path, "--no-graph"]
    if sudo:
        cmd.append("--sudo")
    return run_cmd(cmd).returncode == 0


def wait_stable(path, settle, interval=4.0, timeout=90.0, need=2):
    """Poll the evaluator until the summary is identical `need` times with no_route==0."""
    time.sleep(settle)
    cmd = ["python3", "scripts/evaluate_hijack_impact.py", "--quiet", "--scenario", path]
    start, sig, consec, last = time.monotonic(), None, 0, None
    while True:
        g = parse_summary(run_cmd(cmd).stdout)
        if g:
            last = g
            converged = int(g[3]) == 0  # no_route == 0
            if converged and g == sig:
                consec += 1
            elif converged:
                consec, sig = 1, g
            else:
                consec, sig = 0, None
            if converged and consec >= need:
                return g
        if time.monotonic() - start >= timeout:
            return last
        time.sleep(interval)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base", default=os.path.join("scenarios", "sub_prefix_30.yaml"))
    p.add_argument("--manifest", default=os.path.join("scenarios", "random_runs", "manifest.yaml"))
    p.add_argument("--runs", type=int, default=3, help="Number of victim placements (default 3).")
    p.add_argument("--tiers", default="1,2,3", help="Attacker tiers to sweep.")
    p.add_argument("--max-k", type=int, default=MAX_CENSOR_NUM,
                   help=f"Max censors per tier (hard cap {MAX_CENSOR_NUM}).")
    p.add_argument("--seed", type=int, default=1337)
    p.add_argument("--settle", type=float, default=20.0)
    p.add_argument("--stop-at-100", action="store_true",
                   help="Skip larger k once 100%% is reached (saves time).")
    p.add_argument("--output", default=os.path.join("results", "coalition.csv"))
    p.add_argument("--sudo", action="store_true")
    args = p.parse_args()

    base = normalize_base_topology(load_yaml(args.base))
    tiers_by_num, _ = build_tier_maps(base["tiers"])
    manifest = load_yaml(args.manifest) if os.path.exists(args.manifest) else {}
    manifest_runs = manifest.get("runs", {}) if manifest else {}
    run_keys = (sorted(manifest_runs.keys())[:args.runs] if manifest_runs
                else [f"run_{i:03d}" for i in range(1, args.runs + 1)])
    tiers = [int(t) for t in args.tiers.split(",") if t.strip()]
    cap = min(args.max_k, MAX_CENSOR_NUM)
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)

    print(f"Coalition sweep: {len(run_keys)} run(s) x tiers {tiers}, k=1..{cap} (exact hijack)")
    summary_min_k = {}  # (tier) -> list of min-k-to-100 across runs

    with open(args.output, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["run", "tier", "k", "target", "censors", "total", "hijacked",
                    "legit", "no_route", "hijack_rate", "error"])
        for run_key in run_keys:
            rng = random.Random(f"{args.seed}-{run_key}")
            target = manifest_runs.get(run_key, {}).get("target")
            if not target:
                pool3 = list(tiers_by_num.get(3, []))
                rng.shuffle(pool3)
                target = pool3[0]
            for tier in tiers:
                pool = [a for a in tiers_by_num.get(tier, []) if a != target]
                random.Random(f"{args.seed}-{run_key}-{tier}").shuffle(pool)
                kmax = min(len(pool), cap)
                reached = None
                for k in range(1, kmax + 1):
                    censor_ases = pool[:k]
                    dump_yaml(TMP, build_coalition_scenario(base, censor_ases, target))
                    print(f"[{run_key} tier{tier} k={k}] {censor_ases} -> deploy")
                    if not deploy(TMP, args.sudo):
                        w.writerow([run_key, tier, k, target, ";".join(censor_ases),
                                    "", "", "", "", "", "deploy failed"]); fh.flush(); continue
                    g = wait_stable(TMP, args.settle)
                    if not g:
                        w.writerow([run_key, tier, k, target, ";".join(censor_ases),
                                    "", "", "", "", "", "no summary"]); fh.flush(); continue
                    total, hij, legit, noroute, _other, rate = g
                    w.writerow([run_key, tier, k, target, ";".join(censor_ases),
                                total, hij, legit, noroute, rate, ""]); fh.flush()
                    print(f"    -> hijack_rate={rate}%  (hij={hij}/{total}, legit={legit}, no_route={noroute})")
                    if reached is None and float(rate) >= 100.0:
                        reached = k
                        if args.stop_at_100:
                            print(f"    reached 100% at k={k}; stopping this tier")
                            break
                summary_min_k.setdefault(tier, []).append(reached)

    print(f"\nDone -> {args.output}")
    print("Min #censors to reach 100% (None = not reached within k<=cap):")
    for tier in sorted(summary_min_k):
        print(f"  tier{tier}: {summary_min_k[tier]}")
    if os.path.exists(TMP):
        os.unlink(TMP)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
