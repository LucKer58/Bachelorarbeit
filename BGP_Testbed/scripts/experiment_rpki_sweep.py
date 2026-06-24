#!/usr/bin/env python3
"""Experiment 2 -- defense threshold: how many ASes must deploy RPKI ROV (core-first)
until a sub-prefix hijack is rendered useless.

For each run (victim placement) and each attacker tier, a single censor sub-prefix-hijacks
the target. RPKI-validating routers are added in CORE-FIRST order (tier1 -> tier2 -> tier3,
excluding the censor); for m = 0, 1, ... routers we deploy, force ROV re-validation, and
record the hijack rate. The smallest m reaching 0% true-hijack is the deployment threshold.

Sub-prefix is the right attack: it starts at 100% (strongest hijack), and the ROA maxLength
is 24, so the /25 is RPKI-INVALID and ROV drops it, falling back to the legitimate /24.

TWO metrics are logged, because they differ:
  * hijacked       -- raw: ANY censor ASN in the path (the evaluator's definition). This
                      cannot reach 0% because the censor is also a normal TRANSIT AS, so
                      sources whose legitimate /24 path crosses it are flagged too.
  * true_hijacked  -- sources that actually use the hijack /25 (origin = censor). THIS is
                      what reaches 0% when ROV is fully deployed; use it for the threshold.

Blackhole nuance: we also log legit / no_route -- under RPKI a source may be blackholed
(no_route) rather than recovered to legit.

Output CSV (results/csv/rpki_sweep.csv):
    run, attacker_tier, m, target, censor, rpki_routers, total, hijacked, true_hijacked,
    legit, no_route, hijack_rate, true_hijack_rate, error
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
    FlowSeq, dump_yaml, load_yaml, get_node_num,
)

SUMMARY_RE = re.compile(
    r"Summary: total=(\d+) hijacked=(\d+) legit=(\d+) no-route=(\d+) other=(\d+) hijack_rate=([0-9.]+)%"
)
TMP = os.path.join("scenarios", "_exp_rpki.yaml")


def run_cmd(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def container_prefix():
    lab = load_yaml(os.path.join("generated", "lab.clab.yaml"))
    return f"clab-{(lab or {}).get('name', 'bgp-testbed')}-"


def core_first_order(tiers_by_num, exclude):
    """ASes in core-first order (tier1, tier2, tier3), skipping the excluded set."""
    order = []
    for tier in (1, 2, 3):
        for node in tiers_by_num.get(tier, []):
            if node not in exclude:
                order.append(node)
    return order


def build_rpki_scenario(base, censor_as, target, rpki_routers):
    cname = "censor1"
    routers = [r for r in base["routers"] if r != censor_as]
    tiers = {k: replace_node(v, censor_as, cname) for k, v in base["tiers"].items()}
    links = [FlowSeq(p) for p in replace_links(base["links"], censor_as, cname)]
    scen = {
        "name": base["name"],
        "routers": routers,
        "tiers": tiers,
        "tier_policy": base.get("tier_policy", {}),
        "links": links,
        "censors": [{
            "name": cname, "target_router": target,
            "attack_type": "hijack", "prefix_type": "subprefix", "isp_mode": True,
        }],
        "policies": [],
    }
    if rpki_routers:
        scen["rpki_routers"] = list(rpki_routers)
    return scen


def deploy(path, sudo):
    cmd = ["python3", "scripts/generate_topology.py", "--scenario", path, "--no-graph"]
    if sudo:
        cmd.append("--sudo")
    return run_cmd(cmd).returncode == 0


def rpki_refresh(rpki_routers):
    pre = container_prefix()
    for n in rpki_routers:
        run_cmd(["docker", "exec", f"{pre}{n}", "vtysh", "-c", "clear ip bgp * soft in"])


def evaluate(path, subprefix_str):
    """Return (total, hijacked_raw, true_hijacked, legit, no_route) or None.

    true_hijacked counts sources flagged 'hijacked' whose USED prefix is the /25 -- i.e.
    actually redirected to the attacker, not merely transiting the censor's AS on the /24.
    """
    out = run_cmd(["python3", "scripts/evaluate_hijack_impact.py", "--scenario", path]).stdout
    m = SUMMARY_RE.search(out or "")
    if not m:
        return None
    total, hij, legit, noroute, _other, _rate = m.groups()
    true_hij = sum(1 for ln in out.splitlines()
                   if "hijacked" in ln.lower() and subprefix_str in ln)
    return (int(total), int(hij), true_hij, int(legit), int(noroute))


def wait_stable(path, subprefix_str, interval=4.0, timeout=110.0, need=2):
    """Stable result accepting no_route>0 (blackhole is a valid steady state under RPKI)."""
    start, sig, consec, last = time.monotonic(), None, 0, None
    while True:
        r = evaluate(path, subprefix_str)
        if r:
            last = r
            if r == sig:
                consec += 1
            else:
                consec, sig = 1, r
            if consec >= need:
                return r
        if time.monotonic() - start >= timeout:
            return last
        time.sleep(interval)


def make_steps(total, raw):
    if raw:
        steps = {int(s) for s in raw.split(",") if s.strip()}
    else:
        steps = {0, 1, 2, 3, 5, 8, 12, 16, 20, 24}
    return sorted({s for s in steps if 0 <= s <= total} | {0, total})


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base", default=os.path.join("scenarios", "sub_prefix_30.yaml"))
    p.add_argument("--manifest", default=os.path.join("scenarios", "random_runs", "manifest.yaml"))
    p.add_argument("--runs", type=int, default=3, help="Number of victim placements (default 3).")
    p.add_argument("--tiers", default="1,2,3", help="Attacker tiers to sweep.")
    p.add_argument("--steps", default="",
                   help="Comma list of RPKI-router counts m (default coarse + 0 + total).")
    p.add_argument("--seed", type=int, default=1337)
    p.add_argument("--settle", type=float, default=22.0)
    p.add_argument("--stop-at-0", action="store_true",
                   help="Skip larger m once true-hijack hits 0%% (saves time).")
    p.add_argument("--output", default=os.path.join("results", "csv", "rpki_sweep.csv"))
    p.add_argument("--sudo", action="store_true")
    args = p.parse_args()

    base = normalize_base_topology(load_yaml(args.base))
    tiers_by_num, _ = build_tier_maps(base["tiers"])
    manifest = load_yaml(args.manifest) if os.path.exists(args.manifest) else {}
    manifest_runs = manifest.get("runs", {}) if manifest else {}
    run_keys = (sorted(manifest_runs.keys())[:args.runs] if manifest_runs
                else [f"run_{i:03d}" for i in range(1, args.runs + 1)])
    tiers = [int(t) for t in args.tiers.split(",") if t.strip()]
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)

    print(f"RPKI sweep: {len(run_keys)} run(s) x attacker tiers {tiers}, core-first, subprefix")
    summary_min_m = {}

    with open(args.output, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["run", "attacker_tier", "m", "target", "censor", "rpki_routers",
                    "total", "hijacked", "true_hijacked", "legit", "no_route",
                    "hijack_rate", "true_hijack_rate", "error"])
        for run_key in run_keys:
            info = manifest_runs.get(run_key, {})
            rng = random.Random(f"{args.seed}-{run_key}")
            target = info.get("target")
            if not target:
                pool3 = list(tiers_by_num.get(3, []))
                rng.shuffle(pool3)
                target = pool3[0]
            subprefix_str = f"192.168.{get_node_num(target)}.0/25"
            for tier in tiers:
                censor_as = (info.get("censors") or {}).get(str(tier))
                if not censor_as:
                    cand = [a for a in tiers_by_num.get(tier, []) if a != target]
                    random.Random(f"{args.seed}-{run_key}-{tier}").shuffle(cand)
                    censor_as = cand[0] if cand else None
                if not censor_as:
                    continue
                order = core_first_order(tiers_by_num, exclude={censor_as})
                steps = make_steps(len(order), args.steps)
                reached = None
                for m in steps:
                    rpki = order[:m]
                    dump_yaml(TMP, build_rpki_scenario(base, censor_as, target, rpki))
                    print(f"[{run_key} tier{tier} m={m}] censor={censor_as} -> deploy")
                    if not deploy(TMP, args.sudo):
                        w.writerow([run_key, tier, m, target, censor_as, len(rpki),
                                    "", "", "", "", "", "", "", "deploy failed"]); fh.flush(); continue
                    time.sleep(args.settle)
                    if rpki:
                        rpki_refresh(rpki)  # force ROV re-validation (RPKI timing trap)
                    r = wait_stable(TMP, subprefix_str)
                    if not r:
                        w.writerow([run_key, tier, m, target, censor_as, len(rpki),
                                    "", "", "", "", "", "", "", "no summary"]); fh.flush(); continue
                    total, hij, true_hij, legit, noroute = r
                    raw_rate = 100.0 * hij / total if total else 0.0
                    true_rate = 100.0 * true_hij / total if total else 0.0
                    w.writerow([run_key, tier, m, target, censor_as, len(rpki),
                                total, hij, true_hij, legit, noroute,
                                f"{raw_rate:.1f}", f"{true_rate:.1f}", ""]); fh.flush()
                    print(f"    -> true={true_rate:.0f}% (truehij={true_hij}/{total})  "
                          f"raw={raw_rate:.0f}%  legit={legit} no_route={noroute}")
                    if reached is None and true_rate <= 0.0:
                        reached = m
                        if args.stop_at_0:
                            print(f"    true-hijack 0% at m={m}; stopping this tier")
                            break
                summary_min_m.setdefault(tier, []).append(reached)

    print(f"\nDone -> {args.output}")
    print("Min #RPKI routers to reach 0% TRUE-hijack (None = not reached within steps):")
    for tier in sorted(summary_min_m):
        print(f"  attacker tier{tier}: {summary_min_m[tier]}")
    if os.path.exists(TMP):
        os.unlink(TMP)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
