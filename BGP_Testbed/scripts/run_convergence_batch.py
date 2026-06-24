#!/usr/bin/env python3
"""Batch driver for measure_convergence.py across the randomized runs.

measure_convergence.py only ever measures the *currently deployed* lab. This script
deploys one attack scenario per (run, tier), runs the convergence measurement, reduces
its per-observer output to a single network-wide recovery value per mode, and collects
everything into one CSV ready for aggregate_results.py.

Scope note: convergence is fundamentally BGP withdrawal propagation, which barely
differs between attack *types*. The interesting variables are attacker tier/placement
and withdrawal mode (graceful vs stop), so by default we measure a single
representative attack (1_subprefix_hijack) across all runs and tiers, in both modes.
Override with --scenario-id if you want a different attack.

Output CSV (one row per run x tier x mode x internal conv-run):
    run, tier, scenario, target, censor, mode, conv_run, affected,
    decensor_net_s, ping_net_s, reachability_lost, error
where *_net_s is the slowest observer (network-wide recovery), blank = timeout.
"""
import argparse
import csv
import glob
import os
import re
import subprocess
import tempfile
import time
from typing import Dict, List, Optional

import yaml

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def run_cmd(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def load_yaml(path: str) -> Dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r") as handle:
        return yaml.safe_load(handle) or {}


def parse_csv_list(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def discover_runs(runs_dir: str, limit: Optional[int]) -> List[str]:
    run_dirs = sorted(
        os.path.basename(p)
        for p in glob.glob(os.path.join(runs_dir, "run_*"))
        if os.path.isdir(p)
    )
    return run_dirs[:limit] if limit else run_dirs


def _to_float(value: str) -> Optional[float]:
    value = (value or "").strip()
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def reduce_network_recovery(observer_csv: str) -> List[Dict[str, object]]:
    """Collapse the per-observer measure_convergence CSV into one row per (mode, run).

    Mirrors network_recovery() in measure_convergence.py: the network-wide recovery is
    the slowest observer; a missing decensor time means that observer never recovered
    (timeout -> network value is blank); observers that lost reachability are collateral
    and excluded from the ping figure rather than counted as a hang.
    """
    groups: Dict[tuple, List[Dict[str, str]]] = {}
    with open(observer_csv, newline="") as handle:
        for row in csv.DictReader(handle):
            groups.setdefault((row["mode"], row["run"]), []).append(row)

    results = []
    for (mode, run), rows in sorted(groups.items()):
        affected = sum(1 for r in rows if r.get("hijacked_at_t0") == "1")

        decensor_vals = [_to_float(r.get("decensor_s", "")) for r in rows]
        decensor_net = None if any(v is None for v in decensor_vals) else max(decensor_vals)

        lost = sum(1 for r in rows if r.get("reachability_lost") == "1")
        stuck = any(
            _to_float(r.get("ping_recovered_s", "")) is None and r.get("reachability_lost") != "1"
            for r in rows
        )
        ping_present = [
            _to_float(r.get("ping_recovered_s", ""))
            for r in rows
            if _to_float(r.get("ping_recovered_s", "")) is not None
        ]
        ping_net = None if stuck else (max(ping_present) if ping_present else 0.0)

        results.append({
            "mode": mode,
            "conv_run": run,
            "affected": affected,
            "decensor_net_s": "" if decensor_net is None else f"{decensor_net:.3f}",
            "ping_net_s": "" if ping_net is None else f"{ping_net:.3f}",
            "reachability_lost": lost,
        })
    return results


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--runs-dir", default=os.path.join("scenarios", "random_runs"),
        help="Root of the generated random runs (default: scenarios/random_runs).",
    )
    parser.add_argument("--runs", type=int, help="Limit number of runs (default: all).")
    parser.add_argument("--tiers", default="1,2,3", help="Attacker tiers (default: 1,2,3).")
    parser.add_argument(
        "--scenario-id", default="1_subprefix_hijack",
        help="Attack scenario measured per run/tier (default: 1_subprefix_hijack).",
    )
    parser.add_argument(
        "--mode", choices=["graceful", "stop", "both"], default="both",
        help="Withdrawal method passed to measure_convergence.py (default: both).",
    )
    parser.add_argument("--settle", type=float, default=25.0, help="Post-deploy wait (s).")
    parser.add_argument(
        "--conv-runs", type=int, default=1,
        help="Internal repetitions per mode inside measure_convergence (default: 1).",
    )
    parser.add_argument("--timeout", type=float, default=60.0, help="Per-recovery timeout (s).")
    parser.add_argument("--poll", type=float, default=0.5, help="Sampling interval (s).")
    parser.add_argument(
        "--output", default=os.path.join("results", "csv", "convergence_runs.csv"),
        help="Aggregate CSV path (default: results/csv/convergence_runs.csv).",
    )
    parser.add_argument("--sudo", action="store_true", help="Pass --sudo to deploy + measure.")
    parser.add_argument("--no-hard-clean", action="store_true", help="Skip container cleanup.")
    parser.add_argument("--keep-going", action="store_true", help="Continue past failures.")
    args = parser.parse_args()

    tiers = [int(t) for t in parse_csv_list(args.tiers)]
    run_keys = discover_runs(args.runs_dir, args.runs)
    if not run_keys:
        print(f"No runs found under {args.runs_dir}. Generate random scenarios first.")
        return 1

    manifest = load_yaml(os.path.join(args.runs_dir, "manifest.yaml"))
    manifest_runs = manifest.get("runs", {}) if manifest else {}

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    fieldnames = [
        "run", "tier", "scenario", "target", "censor", "mode", "conv_run",
        "affected", "decensor_net_s", "ping_net_s", "reachability_lost", "error",
    ]

    print(f"Convergence batch: {len(run_keys)} run(s) x tiers {tiers} x '{args.scenario_id}', "
          f"mode={args.mode}")

    with open(args.output, "w", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=fieldnames)
        writer.writeheader()

        for run_key in run_keys:
            run_info = manifest_runs.get(run_key, {})
            target = run_info.get("target", "")
            for tier in tiers:
                censor = (run_info.get("censors") or {}).get(str(tier), "")
                scenario_path = os.path.join(
                    args.runs_dir, run_key, f"tier{tier}", f"{args.scenario_id}.yaml"
                )
                base_row = {
                    "run": run_key, "tier": tier, "scenario": args.scenario_id,
                    "target": target, "censor": censor,
                }
                if not os.path.exists(scenario_path):
                    writer.writerow({**base_row, "error": "scenario file missing"})
                    out.flush()
                    continue

                print(f"\n[{run_key} tier{tier}] deploying {args.scenario_id} ...")
                deploy_cmd = [
                    "python3", "scripts/generate_topology.py",
                    "--scenario", scenario_path, "--no-graph",
                ]
                if args.sudo:
                    deploy_cmd.append("--sudo")
                if args.no_hard_clean:
                    deploy_cmd.append("--no-hard-clean")

                deploy = run_cmd(deploy_cmd)
                if deploy.returncode != 0:
                    writer.writerow({**base_row, "error": "deploy failed"})
                    out.flush()
                    if not args.keep_going:
                        print(deploy.stdout)
                        print(deploy.stderr)
                        return 1
                    continue

                print(f"[{run_key} tier{tier}] deploy ok, settling {args.settle:.0f}s ...")
                time.sleep(args.settle)

                tmp = tempfile.NamedTemporaryFile(
                    mode="w", suffix=".csv", delete=False, dir=os.path.join(BASE_DIR, "results", "csv")
                )
                tmp.close()
                measure_cmd = [
                    "python3", "scripts/measure_convergence.py",
                    "--mode", args.mode,
                    "--runs", str(args.conv_runs),
                    "--timeout", str(args.timeout),
                    "--poll", str(args.poll),
                    "--output", tmp.name,
                ]
                if args.sudo:
                    measure_cmd.append("--sudo")

                measure = run_cmd(measure_cmd)
                if measure.returncode != 0 or not os.path.getsize(tmp.name):
                    writer.writerow({**base_row, "error": "measure failed"})
                    out.flush()
                    os.unlink(tmp.name)
                    if not args.keep_going:
                        print(measure.stdout)
                        print(measure.stderr)
                        return 1
                    continue

                for net in reduce_network_recovery(tmp.name):
                    writer.writerow({**base_row, **net, "error": ""})
                    print(f"    {net['mode']:8s} conv_run={net['conv_run']} "
                          f"affected={net['affected']:2d} "
                          f"de-hijack={net['decensor_net_s'] or 'TIMEOUT':>7} "
                          f"ping={net['ping_net_s'] or 'TIMEOUT':>7}"
                          + (f" lost={net['reachability_lost']}" if net['reachability_lost'] else ""))
                out.flush()
                os.unlink(tmp.name)

    print(f"\nDone. Network-wide convergence written to {args.output}")
    print("Aggregate + plot with: python3 scripts/aggregate_results.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
