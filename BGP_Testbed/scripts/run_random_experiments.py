#!/usr/bin/env python3
import argparse
import csv
import os
import re
import subprocess
import time
from typing import Dict, List, Optional, Tuple

import yaml

SCENARIO_SPECS = [
    "1_subprefix_hijack",
    "2_exact_hijack_no_pref",
    "3_exact_hijack_with_pref",
    "4_exact_hijack_with_defense",
    "5_path_poisoning",
    "6_rpki_test",
    "8_path_forgery",
    "9_mitm_attack",
    "10_origin_code_manipulation",
    "11_origin_spoofing_rpki",
]

SUMMARY_RE = re.compile(
    r"Summary: total=(\d+) hijacked=(\d+) legit=(\d+) no-route=(\d+) other=(\d+) hijack_rate=([0-9.]+)%"
)


def run_cmd(cmd: List[str], cwd: Optional[str] = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, check=False)


def load_yaml(path: str) -> Dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r") as handle:
        return yaml.safe_load(handle) or {}


def parse_csv_list(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def parse_summary(output: str) -> Optional[Dict[str, str]]:
    match = SUMMARY_RE.search(output)
    if not match:
        return None
    total, hijacked, legit, no_route, other, rate = match.groups()
    return {
        "total": total,
        "hijacked": hijacked,
        "legit": legit,
        "no_route": no_route,
        "other": other,
        "hijack_rate": rate,
    }


def parse_bgp_summary_states(output: str) -> List[Tuple[str, str]]:
    states = []
    for line in output.splitlines():
        if not re.match(r"^\d+\.\d+\.\d+\.\d+\s+", line):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue

        updown_idx = None
        for idx, token in enumerate(parts):
            if re.match(r"^\d{2}:\d{2}:\d{2}$", token):
                updown_idx = idx
                break
            if token == "never":
                updown_idx = idx
                break
            if re.match(r"^\d+d\d+h\d+m$", token):
                updown_idx = idx
                break

        if updown_idx is None or updown_idx + 1 >= len(parts):
            continue

        states.append((parts[0], parts[updown_idx + 1]))
    return states


def parse_bgp_summary_ready(states: List[Tuple[str, str]]) -> bool:
    if not states:
        return False
    return all(state.isdigit() for _, state in states)


def get_container_prefix() -> str:
    lab = load_yaml(os.path.join("generated", "lab.clab.yaml"))
    lab_name = lab.get("name", "bgp-testbed")
    return f"clab-{lab_name}-"


def wait_for_bgp_ready(
    nodes: List[str],
    interval: float,
    timeout: float,
    progress_interval: float = 10.0,
) -> bool:
    container_prefix = get_container_prefix()
    start = time.monotonic()
    last_report = 0.0
    while True:
        all_ready = True
        last_node = None
        last_states: List[Tuple[str, str]] = []
        for node in nodes:
            container = f"{container_prefix}{node}"
            result = run_cmd(
                ["docker", "exec", container, "vtysh", "-c", "show ip bgp summary"]
            )
            states = parse_bgp_summary_states(result.stdout) if result.returncode == 0 else []
            if result.returncode != 0 or not parse_bgp_summary_ready(states):
                all_ready = False
                last_node = node
                last_states = states
                break
        if all_ready:
            return True
        now = time.monotonic()
        if now - last_report >= progress_interval and last_node:
            elapsed = now - start
            if last_states:
                sample = ", ".join(
                    f"{neighbor}:{state}" for neighbor, state in last_states[:3]
                )
            else:
                sample = "no neighbors"
            print(
                f"Waiting for BGP on {last_node} ({sample}); elapsed {elapsed:.0f}s"
            )
            last_report = now
        if time.monotonic() - start >= timeout:
            return False
        time.sleep(interval)


def parse_rpki_cache_ready(output: str) -> bool:
    text = output.lower()
    if "no rpki" in text or "not connected" in text:
        return False
    if "disconnected" in text or "down" in text:
        return False
    if "connected" in text or "established" in text or "up" in text:
        return True
    return False


def count_rpki_prefixes(output: str) -> int:
    count = 0
    for line in output.splitlines():
        if re.match(r"^\d+\.\d+\.\d+\.\d+\s+\d+\b", line):
            count += 1
    return count


def wait_for_rpki_ready(
    nodes: List[str],
    interval: float,
    timeout: float,
    progress_interval: float = 10.0,
) -> bool:
    container_prefix = get_container_prefix()
    start = time.monotonic()
    last_report = 0.0
    while True:
        all_ready = True
        last_node = None
        last_prefixes = 0
        for node in nodes:
            container = f"{container_prefix}{node}"
            cache_result = run_cmd(
                ["docker", "exec", container, "vtysh", "-c", "show rpki cache"]
            )
            cache_text = cache_result.stdout.lower() if cache_result.stdout else ""
            cache_ambiguous = "ambiguous command" in cache_text
            cache_ready = (
                cache_result.returncode == 0
                and not cache_ambiguous
                and parse_rpki_cache_ready(cache_result.stdout)
            )
            if cache_result.returncode != 0 or cache_ambiguous:
                cache_result = run_cmd(
                    [
                        "docker",
                        "exec",
                        container,
                        "vtysh",
                        "-c",
                        "show rpki cache-connection",
                    ]
                )
                cache_ready = (
                    cache_result.returncode == 0
                    and parse_rpki_cache_ready(cache_result.stdout)
                )
            prefix_result = run_cmd(
                ["docker", "exec", container, "vtysh", "-c", "show rpki prefix"]
            )
            prefixes = (
                count_rpki_prefixes(prefix_result.stdout)
                if prefix_result.returncode == 0
                else 0
            )
            if prefixes == 0 and cache_ready:
                all_ready = False
                last_node = node
                last_prefixes = 0
                break
            if prefixes == 0 and not cache_ready:
                all_ready = False
                last_node = node
                last_prefixes = 0
                break
            last_prefixes = prefixes

        if all_ready:
            return True
        now = time.monotonic()
        if now - last_report >= progress_interval and last_node:
            elapsed = now - start
            print(
                f"Waiting for RPKI on {last_node} (prefixes {last_prefixes}); elapsed {elapsed:.0f}s"
            )
            last_report = now
        if time.monotonic() - start >= timeout:
            return False
        time.sleep(interval)


def summary_signature(summary: Dict[str, str]) -> Tuple[str, str, str, str, str, str]:
    return (
        summary.get("total", ""),
        summary.get("hijacked", ""),
        summary.get("legit", ""),
        summary.get("no_route", ""),
        summary.get("other", ""),
        summary.get("hijack_rate", ""),
    )


def summary_converged(summary: Optional[Dict[str, str]]) -> bool:
    """Return True only when every source has *some* route to the target.

    In all scenarios in SCENARIO_SPECS the target announces its prefix and stays
    reachable, so the steady-state no-route count must be 0. A non-zero no-route
    count means BGP (or RPKI withdrawal) is still converging and the numbers are
    transient -- treating such a summary as final is what makes repeated runs
    disagree, especially for the RPKI scenario.
    """
    if not summary:
        return False
    try:
        total = int(summary.get("total", "0"))
        no_route = int(summary.get("no_route", "0"))
    except (TypeError, ValueError):
        return False
    return total > 0 and no_route == 0


def force_rpki_revalidation(nodes: List[str]) -> None:
    """Force RPKI routers to re-pull and re-validate routes immediately.

    Opt-in via ``--rpki-refresh`` (off by default), since it perturbs running
    state and costs reconvergence time. It does not change routing policy.
    Without this the run races FRR's ``rpki polling_period`` timer: the cache may
    be loaded but the invalid route not yet withdrawn, so a run can sample (and
    lock onto) the pre-RPKI state. A soft inbound refresh re-runs the inbound
    policy -- including ``match rpki invalid`` -- against the now-loaded cache so
    the evaluation always reflects the post-RPKI state.
    """
    container_prefix = get_container_prefix()
    for node in nodes:
        container = f"{container_prefix}{node}"
        run_cmd(["docker", "exec", container, "vtysh", "-c", "clear ip bgp * soft in"])


def wait_for_stable_summary(
    eval_cmd: List[str],
    interval: float,
    timeout: float,
    stable_count: int,
    require_converged: bool = True,
    progress_interval: float = 15.0,
) -> Tuple[subprocess.CompletedProcess, Optional[Dict[str, str]]]:
    start = time.monotonic()
    last_sig = None
    consecutive = 0
    last_result = None
    last_summary = None
    last_report = 0.0

    while True:
        result = run_cmd(eval_cmd)
        last_result = result
        summary = parse_summary(result.stdout) if result.returncode == 0 else None
        if summary:
            last_summary = summary
            converged = summary_converged(summary) if require_converged else True
            sig = summary_signature(summary)
            if converged and sig == last_sig:
                consecutive += 1
            elif converged:
                consecutive = 1
                last_sig = sig
            else:
                # Still converging (e.g. RPKI withdrawals in flight): don't let a
                # transient plateau with no-route entries count as stable.
                consecutive = 0
                last_sig = None
            if converged and consecutive >= max(1, stable_count):
                return result, summary

        now = time.monotonic()
        if now - last_report >= progress_interval:
            elapsed = now - start
            no_route = last_summary.get("no_route", "?") if last_summary else "?"
            print(
                f"Waiting for stable summary (stable {consecutive}/{stable_count}, "
                f"no_route={no_route}); elapsed {elapsed:.0f}s"
            )
            last_report = now

        if now - start >= timeout:
            return last_result, last_summary

        time.sleep(interval)


def iter_manifest_runs(manifest: Dict, run_limit: Optional[int]) -> List[str]:
    runs = sorted((manifest.get("runs") or {}).keys())
    if run_limit:
        return runs[:run_limit]
    return runs


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deploy and evaluate randomized scenarios without manual intervention."
    )
    parser.add_argument(
        "--runs-dir",
        default=os.path.join("scenarios", "random_runs"),
        help="Root directory containing random runs (default: scenarios/random_runs).",
    )
    parser.add_argument(
        "--runs",
        type=int,
        help="Limit number of runs to process (default: all).",
    )
    parser.add_argument(
        "--tiers",
        default="1,2,3",
        help="Comma-separated list of tiers to process (default: 1,2,3).",
    )
    parser.add_argument(
        "--scenarios",
        default="all",
        help="Comma-separated list of scenario IDs or 'all' (default: all).",
    )
    parser.add_argument(
        "--settle",
        type=float,
        default=20.0,
        help="Seconds to wait after deploy before evaluation (default: 20).",
    )
    parser.add_argument(
        "--wait-bgp",
        action="store_true",
        help="Wait until all BGP sessions are established before evaluation.",
    )
    parser.add_argument(
        "--bgp-interval",
        type=float,
        default=2.0,
        help="Seconds between BGP readiness checks (default: 2).",
    )
    parser.add_argument(
        "--bgp-timeout",
        type=float,
        default=180.0,
        help="Max seconds to wait for BGP readiness (default: 180).",
    )
    parser.add_argument(
        "--wait-stable",
        action="store_true",
        help="Re-run evaluation until the summary is stable.",
    )
    parser.add_argument(
        "--wait-interval",
        type=float,
        default=5.0,
        help="Seconds between evaluation attempts when waiting (default: 5).",
    )
    parser.add_argument(
        "--wait-timeout",
        type=float,
        default=120.0,
        help="Max seconds to wait for a stable evaluation (default: 120).",
    )
    parser.add_argument(
        "--stable-count",
        type=int,
        default=2,
        help="Consecutive identical summaries required (default: 2).",
    )
    parser.add_argument(
        "--allow-unstable",
        action="store_true",
        help=(
            "Accept a summary even if some sources still have no route. By "
            "default --wait-stable keeps polling until no-route is 0, because a "
            "non-zero no-route count means BGP/RPKI has not finished converging "
            "and the numbers are not yet reproducible."
        ),
    )
    parser.add_argument(
        "--wait-rpki",
        action="store_true",
        help="Wait until RPKI cache and prefixes are ready for rpki_routers.",
    )
    parser.add_argument(
        "--rpki-interval",
        type=float,
        default=5.0,
        help="Seconds between RPKI readiness checks (default: 5).",
    )
    parser.add_argument(
        "--rpki-timeout",
        type=float,
        default=180.0,
        help="Max seconds to wait for RPKI readiness (default: 180).",
    )
    parser.add_argument(
        "--rpki-refresh",
        action="store_true",
        help=(
            "After the RPKI cache is loaded, issue 'clear ip bgp * soft in' on "
            "the RPKI routers to force immediate re-validation. Off by default: "
            "it does not change routing policy, but it perturbs the running "
            "state and adds reconvergence time. Enable only if RPKI results "
            "still vary because FRR's polling timer hasn't applied the cache yet."
        ),
    )
    parser.add_argument(
        "--sudo",
        action="store_true",
        help="Run containerlab deploy with sudo.",
    )
    parser.add_argument(
        "--no-hard-clean",
        action="store_true",
        help="Skip container cleanup between runs.",
    )
    parser.add_argument(
        "--output",
        default=os.path.join("results", "csv", "random_runs.csv"),
        help="CSV output path (default: results/csv/random_runs.csv).",
    )
    parser.add_argument(
        "--keep-going",
        action="store_true",
        help="Continue on deploy/evaluation errors.",
    )
    args = parser.parse_args()

    tiers = [int(t) for t in parse_csv_list(args.tiers)]
    scenarios = SCENARIO_SPECS if args.scenarios == "all" else parse_csv_list(args.scenarios)

    manifest_path = os.path.join(args.runs_dir, "manifest.yaml")
    manifest = load_yaml(manifest_path)
    run_keys = iter_manifest_runs(manifest, args.runs)

    if not run_keys:
        print("No runs found. Generate random scenarios first.")
        return 1

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    write_header = not os.path.exists(args.output) or os.path.getsize(args.output) == 0

    with open(args.output, "a", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "run",
                "tier",
                "scenario",
                "target",
                "censor",
                "total",
                "hijacked",
                "legit",
                "no_route",
                "other",
                "hijack_rate",
                "scenario_path",
                "error",
            ],
        )
        if write_header:
            writer.writeheader()

        for run_key in run_keys:
            run_info = (manifest.get("runs") or {}).get(run_key, {})
            for tier in tiers:
                tier_key = str(tier)
                censor_as = (run_info.get("censors") or {}).get(tier_key)
                target = run_info.get("target")

                for scenario_id in scenarios:
                    scenario_path = os.path.join(
                        args.runs_dir, run_key, f"tier{tier}", f"{scenario_id}.yaml"
                    )
                    if not os.path.exists(scenario_path):
                        writer.writerow(
                            {
                                "run": run_key,
                                "tier": tier,
                                "scenario": scenario_id,
                                "target": target or "",
                                "censor": censor_as or "",
                                "scenario_path": scenario_path,
                                "error": "scenario file missing",
                            }
                        )
                        handle.flush()
                        continue

                    print(f"Run {run_key} tier{tier} {scenario_id}: deploying...")
                    deploy_cmd = [
                        "python3",
                        "scripts/generate_topology.py",
                        "--scenario",
                        scenario_path,
                        "--no-graph",
                    ]
                    if args.sudo:
                        deploy_cmd.append("--sudo")
                    if args.no_hard_clean:
                        deploy_cmd.append("--no-hard-clean")

                    deploy_result = run_cmd(deploy_cmd)
                    if deploy_result.returncode != 0:
                        writer.writerow(
                            {
                                "run": run_key,
                                "tier": tier,
                                "scenario": scenario_id,
                                "target": target or "",
                                "censor": censor_as or "",
                                "scenario_path": scenario_path,
                                "error": "deploy failed",
                            }
                        )
                        handle.flush()
                        if not args.keep_going:
                            print(deploy_result.stdout)
                            print(deploy_result.stderr)
                            return 1
                        continue

                    print(f"Run {run_key} tier{tier} {scenario_id}: deploy ok")
                    time.sleep(args.settle)

                    if args.wait_bgp:
                        scenario_data = load_yaml(scenario_path)
                        routers = scenario_data.get("routers", [])
                        censors = [
                            c.get("name")
                            for c in (scenario_data.get("censors") or [])
                            if c.get("name")
                        ]
                        nodes = list(routers) + censors
                        ready = wait_for_bgp_ready(
                            nodes, args.bgp_interval, args.bgp_timeout
                        )
                        if not ready:
                            writer.writerow(
                                {
                                    "run": run_key,
                                    "tier": tier,
                                    "scenario": scenario_id,
                                    "target": target or "",
                                    "censor": censor_as or "",
                                    "scenario_path": scenario_path,
                                    "error": "bgp not ready",
                                }
                            )
                            handle.flush()
                            if not args.keep_going:
                                return 1
                            continue

                    if args.wait_rpki:
                        scenario_data = load_yaml(scenario_path)
                        rpki_nodes = scenario_data.get("rpki_routers", [])
                        if rpki_nodes:
                            ready = wait_for_rpki_ready(
                                rpki_nodes, args.rpki_interval, args.rpki_timeout
                            )
                            if not ready:
                                writer.writerow(
                                    {
                                        "run": run_key,
                                        "tier": tier,
                                        "scenario": scenario_id,
                                        "target": target or "",
                                        "censor": censor_as or "",
                                        "scenario_path": scenario_path,
                                        "error": "rpki not ready",
                                    }
                                )
                                handle.flush()
                                if not args.keep_going:
                                    return 1
                                continue
                            if args.rpki_refresh:
                                force_rpki_revalidation(rpki_nodes)

                    eval_cmd = [
                        "python3",
                        "scripts/evaluate_hijack_impact.py",
                        "--quiet",
                        "--scenario",
                        scenario_path,
                    ]
                    if args.wait_stable:
                        eval_result, summary = wait_for_stable_summary(
                            eval_cmd,
                            args.wait_interval,
                            args.wait_timeout,
                            args.stable_count,
                            require_converged=not args.allow_unstable,
                        )
                    else:
                        eval_result = run_cmd(eval_cmd)
                        summary = parse_summary(eval_result.stdout)
                    if eval_result.returncode != 0 or summary is None:
                        writer.writerow(
                            {
                                "run": run_key,
                                "tier": tier,
                                "scenario": scenario_id,
                                "target": target or "",
                                "censor": censor_as or "",
                                "scenario_path": scenario_path,
                                "error": "evaluation failed",
                            }
                        )
                        handle.flush()
                        if not args.keep_going:
                            print(eval_result.stdout)
                            print(eval_result.stderr)
                            return 1
                        continue

                    row_note = ""
                    if not args.allow_unstable and not summary_converged(summary):
                        row_note = f"unstable: no_route={summary.get('no_route')}"
                        print(
                            f"Run {run_key} tier{tier} {scenario_id}: did not "
                            f"converge within {args.wait_timeout:.0f}s ({row_note})"
                        )

                    writer.writerow(
                        {
                            "run": run_key,
                            "tier": tier,
                            "scenario": scenario_id,
                            "target": target or "",
                            "censor": censor_as or "",
                            "total": summary["total"],
                            "hijacked": summary["hijacked"],
                            "legit": summary["legit"],
                            "no_route": summary["no_route"],
                            "other": summary["other"],
                            "hijack_rate": summary["hijack_rate"],
                            "scenario_path": scenario_path,
                            "error": row_note,
                        }
                    )
                    handle.flush()

    print(f"Results written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
