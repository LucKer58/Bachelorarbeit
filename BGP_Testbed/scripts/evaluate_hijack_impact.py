#!/usr/bin/env python3
import argparse
import csv
import os
import re
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

import yaml

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_LAB = os.path.join(BASE_DIR, "generated", "lab.clab.yaml")
DEFAULT_SCENARIO = os.path.join(BASE_DIR, "generated", "scenario.yaml")


def run_cmd(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def load_yaml(path: str) -> Dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r") as handle:
        return yaml.safe_load(handle) or {}


def load_scenario_snapshot(path: str) -> Dict:
    snapshot = load_yaml(path)
    if "scenario" in snapshot:
        return snapshot.get("scenario", {}) or {}
    return snapshot


def get_node_num(name: str) -> Optional[int]:
    match = re.search(r"\d+", str(name))
    return int(match.group(0)) if match else None


def is_censor_name(name: str) -> bool:
    return str(name).lower().startswith("censor")


def parse_best_path(output: str) -> Optional[Dict[str, object]]:
    if "Network not in table" in output:
        return None

    for line in output.splitlines():
        if line.lstrip().startswith("*>"):
            parts = line.split(None, 3)
            if len(parts) < 4:
                return None
            _, network, nexthop, rest = parts
            path_asns = [int(x) for x in re.findall(r"\b\d+\b", rest)]
            return {
                "network": network,
                "nexthop": nexthop,
                "path_asns": path_asns,
                "raw": line,
            }

    return parse_best_path_detail(output)


def parse_best_path_detail(output: str) -> Optional[Dict[str, object]]:
    network = None
    lines = output.splitlines()
    for line in lines:
        if line.startswith("BGP routing table entry for "):
            network = line.split("for ", 1)[1].split(",", 1)[0].strip()
            break

    best_path = None
    current_as_path = None
    current_nexthop = None
    current_block = []

    def commit_path() -> None:
        nonlocal best_path
        if current_as_path is None:
            return
        block_text = " ".join(current_block)
        if " best" in block_text or block_text.endswith("best"):
            best_path = {
                "network": network,
                "nexthop": current_nexthop,
                "path_asns": current_as_path,
            }
        elif best_path is None:
            best_path = {
                "network": network,
                "nexthop": current_nexthop,
                "path_asns": current_as_path,
            }

    for idx, line in enumerate(lines):
        if re.match(r"^\s+\d+(\s+\d+)*\s*$", line):
            commit_path()
            current_as_path = [int(x) for x in re.findall(r"\b\d+\b", line)]
            current_nexthop = None
            current_block = []

            if idx + 1 < len(lines):
                match = re.search(
                    r"(\d+\.\d+\.\d+\.\d+)\s+from\s+(\d+\.\d+\.\d+\.\d+)",
                    lines[idx + 1],
                )
                if match:
                    current_nexthop = match.group(1)
            continue

        if current_as_path is not None:
            current_block.append(line.strip())

    commit_path()
    return best_path


def get_bgp_best(container: str, prefix: str) -> Optional[Dict[str, object]]:
    cmd = ["docker", "exec", container, "vtysh", "-c", f"show ip bgp {prefix}"]
    result = run_cmd(cmd)
    if result.returncode != 0:
        return None
    return parse_best_path(result.stdout)


def resolve_best_path(
    container_prefix: str,
    source: str,
    origin_prefix: str,
    hijack_prefix: Optional[str],
) -> Tuple[Optional[Dict[str, object]], Optional[str]]:
    container = f"{container_prefix}{source}"

    if hijack_prefix and hijack_prefix != origin_prefix:
        hijack_best = get_bgp_best(container, hijack_prefix)
        if hijack_best:
            return hijack_best, hijack_prefix

    origin_best = get_bgp_best(container, origin_prefix)
    if origin_best:
        return origin_best, origin_prefix

    return None, None


def classify_path(
    best: Optional[Dict[str, object]],
    origin_asn: int,
    censor_asns: List[int],
) -> str:
    if not best:
        return "no-route"
    path_asns = best.get("path_asns", [])
    if any(asn in censor_asns for asn in path_asns):
        return "hijacked"
    if path_asns and path_asns[-1] == origin_asn:
        return "legit"
    return "other"


def parse_csv_list(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate how many routers are routed to the censor vs. the legit target."
    )
    parser.add_argument(
        "--lab",
        default=DEFAULT_LAB,
        help="Path to generated lab.clab.yaml (default: generated/lab.clab.yaml).",
    )
    parser.add_argument(
        "--scenario",
        default=DEFAULT_SCENARIO,
        help="Path to generated scenario.yaml (default: generated/scenario.yaml).",
    )
    parser.add_argument(
        "--target",
        help="Override target AS (e.g. AS21). Defaults to censor target_router.",
    )
    parser.add_argument(
        "--sources",
        help="Comma-separated list of source ASes. Defaults to all routers.",
    )
    parser.add_argument(
        "--include-target",
        action="store_true",
        help="Include the target AS as a source.",
    )
    parser.add_argument(
        "--include-censors",
        action="store_true",
        help="Include censor nodes as sources.",
    )
    parser.add_argument(
        "--output",
        help="Optional CSV output path.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Do not print per-source results.",
    )
    args = parser.parse_args()

    lab = load_yaml(args.lab)
    if not lab:
        print(f"Lab file not found: {args.lab}")
        return 1

    scenario = load_scenario_snapshot(args.scenario)
    if not scenario:
        print(f"Scenario snapshot not found: {args.scenario}")
        return 1

    routers = scenario.get("routers", [])
    censors = scenario.get("censors", [])
    if not routers:
        print("No routers found in scenario.")
        return 1
    if not censors:
        print("No censor found in scenario.")
        return 1

    target_router = args.target
    if not target_router:
        target_router = censors[0].get("target_router")
    if not target_router:
        print("Target router not found. Use --target to set it.")
        return 1

    target_num = get_node_num(target_router)
    if target_num is None:
        print(f"Invalid target router: {target_router}")
        return 1

    prefix_type = censors[0].get("prefix_type", "exact")
    origin_prefix = f"192.168.{target_num}.0/24"
    hijack_prefix = origin_prefix
    if prefix_type == "subprefix":
        hijack_prefix = f"192.168.{target_num}.0/25"

    censor_asns = []
    censor_names = []
    for censor in censors:
        name = censor.get("name")
        if not name:
            continue
        censor_names.append(name)
        num = get_node_num(name)
        if num is not None:
            censor_asns.append(65900 + num)

    if not censor_asns:
        print("No valid censor ASNs found in scenario.")
        return 1

    origin_asn = 65000 + target_num

    lab_name = lab.get("name", "bgp-testbed")
    container_prefix = f"clab-{lab_name}-"

    sources = parse_csv_list(args.sources) or list(routers)
    if not args.include_target and target_router in sources:
        sources.remove(target_router)
    if not args.include_censors:
        sources = [s for s in sources if not is_censor_name(s)]

    results = []
    for source in sources:
        best, used_prefix = resolve_best_path(
            container_prefix, source, origin_prefix, hijack_prefix
        )
        outcome = classify_path(best, origin_asn, censor_asns)
        hijack_censor = None
        if best:
            for asn in best.get("path_asns", []):
                if asn in censor_asns:
                    idx = censor_asns.index(asn)
                    hijack_censor = censor_names[idx]
                    break

        results.append(
            {
                "source": source,
                "result": outcome,
                "used_prefix": used_prefix,
                "hijack_censor": hijack_censor,
                "path_asns": " ".join(str(a) for a in best.get("path_asns", []))
                if best
                else "",
            }
        )

        if not args.quiet:
            if outcome == "hijacked":
                print(
                    f"{source}: hijacked via {hijack_censor or 'censor'} "
                    f"(prefix {used_prefix})"
                )
            elif outcome == "legit":
                print(f"{source}: legit (prefix {used_prefix})")
            elif outcome == "no-route":
                print(f"{source}: no route")
            else:
                print(f"{source}: other path (prefix {used_prefix})")

    total = len(results)
    hijacked = sum(1 for r in results if r["result"] == "hijacked")
    legit = sum(1 for r in results if r["result"] == "legit")
    no_route = sum(1 for r in results if r["result"] == "no-route")
    other = total - hijacked - legit - no_route

    if total:
        percent = (hijacked / total) * 100.0
    else:
        percent = 0.0

    print(
        f"\nSummary: total={total} hijacked={hijacked} legit={legit} "
        f"no-route={no_route} other={other} hijack_rate={percent:.1f}%"
    )

    if args.output:
        with open(args.output, "w", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["source", "result", "used_prefix", "hijack_censor", "path_asns"],
            )
            writer.writeheader()
            writer.writerows(results)
        print(f"CSV written to {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
