#!/usr/bin/env python3
"""Measure how long the network needs to return to normal after a hijack is withdrawn.

Two withdrawal methods (see --mode):

  graceful  The censor stays up and its BGP sessions stay alive; it stops announcing
            the hijacked prefix (`no network ...`) AND removes its blackhole FIB entry,
            i.e. the attacker fully ceases. Removing the blackhole matters for observers
            whose legitimate path transits the censor AS: otherwise the censor keeps
            dropping their traffic even after the route is withdrawn. This isolates pure
            route-withdrawal propagation + best-path reselection -- "BGP convergence".

  stop      The censor's data-plane links are brought down ("censor taken offline" /
            link cut). The neighbours must first detect the dead session (link-down
            fast-external-failover, or hold-timer expiry) before withdrawing its
            routes, so this also includes failure-detection time on top of
            convergence. (A plain `docker stop` is NOT used: restarting a Containerlab
            node loses its veth wiring -- toggling link state is the reversible analog.)

Recovery is measured per source AS, relative to the withdrawal instant, on two planes:

  control plane -- "de-hijacked": the censor ASN is no longer in the best path. This
                   is the residual-censorship duration and is the primary metric. An
                   observer that ends up with no legit route is still de-hijacked.
  data plane    -- ping to the victim loopback succeeds again. Observers that have no
                   legit route after withdrawal can never regain reachability; they
                   are reported as collateral ("reachability lost"), not as a hang.

With --runs > 1 the hijack is re-armed between runs and the tool reports mean +/- std
of the network-wide recovery (the slowest observer) for each plane and method.
"""
import argparse
import csv
import os
import re
import statistics
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

import yaml

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_LAB = os.path.join(BASE_DIR, "generated", "lab.clab.yaml")
DEFAULT_SCENARIO = os.path.join(BASE_DIR, "generated", "scenario.yaml")

# Prefix prepended to docker/vtysh invocations; populated from --sudo in main().
CMD_PREFIX: List[str] = []


def run_cmd(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(CMD_PREFIX + cmd, capture_output=True, text=True, check=False)


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


def parse_csv_list(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


# --------------------------------------------------------------------------- #
# BGP best-path parsing (kept consistent with evaluate_hijack_impact.py)
# --------------------------------------------------------------------------- #
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
            return {"network": network, "nexthop": nexthop, "path_asns": path_asns}

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
    current_block: List[str] = []

    def commit_path() -> None:
        nonlocal best_path
        if current_as_path is None:
            return
        block_text = " ".join(current_block)
        if " best" in block_text or block_text.endswith("best") or best_path is None:
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
    result = run_cmd(["docker", "exec", container, "vtysh", "-c", f"show ip bgp {prefix}"])
    if result.returncode != 0:
        return None
    return parse_best_path(result.stdout)


def resolve_best_path(
    container: str, origin_prefix: str, hijack_prefix: Optional[str]
) -> Optional[Dict[str, object]]:
    if hijack_prefix and hijack_prefix != origin_prefix:
        best = get_bgp_best(container, hijack_prefix)
        if best:
            return best
    return get_bgp_best(container, origin_prefix)


def path_is_censored(best: Optional[Dict[str, object]], censor_asns: List[int]) -> bool:
    # Traffic is censored only when the route's ORIGIN (last ASN) is the censor, i.e.
    # it terminates *at* the censor. Merely transiting *through* the censor AS toward
    # the real victim is normal forwarding, not a hijack.
    if not best:
        return False
    path_asns = best.get("path_asns", [])
    return bool(path_asns) and path_asns[-1] in censor_asns


def path_is_legit(best: Optional[Dict[str, object]], origin_asn: int) -> bool:
    if not best:
        return False
    path_asns = best.get("path_asns", [])
    return bool(path_asns) and path_asns[-1] == origin_asn


def ping_ok(container: str, dst_ip: str, src_ip: str) -> bool:
    result = run_cmd(
        ["docker", "exec", container, "ping", "-c", "1", "-W", "1", "-I", src_ip, dst_ip]
    )
    return result.returncode == 0


# --------------------------------------------------------------------------- #
# Censor control: graceful prefix withdrawal vs. hard container stop
# --------------------------------------------------------------------------- #
def get_censor_networks(container: str) -> List[str]:
    """Return the `network ...` statements the censor currently originates."""
    result = run_cmd(["docker", "exec", container, "vtysh", "-c", "show running-config"])
    return [l.strip() for l in result.stdout.splitlines() if l.strip().startswith("network ")]


def _vtysh_config(container: str, asn: int, lines: List[str]) -> None:
    cmds = ["configure terminal", f"router bgp {asn}", "address-family ipv4 unicast"] + lines
    args = ["docker", "exec", container, "vtysh"]
    for c in cmds:
        args += ["-c", c]
    run_cmd(args)


def withdraw_networks(container: str, asn: int, networks: List[str]) -> None:
    # FRR removes an originated network by prefix only -- a trailing `route-map ...`
    # in the stored statement must be stripped or the `no network` is a no-op.
    prefixes = [net.split()[1] for net in networks if len(net.split()) >= 2]
    _vtysh_config(container, asn, [f"no network {p}" for p in prefixes])


def readd_networks(container: str, asn: int, networks: List[str]) -> None:
    _vtysh_config(container, asn, list(networks))


def get_censor_blackholes(container: str) -> List[str]:
    """Static blackhole routes the censor uses to drop hijacked traffic."""
    result = run_cmd(["docker", "exec", container, "vtysh", "-c", "show running-config"])
    return [l.strip() for l in result.stdout.splitlines()
            if l.strip().startswith("ip route") and "blackhole" in l]


def set_static_routes(container: str, routes: List[str], add: bool) -> None:
    cmds = ["configure terminal"] + [(r if add else f"no {r}") for r in routes]
    args = ["docker", "exec", container, "vtysh"]
    for c in cmds:
        args += ["-c", c]
    run_cmd(args)


def censor_data_ifaces(container: str) -> List[str]:
    """Data-plane interfaces of the censor (eth1+), excluding mgmt eth0 and lo."""
    result = run_cmd(["docker", "exec", container, "sh", "-c", "ls /sys/class/net"])
    return sorted(i for i in result.stdout.split() if re.fullmatch(r"eth[1-9]\d*", i))


def set_ifaces(container: str, ifaces: List[str], up: bool) -> None:
    state = "up" if up else "down"
    for iface in ifaces:
        run_cmd(["docker", "exec", container, "ip", "link", "set", "dev", iface, state])


# --------------------------------------------------------------------------- #
# Per-observer state for a single measurement run
# --------------------------------------------------------------------------- #
class Observer:
    def __init__(self, name: str, container: str, src_ip: str):
        self.name = name
        self.container = container
        self.src_ip = src_ip
        self.censored0 = False          # captured while the hijack is still active
        self.unreachable0 = False
        self.decensor_s: Optional[float] = None    # censor ASN left the path
        self.reachable_s: Optional[float] = None    # ping to victim succeeds again
        self.reachable_possible = True              # set False once stuck without a legit route
        self._nonlegit_streak = 0

    def settled(self) -> bool:
        decensored = self.decensor_s is not None
        reach_done = self.reachable_s is not None or not self.reachable_possible
        return decensored and reach_done


def fmt(value: Optional[float]) -> str:
    return f"{value:.2f}s" if value is not None else "TIMEOUT"


# --------------------------------------------------------------------------- #
# Measurement
# --------------------------------------------------------------------------- #
def hijacked_count(observers, origin_prefix, hijack_prefix, censor_asns, pool) -> int:
    bests = list(pool.map(lambda o: resolve_best_path(o.container, origin_prefix, hijack_prefix), observers))
    return sum(1 for b in bests if path_is_censored(b, censor_asns))


def arm_hijack(observers, origin_prefix, hijack_prefix, censor_asns, pool, timeout, poll) -> int:
    """Wait until at least one observer sees the hijack again. Returns hijacked count."""
    start = time.monotonic()
    while True:
        count = hijacked_count(observers, origin_prefix, hijack_prefix, censor_asns, pool)
        if count > 0 or time.monotonic() - start > timeout:
            return count
        time.sleep(poll)


def capture_baseline(observers, dst_ip, origin_prefix, hijack_prefix, censor_asns, pool) -> None:
    """Snapshot censored/reachable state while the hijack is still active."""
    bests = list(pool.map(lambda o: resolve_best_path(o.container, origin_prefix, hijack_prefix), observers))
    pings = list(pool.map(lambda o: ping_ok(o.container, dst_ip, o.src_ip), observers))
    for obs, best, png in zip(observers, bests, pings):
        obs.censored0 = path_is_censored(best, censor_asns)
        obs.unreachable0 = not png
        if not obs.censored0:
            obs.decensor_s = 0.0
        if png:
            obs.reachable_s = 0.0


def measure_recovery(
    observers, t0, dst_ip, origin_prefix, hijack_prefix, origin_asn, censor_asns,
    pool, timeout, poll, stable_checks,
) -> None:
    next_report = 0.0
    while True:
        elapsed = time.monotonic() - t0
        if elapsed >= timeout:
            break
        pending = [o for o in observers if not o.settled()]
        if not pending:
            break

        bests = list(pool.map(lambda o: resolve_best_path(o.container, origin_prefix, hijack_prefix), pending))
        need_ping = [o for o in pending if o.reachable_s is None and o.reachable_possible]
        pings = list(pool.map(lambda o: ping_ok(o.container, dst_ip, o.src_ip), need_ping))
        now = time.monotonic() - t0

        for obs, best in zip(pending, bests):
            if obs.decensor_s is None and not path_is_censored(best, censor_asns):
                obs.decensor_s = now
            # Decide whether reachability can still be restored: an observer that is
            # de-hijacked but has no legit route (stable) will never ping the victim.
            if obs.decensor_s is not None and obs.reachable_s is None and obs.reachable_possible:
                if path_is_legit(best, origin_asn):
                    obs._nonlegit_streak = 0
                else:
                    obs._nonlegit_streak += 1
                    if obs._nonlegit_streak >= stable_checks:
                        obs.reachable_possible = False
        for obs, png in zip(need_ping, pings):
            if png:
                obs.reachable_s = now

        if now >= next_report:
            dc_left = sum(1 for o in observers if o.decensor_s is None)
            pg_left = sum(1 for o in observers if o.reachable_s is None and o.reachable_possible)
            print(f"    t={now:5.1f}s  decensor_pending={dc_left:3d}  ping_pending={pg_left:3d}")
            next_report = now + 2.0
        time.sleep(poll)


def network_recovery(observers) -> Tuple[Optional[float], Optional[float], int]:
    """Slowest observer per plane (None = some observer never recovered) + collateral count."""
    decensor = [o.decensor_s for o in observers]
    decensor_net = None if any(d is None for d in decensor) else max(decensor)

    reachable_times = [o.reachable_s for o in observers if o.reachable_s is not None]
    stuck = [o for o in observers if o.reachable_s is None and o.reachable_possible]  # legit but no ping
    lost = sum(1 for o in observers if o.reachable_s is None and not o.reachable_possible)
    reachable_net = None if stuck else (max(reachable_times) if reachable_times else 0.0)
    return decensor_net, reachable_net, lost


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--lab", default=DEFAULT_LAB, help="generated/lab.clab.yaml")
    parser.add_argument("--scenario", default=DEFAULT_SCENARIO, help="generated/scenario.yaml")
    parser.add_argument("--target", help="Override target AS (default: censor target_router).")
    parser.add_argument("--sources", help="Comma-separated observer ASes (default: all routers).")
    parser.add_argument(
        "--mode", choices=["graceful", "stop", "both"], default="graceful",
        help="Withdrawal method (default: graceful).",
    )
    parser.add_argument("--runs", type=int, default=1, help="Repetitions per mode (default: 1).")
    parser.add_argument("--poll", type=float, default=0.5, help="Polling interval seconds.")
    parser.add_argument(
        "--timeout", type=float, default=200.0,
        help="Per-run recovery timeout seconds (>= BGP hold timer for 'stop' mode).",
    )
    parser.add_argument("--arm-timeout", type=float, default=120.0, help="Max wait to re-arm hijack.")
    parser.add_argument(
        "--stable-checks", type=int, default=3,
        help="Consecutive non-legit polls after de-hijack before declaring reachability lost.",
    )
    parser.add_argument("--workers", type=int, default=16, help="Parallel docker exec workers.")
    parser.add_argument("--output", help="Optional CSV path (per run/observer detail).")
    parser.add_argument("--sudo", action="store_true", help="Prefix docker commands with sudo.")
    args = parser.parse_args()

    if args.sudo:
        CMD_PREFIX.append("sudo")

    lab = load_yaml(args.lab)
    scenario = load_scenario_snapshot(args.scenario)
    if not lab or not scenario:
        print("Could not load lab/scenario snapshot. Deploy a scenario first.")
        return 1

    routers = scenario.get("routers", [])
    censors = scenario.get("censors", [])
    if not routers or not censors:
        print("Scenario has no routers/censors.")
        return 1

    target_router = args.target or censors[0].get("target_router")
    target_num = get_node_num(target_router)
    if target_num is None:
        print("Could not determine target AS; use --target.")
        return 1

    origin_prefix = f"192.168.{target_num}.0/24"
    prefix_type = censors[0].get("prefix_type", "exact")
    hijack_prefix = f"192.168.{target_num}.0/25" if prefix_type == "subprefix" else origin_prefix
    origin_asn = 65000 + target_num
    dst_ip = f"192.168.{target_num}.1"

    censor_asns, censor_specs = [], []
    for c in censors:
        num = get_node_num(c.get("name"))
        if num is None:
            continue
        censor_asns.append(65900 + num)
        censor_specs.append({"name": c["name"], "asn": 65900 + num})

    lab_name = lab.get("name", "bgp-testbed")
    cprefix = f"clab-{lab_name}-"

    sources = parse_csv_list(args.sources) or list(routers)
    sources = [s for s in sources if s != target_router and not is_censor_name(s)]

    print(
        f"Target {target_router} (origin AS{origin_asn}, prefix {hijack_prefix}); "
        f"{len(sources)} observers; censor(s): {', '.join(c['name'] for c in censor_specs)}"
    )

    def make_observers() -> List[Observer]:
        return [Observer(s, f"{cprefix}{s}", f"192.168.{get_node_num(s)}.1") for s in sources]

    def restore(mode: str, saved: Dict[str, List[str]]) -> None:
        for c in censor_specs:
            container = f"{cprefix}{c['name']}"
            entry = saved.get(c["name"], {})
            if mode == "graceful":
                readd_networks(container, c["asn"], entry.get("nets", []))
                set_static_routes(container, entry.get("bh", []), add=True)
            else:
                set_ifaces(container, entry.get("ifaces", []), up=True)

    pool = ThreadPoolExecutor(max_workers=args.workers)
    modes = ["graceful", "stop"] if args.mode == "both" else [args.mode]
    csv_rows: List[Dict] = []
    summary: Dict[str, List[Tuple[Optional[float], Optional[float], int]]] = {m: [] for m in modes}

    try:
        for mode in modes:
            print(f"\n=== mode: {mode} ===")
            for run in range(1, args.runs + 1):
                observers = make_observers()
                armed = arm_hijack(
                    observers, origin_prefix, hijack_prefix, censor_asns, pool,
                    args.arm_timeout, args.poll,
                )
                if armed == 0:
                    print(f"  run {run}: no observer is hijacked (defense effective / not converged) "
                          f"-- skipping.")
                    summary[mode].append((0.0, 0.0, 0))
                    continue

                # Snapshot the affected set while the hijack is still active.
                capture_baseline(observers, dst_ip, origin_prefix, hijack_prefix, censor_asns, pool)
                affected = sum(1 for o in observers if o.censored0)
                if mode == "graceful":
                    saved = {c["name"]: {
                        "nets": get_censor_networks(f"{cprefix}{c['name']}"),
                        "bh": get_censor_blackholes(f"{cprefix}{c['name']}"),
                    } for c in censor_specs}
                else:
                    saved = {c["name"]: {"ifaces": censor_data_ifaces(f"{cprefix}{c['name']}")}
                             for c in censor_specs}

                print(f"  run {run}/{args.runs}: withdrawing via '{mode}' ({affected} observers hijacked)")
                t0 = time.monotonic()
                for c in censor_specs:
                    container = f"{cprefix}{c['name']}"
                    if mode == "graceful":
                        withdraw_networks(container, c["asn"], saved[c["name"]]["nets"])
                        set_static_routes(container, saved[c["name"]]["bh"], add=False)
                    else:
                        set_ifaces(container, saved[c["name"]]["ifaces"], up=False)

                try:
                    measure_recovery(
                        observers, t0, dst_ip, origin_prefix, hijack_prefix, origin_asn,
                        censor_asns, pool, args.timeout, args.poll, args.stable_checks,
                    )
                finally:
                    restore(mode, saved)

                decensor_net, reachable_net, lost = network_recovery(observers)
                summary[mode].append((decensor_net, reachable_net, lost))
                print(f"  run {run}: de-hijack={fmt(decensor_net)}  ping-recovery={fmt(reachable_net)}"
                      + (f"  reachability lost on {lost} observer(s)" if lost else ""))

                for o in observers:
                    csv_rows.append({
                        "mode": mode, "run": run, "observer": o.name,
                        "hijacked_at_t0": int(o.censored0),
                        "unreachable_at_t0": int(o.unreachable0),
                        "decensor_s": "" if o.decensor_s is None else f"{o.decensor_s:.3f}",
                        "ping_recovered_s": "" if o.reachable_s is None else f"{o.reachable_s:.3f}",
                        "reachability_lost": int(o.reachable_s is None and not o.reachable_possible),
                    })
    except KeyboardInterrupt:
        print("\nInterrupted -- censor restored to its pre-withdrawal state.")
    finally:
        pool.shutdown(wait=True)

    # Aggregate.
    print("\n===== Summary =====")

    def stat(vals):
        if not vals:
            return "n/a"
        if len(vals) == 1:
            return f"{vals[0]:.2f}s"
        return f"{statistics.mean(vals):.2f}s +/- {statistics.pstdev(vals):.2f} (n={len(vals)})"

    for mode in modes:
        runs = summary[mode]
        dc = [d for d, _, _ in runs if d is not None]
        pg = [p for _, p, _ in runs if p is not None]
        dc_to = sum(1 for d, _, _ in runs if d is None)
        lost_total = sum(l for _, _, l in runs)
        print(f"[{mode}] de-hijack (control plane): {stat(dc)}"
              + (f"  ({dc_to} timed out)" if dc_to else ""))
        print(f"[{mode}] ping recovery (data plane): {stat(pg)}"
              + (f"  ({lost_total} observer-runs lost reachability)" if lost_total else ""))

    if "graceful" in summary and "stop" in summary:
        g = [d for d, _, _ in summary["graceful"] if d is not None]
        s = [d for d, _, _ in summary["stop"] if d is not None]
        if g and s:
            print(f"\nDetection cost (stop - graceful, de-hijack): "
                  f"{statistics.mean(s) - statistics.mean(g):.2f}s")

    if args.output:
        with open(args.output, "w", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["mode", "run", "observer", "hijacked_at_t0", "unreachable_at_t0",
                            "decensor_s", "ping_recovered_s", "reachability_lost"],
            )
            writer.writeheader()
            writer.writerows(csv_rows)
        print(f"\nCSV written to {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
