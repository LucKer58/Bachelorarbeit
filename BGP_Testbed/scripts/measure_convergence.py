#!/usr/bin/env python3
import argparse
import re
import subprocess
import sys
import time
from typing import Dict, List, Optional


def run_cmd(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def router_container(router: str, prefix: str) -> str:
    return f"{prefix}{router}"


def parse_best_path(output: str) -> Optional[Dict[str, object]]:
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
    return None


def parse_best_path_detail(output: str) -> Optional[Dict[str, object]]:
    lines = output.splitlines()
    network = None
    for line in lines:
        if line.startswith("BGP routing table entry for "):
            network = line.split("for ", 1)[1].split(",", 1)[0].strip()
            break

    as_path = None
    nexthop = None
    for i, line in enumerate(lines):
        if re.match(r"^\s+\d+(\s+\d+)*\s*$", line):
            as_path = [int(x) for x in re.findall(r"\b\d+\b", line)]
            if i + 1 < len(lines):
                next_line = lines[i + 1]
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+from\s+(\d+\.\d+\.\d+\.\d+)", next_line)
                if match:
                    nexthop = match.group(1)
            break

    if as_path is None:
        return None

    return {
        "network": network,
        "nexthop": nexthop,
        "path_asns": as_path,
        "raw": output,
    }


def get_bgp_best(container: str, prefix: str) -> Optional[Dict[str, object]]:
    cmd = ["docker", "exec", container, "vtysh", "-c", f"show ip bgp {prefix}"]
    result = run_cmd(cmd)
    if result.returncode != 0:
        return None
    best = parse_best_path(result.stdout)
    if best:
        return best
    return parse_best_path_detail(result.stdout)


def ping_once(container: str, dst_ip: str, src_ip: str) -> bool:
    cmd = [
        "docker",
        "exec",
        container,
        "ping",
        "-c",
        "1",
        "-W",
        "1",
        "-I",
        src_ip,
        dst_ip,
    ]
    result = run_cmd(cmd)
    return result.returncode == 0


def is_origin_best(best: Optional[Dict[str, object]], origin_asn: int) -> bool:
    if not best:
        return False
    path_asns = best.get("path_asns", [])
    if not path_asns:
        return False
    return path_asns[-1] == origin_asn


def write_event(log_fp, event: str, elapsed: float) -> None:
    if not log_fp:
        return
    log_fp.write(f"{elapsed:.3f},{event}\n")
    log_fp.flush()


def stop_container(container: str) -> bool:
    result = run_cmd(["docker", "stop", container])
    return result.returncode == 0


def start_container(container: str) -> bool:
    result = run_cmd(["docker", "start", container])
    return result.returncode == 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Measure BGP convergence and ping recovery after a hijack withdrawal."
    )
    parser.add_argument("--observer", default="AS1", help="Observer AS name.")
    parser.add_argument("--container-prefix", default="clab-bgp-testbed-", help="Container name prefix.")
    parser.add_argument("--origin-prefix", default="192.168.3.0/24", help="Legit prefix.")
    parser.add_argument("--hijack-prefix", default="192.168.3.0/25", help="Hijack subprefix.")
    parser.add_argument("--origin-asn", type=int, default=65003, help="Origin ASN for the legit prefix.")
    parser.add_argument("--ping-ip", default="192.168.3.1", help="Ping destination.")
    parser.add_argument("--src-ip", default="192.168.1.1", help="Ping source address.")
    parser.add_argument("--poll", type=float, default=0.2, help="Polling interval in seconds.")
    parser.add_argument("--timeout", type=float, default=120.0, help="Timeout in seconds.")
    parser.add_argument("--output", help="Optional CSV output path.")
    parser.add_argument(
        "--censor-container",
        default="clab-bgp-testbed-censor1",
        help="Censor container name for auto-withdraw/restore.",
    )
    parser.add_argument(
        "--auto-withdraw",
        action="store_true",
        help="Stop the censor container and start timing immediately.",
    )
    parser.add_argument(
        "--auto-restore",
        action="store_true",
        help="Start the censor container after measurement finishes.",
    )
    parser.add_argument(
        "--wait-hijack",
        action="store_true",
        help="Wait until the hijack prefix is visible before auto-withdraw.",
    )
    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="Start measuring immediately without waiting for Enter.",
    )
    args = parser.parse_args()

    container = router_container(args.observer, args.container_prefix)

    if args.auto_withdraw:
        if args.wait_hijack:
            print("Waiting for hijack prefix to appear...")
            wait_start = time.monotonic()
            while True:
                best_hijack = get_bgp_best(container, args.hijack_prefix)
                if best_hijack is not None:
                    break
                if time.monotonic() - wait_start > args.timeout:
                    print("Timeout waiting for hijack prefix.")
                    return 1
                time.sleep(args.poll)
        print(f"Stopping censor container {args.censor_container}...")
        if not stop_container(args.censor_container):
            print("Failed to stop censor container.")
            return 1
        start = time.monotonic()
    else:
        if not args.no_prompt:
            print("Trigger the hijack withdrawal, then press Enter to start measuring.")
            try:
                input()
            except EOFError:
                pass
        start = time.monotonic()

    log_fp = open(args.output, "w") if args.output else None
    if log_fp:
        log_fp.write("elapsed_s,event\n")

    bgp_recovered_at = None
    ping_recovered_at = None
    next_report = 0.0

    while True:
        now = time.monotonic()
        elapsed = now - start

        if elapsed >= args.timeout:
            print("Timeout reached without full recovery.")
            break

        best_hijack = get_bgp_best(container, args.hijack_prefix)
        best_origin = get_bgp_best(container, args.origin_prefix)
        hijack_active = best_hijack is not None
        bgp_ok = (not hijack_active) and is_origin_best(best_origin, args.origin_asn)

        if bgp_ok and bgp_recovered_at is None:
            bgp_recovered_at = elapsed
            print(f"BGP recovered at {bgp_recovered_at:.3f}s")
            write_event(log_fp, "bgp_recovered", bgp_recovered_at)

        ping_ok = ping_once(container, args.ping_ip, args.src_ip)
        if ping_ok and ping_recovered_at is None:
            ping_recovered_at = elapsed
            print(f"Ping recovered at {ping_recovered_at:.3f}s")
            write_event(log_fp, "ping_recovered", ping_recovered_at)

        if elapsed >= next_report:
            status = "ok" if ping_ok else "fail"
            hijack_state = "active" if hijack_active else "withdrawn"
            print(
                f"t={elapsed:.1f}s hijack={hijack_state} bgp_ok={bgp_ok} ping={status}"
            )
            next_report = elapsed + 1.0

        if bgp_recovered_at is not None and ping_recovered_at is not None:
            break

        time.sleep(args.poll)

    if bgp_recovered_at is not None:
        print(f"BGP convergence: {bgp_recovered_at:.3f}s")
    if ping_recovered_at is not None:
        print(f"Ping recovery: {ping_recovered_at:.3f}s")

    if log_fp:
        log_fp.close()

    if args.auto_restore:
        print(f"Starting censor container {args.censor_container}...")
        if not start_container(args.censor_container):
            print("Failed to start censor container.")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
