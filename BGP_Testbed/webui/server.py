#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import yaml

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
LAB_PATH = os.path.join(BASE_DIR, "generated", "lab.clab.yaml")
SCENARIO_PATH = os.path.join(BASE_DIR, "generated", "scenario.yaml")


def run_cmd(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=3, check=False)


def load_lab():
    if not os.path.exists(LAB_PATH):
        return None
    with open(LAB_PATH, "r") as handle:
        return yaml.safe_load(handle)


def load_scenario_snapshot():
    if not os.path.exists(SCENARIO_PATH):
        return {"meta": {}, "scenario": {}}
    with open(SCENARIO_PATH, "r") as handle:
        snapshot = yaml.safe_load(handle) or {}
    if "scenario" in snapshot:
        return {
            "meta": snapshot.get("meta", {}) or {},
            "scenario": snapshot.get("scenario", {}) or {},
        }
    return {"meta": {}, "scenario": snapshot}


def get_node_num(name):
    match = re.search(r"\d+", str(name))
    return int(match.group(0)) if match else None


def is_censor_name(name):
    return str(name).lower().startswith("censor")


def parse_best_path(output):
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
            }

    return parse_best_path_detail(output)


def parse_best_path_detail(output):
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

    def commit_path():
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


def asn_to_node_name(asn, node_map):
    if asn in node_map:
        return node_map[asn]
    return f"AS{asn}"


def build_neighbors(links):
    neighbors = {}
    for link in links:
        endpoints = link.get("endpoints", [])
        if len(endpoints) != 2:
            continue
        node_a = endpoints[0].split(":")[0]
        node_b = endpoints[1].split(":")[0]
        neighbors.setdefault(node_a, set()).add(node_b)
        neighbors.setdefault(node_b, set()).add(node_a)
    return {node: sorted(values) for node, values in neighbors.items()}


def resolve_tier(tiers, router_name):
    if not tiers:
        return None
    for key, routers in tiers.items():
        if router_name not in routers:
            continue
        if isinstance(key, int):
            return key
        match = re.search(r"\d+", str(key))
        return int(match.group(0)) if match else None
    return None


def build_node_payload(node_name, lab, snapshot):
    nodes = lab.get("topology", {}).get("nodes", {})
    if node_name not in nodes:
        return None

    scenario = snapshot.get("scenario", {})
    neighbors = build_neighbors(lab.get("topology", {}).get("links", []))

    payload = {
        "name": node_name,
        "type": "censor" if is_censor_name(node_name) else "router",
        "neighbors": neighbors.get(node_name, []),
    }

    node_num = get_node_num(node_name)
    if node_num is not None:
        if payload["type"] == "router":
            payload.update(
                {
                    "asn": 65000 + node_num,
                    "router_id": f"{node_num}.{node_num}.{node_num}.{node_num}",
                    "prefix": f"192.168.{node_num}.0/24",
                }
            )
        else:
            payload["asn"] = 65900 + node_num

    if payload["type"] == "router":
        rpki_routers = scenario.get("rpki_routers", [])
        payload["rpki_enabled"] = node_name in rpki_routers
        payload["tier"] = resolve_tier(scenario.get("tiers", {}), node_name)
    else:
        censors = scenario.get("censors", [])
        censor_info = next((c for c in censors if c.get("name") == node_name), {})
        payload.update(
            {
                "attack_type": censor_info.get("attack_type"),
                "target_router": censor_info.get("target_router"),
                "prefix_type": censor_info.get("prefix_type", "exact"),
                "mitm_forward_node": censor_info.get("mitm_forward_node"),
                "community": censor_info.get("community"),
                "poison_asn": censor_info.get("poison_asn"),
                "prepend_asn": censor_info.get("prepend_asn"),
                "prepend_count": censor_info.get("prepend_count"),
                "fake_path": censor_info.get("fake_path"),
                "origin_code": censor_info.get("origin_code"),
            }
        )
        target_match = re.search(r"\d+", censor_info.get("target_router", ""))
        if target_match:
            target_num = int(target_match.group(0))
            prefix_type = payload.get("prefix_type")
            if prefix_type == "subprefix":
                payload["prefix"] = f"192.168.{target_num}.0/25"
            else:
                payload["prefix"] = f"192.168.{target_num}.0/24"

    return payload


def build_path_nodes(source, best, node_map):
    path_nodes = [source]
    for asn in best.get("path_asns", []):
        path_nodes.append(asn_to_node_name(asn, node_map))
    return path_nodes


def get_best_path(container_prefix, source, target_num):
    origin_prefix = f"192.168.{target_num}.0/24"
    hijack_prefix = f"192.168.{target_num}.0/25"
    container = f"{container_prefix}{source}"

    hijack_cmd = [
        "docker",
        "exec",
        container,
        "vtysh",
        "-c",
        f"show ip bgp {hijack_prefix}",
    ]
    hijack_out = run_cmd(hijack_cmd)
    hijack_best = parse_best_path(hijack_out.stdout) if hijack_out.returncode == 0 else None

    origin_cmd = [
        "docker",
        "exec",
        container,
        "vtysh",
        "-c",
        f"show ip bgp {origin_prefix}",
    ]
    origin_out = run_cmd(origin_cmd)
    origin_best = parse_best_path(origin_out.stdout) if origin_out.returncode == 0 else None

    if hijack_best:
        return hijack_best, hijack_prefix
    if origin_best:
        return origin_best, origin_prefix
    return None, None


def load_censor_forward_node(censor_name, prefix, node_map):
    conf_path = os.path.join(BASE_DIR, "generated", "configs", f"{censor_name}.conf")
    if not os.path.exists(conf_path):
        return None

    next_hop = None
    neighbor_ip_to_asn = {}

    with open(conf_path, "r") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            route_match = re.match(r"^ip route\s+(\S+)\s+(\S+)$", line)
            if route_match and route_match.group(1) == prefix:
                next_hop = route_match.group(2)
                continue

            neighbor_match = re.match(r"^neighbor\s+(\S+)\s+remote-as\s+(\d+)$", line)
            if neighbor_match:
                neighbor_ip_to_asn[neighbor_match.group(1)] = int(neighbor_match.group(2))

    if not next_hop or next_hop == "blackhole":
        return None

    asn = neighbor_ip_to_asn.get(next_hop)
    if not asn:
        return None

    return asn_to_node_name(asn, node_map)


def resolve_route(source, target):
    lab = load_lab()
    if not lab:
        return {"error": "lab.clab.yaml not found. Generate topology first."}

    lab_name = lab.get("name", "bgp-testbed")
    container_prefix = f"clab-{lab_name}-"
    container = f"{container_prefix}{source}"

    target_match = re.search(r"\d+", target)
    source_match = re.search(r"\d+", source)
    if not target_match or not source_match:
        return {"error": "Invalid source or target."}

    target_num = int(target_match.group(0))
    source_num = int(source_match.group(0))

    best, used_prefix = get_best_path(container_prefix, source, target_num)
    if not best or not used_prefix:
        return {"error": "No BGP path found for target."}

    nodes = lab.get("topology", {}).get("nodes", {})
    node_map = {}
    for name in nodes.keys():
        node_num = get_node_num(name)
        if node_num is None:
            continue
        if is_censor_name(name):
            node_map[65900 + node_num] = name
        else:
            node_map[65000 + node_num] = name

    path_nodes = build_path_nodes(source, best, node_map)

    hijack_censor = None
    for asn in best.get("path_asns", []):
        if 65900 <= asn < 66000:
            hijack_censor = node_map.get(asn, f"AS{asn}")
            break

    forward_node = None
    if hijack_censor:
        forward_node = load_censor_forward_node(hijack_censor, used_prefix, node_map)
    if forward_node and forward_node != hijack_censor:
        forward_best, _ = get_best_path(container_prefix, forward_node, target_num)
        if forward_best:
            forward_path = build_path_nodes(forward_node, forward_best, node_map)
        else:
            forward_path = [forward_node]

        if hijack_censor in path_nodes:
            idx = path_nodes.index(hijack_censor)
            merged = path_nodes[: idx + 1]
            for node in forward_path:
                if merged and merged[-1] == node:
                    continue
                merged.append(node)
            path_nodes = merged
        else:
            for node in forward_path:
                if path_nodes and path_nodes[-1] == node:
                    continue
                path_nodes.append(node)

    ping_cmd = [
        "docker",
        "exec",
        container,
        "ping",
        "-c",
        "1",
        "-W",
        "1",
        "-I",
        f"192.168.{source_num}.1",
        f"192.168.{target_num}.1",
    ]
    ping_out = run_cmd(ping_cmd)
    ping_ok = ping_out.returncode == 0

    hijack_active = hijack_censor is not None
    if not ping_ok and hijack_active:
        message = (
            f"Ping failed: hijack by {hijack_censor} on {target} is active."
        )
    elif not ping_ok:
        message = "Ping failed: verify reachability or BGP state."
    elif hijack_active:
        message = f"Hijack active via {hijack_censor}, but ping still succeeds."
    else:
        message = "Ping succeeded: route follows the legit origin."

    return {
        "source": source,
        "target": target,
        "used_prefix": used_prefix,
        "next_hop": best.get("nexthop"),
        "path_asns": best.get("path_asns"),
        "path_nodes": path_nodes,
        "hijack_active": hijack_active,
        "hijack_censor": hijack_censor,
        "ping_ok": ping_ok,
        "message": message,
    }


def load_topology_payload():
    lab = load_lab()
    if not lab:
        return {"error": "lab.clab.yaml not found. Generate topology first."}

    snapshot = load_scenario_snapshot()
    scenario = snapshot.get("scenario", {})
    meta = snapshot.get("meta", {})

    nodes = lab.get("topology", {}).get("nodes", {})
    links = lab.get("topology", {}).get("links", [])

    payload_nodes = []
    for name in nodes.keys():
        node_type = "censor" if is_censor_name(name) else "router"
        payload_nodes.append({"id": name, "type": node_type})

    payload_links = []
    for link in links:
        endpoints = link.get("endpoints", [])
        if len(endpoints) != 2:
            continue
        node_a = endpoints[0].split(":")[0]
        node_b = endpoints[1].split(":")[0]
        payload_links.append({"source": node_a, "target": node_b})

    router_count = len([n for n in payload_nodes if n["type"] == "router"])
    censor_count = len([n for n in payload_nodes if n["type"] == "censor"])
    scenario_payload = {
        "name": scenario.get("name"),
        "source": meta.get("source"),
        "router_count": scenario.get("routers") and len(scenario.get("routers", [])) or router_count,
        "censor_count": scenario.get("censors") and len(scenario.get("censors", [])) or censor_count,
    }

    return {
        "nodes": payload_nodes,
        "links": payload_links,
        "lab_name": lab.get("name"),
        "scenario": scenario_payload,
    }


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        super().end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/topology":
            payload = load_topology_payload()
            return self._send_json(payload)
        if parsed.path == "/api/route":
            params = parse_qs(parsed.query)
            source = params.get("source", [""])[0]
            target = params.get("target", [""])[0]
            if not source or not target:
                return self._send_json({"error": "source and target required"}, 400)
            payload = resolve_route(source, target)
            status = 200 if "error" not in payload else 400
            return self._send_json(payload, status)
        if parsed.path == "/api/node":
            params = parse_qs(parsed.query)
            name = params.get("name", [""])[0]
            if not name:
                return self._send_json({"error": "name required"}, 400)
            lab = load_lab()
            if not lab:
                return self._send_json(
                    {"error": "lab.clab.yaml not found. Generate topology first."},
                    400,
                )
            snapshot = load_scenario_snapshot()
            payload = build_node_payload(name, lab, snapshot)
            if not payload:
                return self._send_json({"error": "node not found"}, 404)
            return self._send_json(payload)

        if parsed.path == "/":
            self.path = "/index.html"
        return super().do_GET()

    def _send_json(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser(description="BGP testbed web UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Serving on http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
