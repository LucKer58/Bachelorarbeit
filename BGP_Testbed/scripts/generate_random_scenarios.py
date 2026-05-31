#!/usr/bin/env python3
import argparse
import os
import random
import re
from collections import deque
from typing import Dict, List, Optional, Tuple

import yaml


class FlowSeq(list):
    pass


class FlowDumper(yaml.SafeDumper):
    pass


def flow_seq_representer(dumper: yaml.SafeDumper, data: FlowSeq) -> yaml.SequenceNode:
    return dumper.represent_sequence("tag:yaml.org,2002:seq", data, flow_style=True)


FlowDumper.add_representer(FlowSeq, flow_seq_representer)

SCENARIO_SPECS = [
    "1_subprefix_hijack",
    "2_exact_hijack_no_pref",
    "3_exact_hijack_with_pref",
    "4_exact_hijack_with_defense",
    "5_path_poisoning",
    "6_rpki_test",
    "7_origin_spoofing_rpki",
    "8_path_forgery",
    "9_mitm_attack",
    "10_origin_code_manipulation",
]


def load_yaml(path: str) -> Dict:
    with open(path, "r") as handle:
        return yaml.safe_load(handle) or {}


def dump_yaml(path: str, payload: Dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as handle:
        yaml.dump(payload, handle, sort_keys=False, Dumper=FlowDumper)


def is_as_name(name: str) -> bool:
    return bool(re.match(r"^AS\d+$", str(name)))


def get_node_num(name: str) -> Optional[int]:
    match = re.search(r"\d+", str(name))
    return int(match.group(0)) if match else None


def parse_tier_key(key: object) -> Optional[int]:
    if isinstance(key, int):
        return key
    match = re.search(r"\d+", str(key))
    return int(match.group(0)) if match else None


def build_graph(links: List[List[str]]) -> Dict[str, List[str]]:
    graph: Dict[str, List[str]] = {}
    for node_a, node_b in links:
        graph.setdefault(node_a, []).append(node_b)
        graph.setdefault(node_b, []).append(node_a)
    return graph


def shortest_path(
    graph: Dict[str, List[str]],
    start: str,
    goal: str,
    blocked: Optional[set] = None,
) -> Optional[List[str]]:
    if start == goal:
        return [start]
    blocked = blocked or set()
    queue = deque([(start, [start])])
    visited = {start}
    while queue:
        node, path = queue.popleft()
        for neighbor in graph.get(node, []):
            if neighbor in blocked or neighbor in visited:
                continue
            if neighbor == goal:
                return path + [neighbor]
            visited.add(neighbor)
            queue.append((neighbor, path + [neighbor]))
    return None


def normalize_base_topology(data: Dict, max_as: Optional[int] = None) -> Dict:
    routers_raw = data.get("routers", [])
    tiers_raw = data.get("tiers", {}) or {}
    links_raw = data.get("links", [])

    all_nodes = set(routers_raw)
    for nodes in tiers_raw.values():
        all_nodes.update(nodes)
    for link in links_raw:
        if isinstance(link, (list, tuple)) and len(link) == 2:
            all_nodes.update(link)

    as_nodes = [r for r in all_nodes if is_as_name(r)]
    other_nodes = [r for r in all_nodes if not is_as_name(r)]

    max_num = max([get_node_num(r) or 0 for r in as_nodes], default=0)
    if max_as is not None:
        max_num = max(max_num, max_as)

    missing = [
        f"AS{idx}" for idx in range(1, max_num + 1) if f"AS{idx}" not in as_nodes
    ]
    replacements: Dict[str, str] = {}
    for node in sorted(other_nodes):
        if missing:
            replacements[node] = missing.pop(0)

    def map_node(node: str) -> str:
        return replacements.get(node, node)

    routers = [f"AS{idx}" for idx in range(1, max_num + 1)]
    tiers: Dict[str, List[str]] = {}
    for key, nodes in tiers_raw.items():
        mapped_nodes = [map_node(node) for node in nodes]
        cleaned: List[str] = []
        seen = set()
        for node in mapped_nodes:
            if node in routers and node not in seen:
                cleaned.append(node)
                seen.add(node)
        if cleaned:
            tiers[key] = cleaned
    links: List[List[str]] = []
    for link in links_raw:
        if not isinstance(link, (list, tuple)) or len(link) != 2:
            continue
        node_a = map_node(link[0])
        node_b = map_node(link[1])
        if node_a in routers and node_b in routers:
            links.append([node_a, node_b])

    return {
        "name": data.get("name", "bgp-testbed"),
        "routers": routers,
        "tiers": tiers,
        "tier_policy": data.get("tier_policy", {}),
        "links": links,
    }


def build_tier_maps(tiers: Dict[str, List[str]]) -> Tuple[Dict[int, List[str]], Dict[str, int]]:
    tiers_by_num: Dict[int, List[str]] = {}
    tier_map: Dict[str, int] = {}
    for key, nodes in tiers.items():
        tier_num = parse_tier_key(key)
        if tier_num is None:
            continue
        tiers_by_num.setdefault(tier_num, []).extend(nodes)
        for node in nodes:
            tier_map[node] = tier_num
    return tiers_by_num, tier_map


def replace_node(items: List[str], old: str, new: str) -> List[str]:
    return [new if item == old else item for item in items]


def replace_links(links: List[List[str]], old: str, new: str) -> List[List[str]]:
    updated = []
    for node_a, node_b in links:
        updated.append([
            new if node_a == old else node_a,
            new if node_b == old else node_b,
        ])
    return updated


def choose_policy_router(neighbors: List[str], tier_map: Dict[str, int]) -> Optional[str]:
    if not neighbors:
        return None
    return sorted(neighbors, key=lambda n: (tier_map.get(n, 99), n))[0]


def choose_legit_neighbor(
    graph: Dict[str, List[str]],
    policy_router: str,
    target: str,
    censor_name: str,
) -> Optional[str]:
    path = shortest_path(graph, policy_router, target, blocked={censor_name})
    if path and len(path) > 1:
        return path[1]
    for neighbor in graph.get(policy_router, []):
        if neighbor != censor_name:
            return neighbor
    return None


def build_fake_path(path_nodes: Optional[List[str]]) -> str:
    if not path_nodes:
        return ""
    without_censor = [node for node in path_nodes if not node.lower().startswith("censor")]
    if len(without_censor) >= 2:
        fake_nodes = without_censor[-2:]
    elif without_censor:
        fake_nodes = [without_censor[-1]]
    else:
        fake_nodes = []
    asns = []
    for node in fake_nodes:
        node_num = get_node_num(node)
        if node_num is not None:
            asns.append(str(65000 + node_num))
    return " ".join(asns)


def build_scenario(
    base: Dict,
    censor_as: str,
    censor_name: str,
    target: str,
    scenario_id: str,
) -> Tuple[Dict, Dict]:
    routers = [r for r in base["routers"] if r != censor_as]
    tiers = {key: replace_node(nodes, censor_as, censor_name) for key, nodes in base["tiers"].items()}
    links = [FlowSeq(pair) for pair in replace_links(base["links"], censor_as, censor_name)]

    graph = build_graph(links)
    _, tier_map = build_tier_maps(tiers)

    censor_neighbors = graph.get(censor_name, [])
    policy_router = choose_policy_router(censor_neighbors, tier_map)
    legit_neighbor = None
    if policy_router:
        legit_neighbor = choose_legit_neighbor(graph, policy_router, target, censor_name)

    path_censor_target = shortest_path(graph, censor_name, target)
    mitm_forward_node = None
    if path_censor_target and len(path_censor_target) > 1:
        mitm_forward_node = path_censor_target[1]
    elif censor_neighbors:
        mitm_forward_node = censor_neighbors[0]

    fake_path = build_fake_path(path_censor_target)
    poison_asn = None
    if legit_neighbor:
        legit_num = get_node_num(legit_neighbor)
        if legit_num is not None:
            poison_asn = 65000 + legit_num

    censor_config = {
        "name": censor_name,
        "target_router": target,
        "attack_type": "hijack",
        "prefix_type": "exact",
        "isp_mode": True,
    }

    policies: List[Dict] = []
    rpki_routers: Optional[List[str]] = None
    censor_num = get_node_num(censor_name)
    censor_asn = 65900 + censor_num if censor_num is not None else 65901

    if scenario_id == "1_subprefix_hijack":
        censor_config["prefix_type"] = "subprefix"
    elif scenario_id == "2_exact_hijack_no_pref":
        pass
    elif scenario_id == "3_exact_hijack_with_pref":
        if policy_router and legit_neighbor:
            policies.append(
                {
                    "node": policy_router,
                    "neighbor": legit_neighbor,
                    "target_node": target,
                    "local_preference": 300,
                }
            )
    elif scenario_id == "4_exact_hijack_with_defense":
        if policy_router:
            policies.append(
                {
                    "node": policy_router,
                    "neighbor": censor_name,
                    "target_node": target,
                    "prepend_asn": censor_asn,
                    "prepend_count": 5,
                }
            )
    elif scenario_id == "5_path_poisoning":
        censor_config["attack_type"] = "as_path_poisoning"
        censor_config["prefix_type"] = "subprefix"
        if poison_asn is not None:
            censor_config["poison_asn"] = poison_asn
    elif scenario_id == "6_rpki_test":
        rpki_routers = [node for node in tiers.get("tier1", []) if node != censor_name]
    elif scenario_id == "8_path_forgery":
        censor_config["attack_type"] = "as_path_forgery"
        if fake_path:
            censor_config["fake_path"] = fake_path
    elif scenario_id == "9_mitm_attack":
        censor_config["attack_type"] = "mitm"
        censor_config["prefix_type"] = "subprefix"
        if mitm_forward_node:
            censor_config["mitm_forward_node"] = mitm_forward_node
    elif scenario_id == "10_origin_code_manipulation":
        if policy_router and legit_neighbor:
            policies.append(
                {
                    "node": policy_router,
                    "neighbor": legit_neighbor,
                    "target_node": target,
                    "origin_code": "incomplete",
                }
            )
    elif scenario_id == "7_origin_spoofing_rpki":
        # Origin spoofing forges the victim's real origin ASN, so the route is
        # RPKI-valid: ROV cannot drop it. Deploying RPKI here (same routers as
        # 6_rpki_test) demonstrates the evasion -- the hijack rate stays high,
        # unlike 6_rpki_test where RPKI drops the wrong-origin hijack.
        censor_config["attack_type"] = "origin_spoofing"
        rpki_routers = [node for node in tiers.get("tier1", []) if node != censor_name]

    scenario = {
        "name": base["name"],
        "routers": routers,
        "tiers": tiers,
        "tier_policy": base.get("tier_policy", {}),
    }

    if rpki_routers is not None:
        scenario["rpki_routers"] = rpki_routers

    scenario["links"] = links
    scenario["censors"] = [censor_config]
    scenario["policies"] = policies

    context = {
        "policy_router": policy_router,
        "legit_neighbor": legit_neighbor,
        "mitm_forward_node": mitm_forward_node,
        "fake_path": fake_path,
        "poison_asn": poison_asn,
    }
    return scenario, context


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate randomized 30-AS scenarios with comparable roles across attacks."
    )
    parser.add_argument(
        "--base",
        default=os.path.join("scenarios", "sub_prefix_30.yaml"),
        help="Base topology YAML (default: scenarios/sub_prefix_30.yaml).",
    )
    parser.add_argument(
        "--out",
        default=os.path.join("scenarios", "random_runs"),
        help="Output directory for generated scenarios.",
    )
    parser.add_argument(
        "--runs",
        type=int,
        required=True,
        help="Number of randomized runs to generate.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=1337,
        help="Base RNG seed (default: 1337).",
    )
    parser.add_argument(
        "--censor-name",
        default="censor1",
        help="Censor node name (default: censor1).",
    )
    parser.add_argument(
        "--max-as",
        type=int,
        default=30,
        help="Expected max AS number in the base topology (default: 30).",
    )
    args = parser.parse_args()

    base_raw = load_yaml(args.base)
    base = normalize_base_topology(base_raw, max_as=args.max_as)
    tiers_by_num, _ = build_tier_maps(base["tiers"])

    for tier in (1, 2, 3):
        if tier not in tiers_by_num or not tiers_by_num[tier]:
            raise SystemExit(f"Tier {tier} has no routers in the base topology.")

    rng = random.Random(args.seed)
    tier3_targets = list(tiers_by_num[3])
    rng.shuffle(tier3_targets)
    target_index = 0
    last_target = None

    manifest = {
        "base": args.base,
        "seed": args.seed,
        "runs": {},
    }

    for run_idx in range(1, args.runs + 1):
        if target_index >= len(tier3_targets):
            rng.shuffle(tier3_targets)
            if (
                last_target
                and len(tier3_targets) > 1
                and tier3_targets[0] == last_target
            ):
                tier3_targets[0], tier3_targets[-1] = (
                    tier3_targets[-1],
                    tier3_targets[0],
                )
            target_index = 0

        target = tier3_targets[target_index]
        target_index += 1
        last_target = target

        censor_by_tier: Dict[int, str] = {}
        for tier in (1, 2, 3):
            candidates = [node for node in tiers_by_num[tier] if node != target]
            censor_by_tier[tier] = rng.choice(candidates)

        run_key = f"run_{run_idx:03d}"
        manifest["runs"][run_key] = {
            "target": target,
            "censors": {str(tier): censor_by_tier[tier] for tier in (1, 2, 3)},
        }

        for tier in (1, 2, 3):
            censor_as = censor_by_tier[tier]
            tier_dir = os.path.join(args.out, run_key, f"tier{tier}")
            for scenario_id in SCENARIO_SPECS:
                scenario, context = build_scenario(
                    base, censor_as, args.censor_name, target, scenario_id
                )
                file_path = os.path.join(tier_dir, f"{scenario_id}.yaml")
                dump_yaml(file_path, scenario)
                manifest["runs"][run_key].setdefault("context", {}).setdefault(
                    f"tier{tier}",
                    {},
                ).update(context)

    manifest_path = os.path.join(args.out, "manifest.yaml")
    dump_yaml(manifest_path, manifest)
    print(f"Generated scenarios in {args.out}")
    print(f"Manifest written to {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
