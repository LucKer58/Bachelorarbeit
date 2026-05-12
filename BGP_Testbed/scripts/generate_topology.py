import argparse
import re

from generator.censor_config import build_censor_configs
from generator.core import (
    build_connections,
    ensure_repo_root,
    load_scenario,
    reset_generated_dir,
    resolve_scenario_path,
    write_lab_file,
    write_roas,
)
from generator.deploy import run_deploy
from generator.router_config import build_router_configs


DEFAULT_SCENARIO = "scenarios/base_case_30.yaml"


def build_tier_policies(data, links):
    tiers = data.get("tiers")
    policy_cfg = data.get("tier_policy", {})
    if not tiers or not policy_cfg:
        return []

    model = policy_cfg.get("model", "gao-rexford")
    if model != "gao-rexford":
        return []

    tier_map = {}
    for key, routers in tiers.items():
        if isinstance(key, int):
            tier_num = key
        else:
            match = re.search(r"\d+", str(key))
            if not match:
                continue
            tier_num = int(match.group(0))
        for router in routers:
            tier_map[router] = tier_num

    neighbors = {router: set() for router in tier_map}
    for node_a, node_b in links:
        if node_a in neighbors:
            neighbors[node_a].add(node_b)
        if node_b in neighbors:
            neighbors[node_b].add(node_a)

    local_prefs = policy_cfg.get("local_pref", {})
    customer_pref = local_prefs.get("customer", 200)
    peer_pref = local_prefs.get("peer", 100)
    provider_pref = local_prefs.get("provider", 50)

    policies = []
    for router, router_neighbors in neighbors.items():
        router_tier = tier_map[router]
        for neighbor in router_neighbors:
            neighbor_tier = tier_map.get(neighbor)
            if neighbor_tier is None:
                continue
            if neighbor_tier > router_tier:
                pref = customer_pref
            elif neighbor_tier < router_tier:
                pref = provider_pref
            else:
                if peer_pref == 100:
                    continue
                pref = peer_pref

            policies.append(
                {
                    "node": router,
                    "neighbor": neighbor,
                    "match": "all",
                    "local_preference": pref,
                }
            )

    return policies


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate Containerlab topology and configs."
    )
    parser.add_argument(
        "--scenario",
        default=DEFAULT_SCENARIO,
        help="Path to the scenario YAML (relative to repo root or absolute).",
    )
    parser.add_argument(
        "--no-deploy",
        action="store_true",
        help="Only generate files; do not run containerlab deploy.",
    )
    parser.add_argument(
        "--sudo",
        action="store_true",
        help="Run containerlab deploy with sudo.",
    )
    parser.add_argument(
        "--no-graph",
        action="store_true",
        help="Do not generate the containerlab graph.",
    )
    parser.add_argument(
        "--no-hard-clean",
        action="store_true",
        help="Skip force-removal of lab containers before deploy.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    bash_dir = ensure_repo_root()
    scenario_path = resolve_scenario_path(bash_dir, args.scenario)

    reset_generated_dir()
    data = load_scenario(scenario_path)

    routers = data["routers"]
    censors = data.get("censors", [])
    rpki_routers = data.get("rpki_routers", [])
    links = data["links"]
    policies = data.get("policies", [])
    tier_policies = build_tier_policies(data, links)
    if tier_policies:
        policies = policies + tier_policies

    all_nodes = routers + [c["name"] for c in censors]
    connections, link_details = build_connections(links, all_nodes)

    write_lab_file(data, routers, censors, rpki_routers, link_details)
    if rpki_routers:
        write_roas(routers)

    build_router_configs(routers, connections, policies, rpki_routers)
    build_censor_configs(censors, connections, policies)

    run_deploy(args, bash_dir)


if __name__ == "__main__":
    main()
