import argparse

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
