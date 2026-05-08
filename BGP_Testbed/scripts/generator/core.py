import os
import shutil
import yaml


def ensure_repo_root():
    bash_dir = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    os.chdir(bash_dir)
    return bash_dir


def resolve_scenario_path(bash_dir, scenario_arg):
    scenario_path = scenario_arg
    if not os.path.isabs(scenario_path):
        scenario_path = os.path.join(bash_dir, scenario_path)
    if not os.path.exists(scenario_path):
        raise FileNotFoundError(f"Scenario file not found: {scenario_path}")
    return scenario_path


def reset_generated_dir():
    if os.path.exists("generated"):
        shutil.rmtree("generated")
    os.makedirs("generated/configs", exist_ok=True)


def load_scenario(path):
    with open(path, "r") as f:
        return yaml.safe_load(f)


def build_connections(links, all_nodes):
    connections = {node: [] for node in all_nodes}
    interface_counter = {node: 1 for node in all_nodes}
    link_details = []

    for link_num, link in enumerate(links):
        node_a, node_b = link

        eth_a = interface_counter[node_a]
        eth_b = interface_counter[node_b]
        interface_counter[node_a] += 1
        interface_counter[node_b] += 1

        ip_a = f"10.0.{link_num}.1/30"
        ip_b = f"10.0.{link_num}.2/30"

        connections[node_a].append(
            {
                "neighbor": node_b,
                "interface": f"eth{eth_a}",
                "ip": ip_a,
                "neighbor_ip": ip_b.split("/")[0],
            }
        )
        connections[node_b].append(
            {
                "neighbor": node_a,
                "interface": f"eth{eth_b}",
                "ip": ip_b,
                "neighbor_ip": ip_a.split("/")[0],
            }
        )

        link_details.append(
            {"endpoints": [f"{node_a}:eth{eth_a}", f"{node_b}:eth{eth_b}"]}
        )

    return connections, link_details


def write_lab_file(data, routers, censors, rpki_routers, link_details):
    topology = {
        "name": data["name"],
        "topology": {"nodes": {}, "links": []},
    }

    for router in routers:
        num = int(router.replace("router", ""))
        topology["topology"]["nodes"][router] = {
            "kind": "linux",
            "image": "frrouting/frr:latest",
            "binds": [
                f"./configs/frr{num}.conf:/etc/frr/frr.conf",
                "../configs/daemons:/etc/frr/daemons",
            ],
        }

    for censor in censors:
        censor_name = censor["name"]
        topology["topology"]["nodes"][censor_name] = {
            "kind": "linux",
            "image": "frrouting/frr:latest",
            "binds": [
                f"./configs/{censor_name}.conf:/etc/frr/frr.conf",
                "../configs/daemons:/etc/frr/daemons",
            ],
        }

    if rpki_routers:
        topology["topology"]["nodes"]["rpki-validator"] = {
            "kind": "linux",
            "image": "cloudflare/gortr",
            "cmd": "-bind :3323 -cache /roas.json -verify=false -checktime=false",
            "binds": ["./configs/roas.json:/roas.json:ro"],
        }

    topology["topology"]["links"] = link_details

    with open("generated/lab.clab.yaml", "w") as f:
        yaml.dump(topology, f, default_flow_style=False, sort_keys=False)


def write_roas(routers):
    import json

    roas_data = {"roas": []}
    for r in routers:
        r_num = int(r.replace("router", ""))
        roas_data["roas"].append(
            {
                "asn": f"AS6500{r_num}",
                "prefix": f"192.168.{r_num}.0/24",
                "maxLength": 24,
                "ta": "Testbed",
            }
        )
    with open("generated/configs/roas.json", "w") as f:
        json.dump(roas_data, f, indent=2)
