from collections import defaultdict

from generator.core import get_node_num

COMMUNITY_FROM_CUSTOMER = "65000:1"
COMMUNITY_FROM_PEER = "65000:2"
COMMUNITY_FROM_PROVIDER = "65000:3"
COMMUNITY_LIST_NON_CUSTOMER = "CL-NON-CUSTOMER"
COMMUNITY_LIST_CUSTOMER = "CL-CUSTOMER"
COMMUNITY_LIST_RELATION = "CL-RELATION"
ORIGIN_ROUTE_MAP = "RM-ORIGIN-CUSTOMER"
RELATION_COMMUNITY = {
    "customer": COMMUNITY_FROM_CUSTOMER,
    "peer": COMMUNITY_FROM_PEER,
    "provider": COMMUNITY_FROM_PROVIDER,
}


def build_censor_configs(censors, connections, policies, customer_cones=None):
    customer_cones = customer_cones or {}
    for censor in censors:
        censor_name = censor["name"]
        censor_num = get_node_num(censor_name)
        target_router = censor["target_router"]
        target_num = get_node_num(target_router)
        hijack_target_num = target_num
        attack_type = censor["attack_type"]
        prefix_type = censor.get("prefix_type", "exact")
        use_tier_policy = bool(
            censor.get("isp_mode") or censor.get("follow_tier_policy")
        )
        censor_connections = connections[censor_name]
        censor_asn = 65900 + censor_num

        config = f"""frr defaults traditional
!
hostname {censor_name}
!"""

        for conn in censor_connections:
            config += f"""
interface {conn['interface']}
 ip address {conn['ip']}
!"""

        config += f"""
interface lo
 ip address 10.255.255.{censor_num}/32
!"""

        static_routes = ""
        networks = ""
        route_maps = ""
        attack_rmap_name = f"RM-ATTACK-{attack_type.upper()}"

        my_censor_policies = [p for p in policies if p["node"] == censor_name]
        policies_by_neighbor_censor = defaultdict(list)
        neighbor_relationships = {}
        for p in my_censor_policies:
            policies_by_neighbor_censor[p["neighbor"]].append(p)
            relation = p.get("relationship")
            if relation:
                neighbor_relationships[p["neighbor"]] = relation

        censor_prefix_lists = ""
        censor_in_route_maps = ""
        censor_neighbor_in_rmaps = {}
        community_lists = ""
        censor_out_route_maps = ""
        censor_neighbor_out_rmaps = {}
        use_communities = False

        for neighbor, pols in policies_by_neighbor_censor.items():
            rmap_name = f"RM-IN-{neighbor.upper()}"
            seq = 10
            neighbor_ip = next(
                c["neighbor_ip"]
                for c in censor_connections
                if c["neighbor"] == neighbor
            )

            censor_neighbor_in_rmaps[neighbor_ip] = rmap_name

            default_local_pref = None
            relation = neighbor_relationships.get(neighbor)
            community_tag = RELATION_COMMUNITY.get(relation)
            if community_tag and use_tier_policy:
                use_communities = True

            for p in pols:
                if p.get("match") == "all":
                    if "local_preference" in p:
                        default_local_pref = p["local_preference"]
                    seq += 10
                    continue

                policy_target = p.get("target_node")
                if not policy_target:
                    continue
                policy_target_num = get_node_num(policy_target)
                plist_name = f"PFX-{policy_target.upper()}"

                if f"ip prefix-list {plist_name}" not in censor_prefix_lists:
                    censor_prefix_lists += f"""
ip prefix-list {plist_name} seq 5 permit 192.168.{policy_target_num}.0/24
!"""

                censor_in_route_maps += f"""
route-map {rmap_name} permit {seq}
 match ip address prefix-list {plist_name}"""

                if "local_preference" in p:
                    censor_in_route_maps += f"\n set local-preference {p['local_preference']}"

                if "prepend_asn" in p:
                    prepend_count = p.get("prepend_count", 3)
                    prepend = " ".join([str(p["prepend_asn"])] * prepend_count)
                    censor_in_route_maps += f"\n set as-path prepend {prepend}"

                if "origin_code" in p:
                    censor_in_route_maps += f"\n set origin {p['origin_code']}"

                if community_tag and use_tier_policy:
                    censor_in_route_maps += f"\n set community {COMMUNITY_LIST_RELATION} delete"
                    censor_in_route_maps += f"\n set community {community_tag} additive"

                censor_in_route_maps += "\n!\n"
                seq += 10

            censor_in_route_maps += f"""
route-map {rmap_name} permit {seq}"""
            if default_local_pref is not None:
                censor_in_route_maps += f"\n set local-preference {default_local_pref}"
            if community_tag and use_tier_policy:
                censor_in_route_maps += f"\n set community {COMMUNITY_LIST_RELATION} delete"
                censor_in_route_maps += f"\n set community {community_tag} additive"
            censor_in_route_maps += "\n!"

            if use_tier_policy and relation in {"peer", "provider"}:
                out_name = f"RM-OUT-{neighbor.upper()}"
                censor_neighbor_out_rmaps[neighbor_ip] = out_name
                censor_out_route_maps += f"""
route-map {out_name} deny 5
 match community {COMMUNITY_LIST_NON_CUSTOMER}
!
route-map {out_name} permit 10
 match community {COMMUNITY_LIST_CUSTOMER}
!
route-map {out_name} deny 20
!"""

        if use_communities and not community_lists:
            community_lists = f"""
bgp community-list standard {COMMUNITY_LIST_RELATION} permit {COMMUNITY_FROM_CUSTOMER}
bgp community-list standard {COMMUNITY_LIST_RELATION} permit {COMMUNITY_FROM_PEER}
bgp community-list standard {COMMUNITY_LIST_RELATION} permit {COMMUNITY_FROM_PROVIDER}
bgp community-list standard {COMMUNITY_LIST_NON_CUSTOMER} permit {COMMUNITY_FROM_PEER}
bgp community-list standard {COMMUNITY_LIST_NON_CUSTOMER} permit {COMMUNITY_FROM_PROVIDER}
bgp community-list standard {COMMUNITY_LIST_CUSTOMER} permit {COMMUNITY_FROM_CUSTOMER}
!"""

        if prefix_type == "subprefix":
            prefix = f"192.168.{hijack_target_num}.0/25"
        else:
            prefix = f"192.168.{hijack_target_num}.0/24"

        mitm_forward_node = censor.get("mitm_forward_node")
        if attack_type == "mitm" and mitm_forward_node:
            forward_ip = "blackhole"
            for conn in censor_connections:
                if conn["neighbor"] == mitm_forward_node:
                    forward_ip = conn["neighbor_ip"]
            if forward_ip != "blackhole":
                static_routes += f"ip route {prefix} {forward_ip}\n"
            else:
                static_routes += f"ip route {prefix} blackhole\n"
        else:
            static_routes += f"ip route {prefix} blackhole\n"

        if attack_type in ["hijack", "mitm"]:
            if use_communities:
                networks += f"  network {prefix} route-map {ORIGIN_ROUTE_MAP}\n"
            else:
                networks += f"  network {prefix}\n"
        else:
            networks += f"  network {prefix} route-map {attack_rmap_name}\n"
            route_maps += f"route-map {attack_rmap_name} permit 10\n"

            if attack_type == "as_path_poisoning":
                poison_asn = censor.get("poison_asn", 65000 + hijack_target_num)
                route_maps += f" set as-path prepend {poison_asn}\n"

            elif attack_type == "as_path_forgery":
                fake_path = censor.get("fake_path", "65004 65003")
                route_maps += f" set as-path prepend {fake_path}\n"

            elif attack_type == "origin_spoofing":
                target_asn = 65000 + hijack_target_num
                route_maps += f" set as-path prepend {target_asn}\n"
            elif attack_type == "origin_code_manipulation":
                origin_code = censor.get("origin_code", "incomplete")
                route_maps += f" set origin {origin_code}\n"
            elif attack_type == "blackhole":
                community = censor.get("community", "65535:666")
                route_maps += f" set community {community}\n"

            if use_communities:
                route_maps += f" set community {COMMUNITY_FROM_CUSTOMER} additive\n"

            route_maps += "!\n"

        if censor_prefix_lists:
            config += f"\n{censor_prefix_lists.strip()}"
        if community_lists:
            config += f"\n{community_lists.strip()}"
        if static_routes:
            config += f"\n{static_routes.strip()}"
        if use_communities:
            config += f"""
!
route-map {ORIGIN_ROUTE_MAP} permit 10
 set community {COMMUNITY_FROM_CUSTOMER} additive
!"""
        if route_maps:
            config += f"\n!\n{route_maps.strip()}"
        if censor_in_route_maps:
            config += f"\n!\n{censor_in_route_maps.strip()}"
        if censor_out_route_maps:
            config += f"\n!\n{censor_out_route_maps.strip()}"

        config += f"""
!
router bgp {censor_asn}
 bgp router-id {90 + censor_num}.{90 + censor_num}.{90 + censor_num}.{90 + censor_num}
 no bgp bestpath compare-age
 bgp bestpath compare-routerid
 no bgp ebgp-requires-policy"""

        for conn in censor_connections:
            neighbor = conn["neighbor"]
            if neighbor.lower().startswith("censor"):
                neighbor_asn = 65900 + get_node_num(neighbor)
            else:
                neighbor_asn = 65000 + get_node_num(neighbor)
            config += f"""
 neighbor {conn['neighbor_ip']} remote-as {neighbor_asn}"""

        config += """
 !
 address-family ipv4 unicast"""
        if networks:
            config += "\n" + networks.rstrip()

        for conn in censor_connections:
            config += f"""
  neighbor {conn['neighbor_ip']} activate"""
            if conn["neighbor_ip"] in censor_neighbor_in_rmaps:
                rmap = censor_neighbor_in_rmaps[conn["neighbor_ip"]]
                config += f"\n  neighbor {conn['neighbor_ip']} route-map {rmap} in"

            if use_communities or attack_type in ["blackhole", "mitm"]:
                config += f"""
  neighbor {conn['neighbor_ip']} send-community both"""

            if attack_type == "mitm":
                if mitm_forward_node == conn["neighbor"]:
                    config += f"\n  neighbor {conn['neighbor_ip']} route-map RM-NO-MITM out\n"
                else:
                    config += (
                        f"\n  neighbor {conn['neighbor_ip']} route-map RM-MITM-VICTIM out\n"
                    )
            elif conn["neighbor_ip"] in censor_neighbor_out_rmaps:
                rmap = censor_neighbor_out_rmaps[conn["neighbor_ip"]]
                config += f"\n  neighbor {conn['neighbor_ip']} route-map {rmap} out"

        config += """
 exit-address-family
!
!
"""
        if attack_type == "mitm":
            config += f"""
ip prefix-list PL-MITM seq 5 permit {prefix}
!
route-map RM-NO-MITM deny 10
 match ip address prefix-list PL-MITM
!
route-map RM-NO-MITM permit 20
!
route-map RM-MITM-VICTIM permit 10
 match ip address prefix-list PL-MITM
 set community no-export
!
route-map RM-MITM-VICTIM permit 20
!
"""

        with open(f"generated/configs/{censor_name}.conf", "w") as f:
            f.write(config)
