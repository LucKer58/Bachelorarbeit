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


def build_router_configs(routers, connections, policies, rpki_routers, customer_cones=None):
    customer_cones = customer_cones or {}
    for router in routers:
        num = get_node_num(router)
        router_connections = connections[router]
        my_policies = [p for p in policies if p["node"] == router]
        config = f"""frr defaults traditional
!
hostname {router}
!"""

        if router in rpki_routers:
            config += """
rpki
 rpki polling_period 10
 rpki retry_interval 5
 rpki cache rpki-validator 3323 preference 1
 exit
!"""

        for conn in router_connections:
            config += f"""
interface {conn['interface']}
 ip address {conn['ip']}
!"""

        config += f"""
interface lo
 ip address 192.168.{num}.1/24
!"""

        policies_by_neighbor = defaultdict(list)
        neighbor_relationships = {}
        for p in my_policies:
            policies_by_neighbor[p["neighbor"]].append(p)
            relation = p.get("relationship")
            if relation:
                neighbor_relationships[p["neighbor"]] = relation

        prefix_lists = ""
        community_lists = ""
        route_maps = ""
        out_route_maps = ""
        neighbor_route_maps = {}
        neighbor_out_maps = {}
        use_communities = False

        for neighbor, pols in policies_by_neighbor.items():
            rmap_name = f"RM-IN-{neighbor.upper()}"
            seq = 10
            neighbor_ip = next(
                c["neighbor_ip"]
                for c in router_connections
                if c["neighbor"] == neighbor
            )

            neighbor_route_maps[neighbor_ip] = rmap_name

            default_local_pref = None
            relation = neighbor_relationships.get(neighbor)
            community_tag = RELATION_COMMUNITY.get(relation)
            if community_tag:
                use_communities = True

            for p in pols:
                if p.get("match") == "all":
                    if "local_preference" in p:
                        default_local_pref = p["local_preference"]
                    seq += 10
                    continue
                target = p["target_node"]
                target_num = get_node_num(target)
                plist_name = f"PFX-{target.upper()}"

                if f"ip prefix-list {plist_name}" not in prefix_lists:
                    prefix_lists += f"""
ip prefix-list {plist_name} seq 5 permit 192.168.{target_num}.0/24
!"""

                route_maps += f"""
route-map {rmap_name} permit {seq}
 match ip address prefix-list {plist_name}"""

                if "local_preference" in p:
                    route_maps += f"\n set local-preference {p['local_preference']}"

                if "prepend_asn" in p:
                    prepend_count = p.get("prepend_count", 3)
                    prepend = " ".join([str(p["prepend_asn"])] * prepend_count)
                    route_maps += f"\n set as-path prepend {prepend}"

                if "origin_code" in p:
                    route_maps += f"\n set origin {p['origin_code']}"

                if community_tag:
                    route_maps += f"\n set community {COMMUNITY_LIST_RELATION} delete"
                    route_maps += f"\n set community {community_tag} additive"

                route_maps += "\n!\n"
                seq += 10

            route_maps += f"""
route-map {rmap_name} permit {seq}"""
            if default_local_pref is not None:
                route_maps += f"\n set local-preference {default_local_pref}"
            if community_tag:
                route_maps += f"\n set community {COMMUNITY_LIST_RELATION} delete"
                route_maps += f"\n set community {community_tag} additive"
            route_maps += "\n!"

            if relation in {"peer", "provider"}:
                out_name = f"RM-OUT-{neighbor.upper()}"
                neighbor_out_maps[neighbor_ip] = out_name
                out_route_maps += f"""
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

        if router in rpki_routers:
            rpki_route_maps = """
route-map RM-RPKI-IN deny 10
 match rpki invalid
!
route-map RM-RPKI-IN permit 20
!"""
            for rmap in set(neighbor_route_maps.values()):
                rpki_route_maps += f"""
route-map {rmap} deny 5
 match rpki invalid
!"""
            route_maps = rpki_route_maps + route_maps

        if prefix_lists:
            config += prefix_lists
        if community_lists:
            config += community_lists
        if use_communities:
            config += f"""
route-map {ORIGIN_ROUTE_MAP} permit 10
 set community {COMMUNITY_FROM_CUSTOMER} additive
!"""
        if route_maps:
            config += route_maps
        if out_route_maps:
            config += f"\n!\n{out_route_maps.strip()}"

        router_asn = 65000 + num
        config += f"""
router bgp {router_asn}
 bgp router-id {num}.{num}.{num}.{num}
 no bgp bestpath compare-age
 bgp bestpath compare-routerid
 no bgp ebgp-requires-policy"""

        for conn in router_connections:
            neighbor = conn["neighbor"]
            neighbor_ip = conn["neighbor_ip"]

            if neighbor.lower().startswith("censor"):
                neighbor_asn = 65900 + get_node_num(neighbor)
            else:
                neighbor_asn = 65000 + get_node_num(neighbor)

            config += f"""
 neighbor {neighbor_ip} remote-as {neighbor_asn}"""

        config += f"""
 !
 address-family ipv4 unicast"""

        if use_communities:
            config += f"""
  network 192.168.{num}.0/24 route-map {ORIGIN_ROUTE_MAP}"""
        else:
            config += f"""
  network 192.168.{num}.0/24"""

        for conn in router_connections:
            config += f"""
  neighbor {conn['neighbor_ip']} activate"""
            if use_communities:
                config += f"\n  neighbor {conn['neighbor_ip']} send-community both"

        for nip, rmap in neighbor_route_maps.items():
            config += f"""
  neighbor {nip} route-map {rmap} in"""

        for nip, rmap in neighbor_out_maps.items():
            config += f"""
  neighbor {nip} route-map {rmap} out"""

        if router in rpki_routers:
            for conn in router_connections:
                if conn["neighbor_ip"] not in neighbor_route_maps:
                    config += f"""
  neighbor {conn['neighbor_ip']} route-map RM-RPKI-IN in"""

        config += """
 exit-address-family
!
!
"""

        with open(f"generated/configs/frr{num}.conf", "w") as f:
            f.write(config)
