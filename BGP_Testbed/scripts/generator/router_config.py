from collections import defaultdict

from generator.core import get_node_num


def build_router_configs(routers, connections, policies, rpki_routers):
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
        for p in my_policies:
            policies_by_neighbor[p["neighbor"]].append(p)

        prefix_lists = ""
        route_maps = ""
        neighbor_route_maps = {}

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

                route_maps += "\n!\n"
                seq += 10

            route_maps += f"""
route-map {rmap_name} permit {seq}"""
            if default_local_pref is not None:
                route_maps += f"\n set local-preference {default_local_pref}"
            route_maps += "\n!"

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
        if route_maps:
            config += route_maps

        router_asn = 65000 + num
        config += f"""
router bgp {router_asn}
 bgp router-id {num}.{num}.{num}.{num}
 no bgp ebgp-requires-policy"""

        for conn in router_connections:
            neighbor = conn["neighbor"]
            neighbor_ip = conn["neighbor_ip"]

            if neighbor.startswith("censor"):
                neighbor_asn = 65900 + get_node_num(neighbor)
            else:
                neighbor_asn = 65000 + get_node_num(neighbor)

            config += f"""
 neighbor {neighbor_ip} remote-as {neighbor_asn}"""

        config += f"""
 !
 address-family ipv4 unicast
  network 192.168.{num}.0/24"""

        for conn in router_connections:
            config += f"""
  neighbor {conn['neighbor_ip']} activate"""

        for nip, rmap in neighbor_route_maps.items():
            config += f"""
  neighbor {nip} route-map {rmap} in"""

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
