from collections import defaultdict


def build_censor_configs(censors, connections, policies):
    for censor in censors:
        censor_name = censor["name"]
        censor_num = int(censor_name.replace("censor", ""))
        target_router = censor["target_router"]
        target_num = int(target_router.replace("router", ""))
        attack_type = censor["attack_type"]

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
        for p in my_censor_policies:
            policies_by_neighbor_censor[p["neighbor"]].append(p)

        censor_prefix_lists = ""
        censor_in_route_maps = ""
        censor_neighbor_in_rmaps = {}

        for neighbor, pols in policies_by_neighbor_censor.items():
            rmap_name = f"RM-IN-{neighbor.upper()}"
            seq = 10
            neighbor_ip = next(
                c["neighbor_ip"]
                for c in censor_connections
                if c["neighbor"] == neighbor
            )

            censor_neighbor_in_rmaps[neighbor_ip] = rmap_name

            for p in pols:
                target = p["target_node"]
                target_num = int(target.replace("router", ""))
                plist_name = f"PFX-{target.upper()}"

                if f"ip prefix-list {plist_name}" not in censor_prefix_lists:
                    censor_prefix_lists += f"""
ip prefix-list {plist_name} seq 5 permit 192.168.{target_num}.0/24
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

                censor_in_route_maps += "\n!\n"
                seq += 10

            censor_in_route_maps += f"""
route-map {rmap_name} permit {seq}
!"""

        prefix_type = censor.get("prefix_type", "exact")
        if prefix_type == "subprefix":
            prefix = f"192.168.{target_num}.0/25"
        else:
            prefix = f"192.168.{target_num}.0/24"

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
            networks += f"  network {prefix}\n"
        else:
            networks += f"  network {prefix} route-map {attack_rmap_name}\n"
            route_maps += f"route-map {attack_rmap_name} permit 10\n"

            if attack_type == "as_path_poisoning":
                poison_asn = censor.get("poison_asn", 65000 + target_num)
                route_maps += f" set as-path prepend {poison_asn}\n"

            elif attack_type == "as_path_forgery":
                fake_path = censor.get("fake_path", "65004 65003")
                route_maps += f" set as-path prepend {fake_path}\n"

            elif attack_type == "origin_spoofing":
                target_asn = 65000 + target_num
                route_maps += f" set as-path prepend {target_asn}\n"
            elif attack_type == "origin_code_manipulation":
                origin_code = censor.get("origin_code", "incomplete")
                route_maps += f" set origin {origin_code}\n"
            elif attack_type == "blackhole":
                community = censor.get("community", "65535:666")
                route_maps += f" set community {community}\n"

            route_maps += "!\n"

        if censor_prefix_lists:
            config += f"\n{censor_prefix_lists.strip()}"
        if static_routes:
            config += f"\n{static_routes.strip()}"
        if route_maps:
            config += f"\n!\n{route_maps.strip()}"
        if censor_in_route_maps:
            config += f"\n!\n{censor_in_route_maps.strip()}"

        config += f"""
!
router bgp {censor_asn}
 bgp router-id 9{censor_num}.9{censor_num}.9{censor_num}.9{censor_num}
 no bgp ebgp-requires-policy"""

        for conn in censor_connections:
            neighbor = conn["neighbor"]
            if neighbor.startswith("router"):
                neighbor_asn = 65000 + int(neighbor.replace("router", ""))
            elif neighbor.startswith("censor"):
                neighbor_asn = 65900 + int(neighbor.replace("censor", ""))
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

            if attack_type in ["blackhole", "mitm"]:
                config += f"""
  neighbor {conn['neighbor_ip']} send-community both"""

            if attack_type == "mitm":
                if mitm_forward_node == conn["neighbor"]:
                    config += f"\n  neighbor {conn['neighbor_ip']} route-map RM-NO-MITM out\n"
                else:
                    config += (
                        f"\n  neighbor {conn['neighbor_ip']} route-map RM-MITM-VICTIM out\n"
                    )

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
