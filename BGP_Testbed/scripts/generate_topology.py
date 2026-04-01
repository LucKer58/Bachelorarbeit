import yaml
import os
import shutil

# Wechsle in das Verzeichnis BGP_Testbed, in dem sich die Ordner 'scenarios' und 'generated' befinden
bash_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(bash_dir)

if os.path.exists('generated'):
    shutil.rmtree('generated')
os.makedirs('generated/configs', exist_ok=True)

with open('scenarios/simple_nodes.yaml', 'r') as f:
    data = yaml.safe_load(f)

routers = data['routers']  # ['router1', 'router2', 'router3', 'router4']
censors = data.get('censors', [])  # [{'name': 'censor1', 'target_router': 'router1', ...}]
links = data['links']  # [['router1', 'router2'], ...]
policies = data.get('policies', [])

all_nodes = routers + [c['name'] for c in censors]

connections = {node: [] for node in all_nodes}
interface_counter = {node: 1 for node in all_nodes}  # eth1, eth2, ...

link_details = []  # Speichert IP-Adressen pro Link

for link_num, link in enumerate(links):
    node_a, node_b = link
    
    # Interface-Nummern
    eth_a = interface_counter[node_a]
    eth_b = interface_counter[node_b]
    interface_counter[node_a] += 1
    interface_counter[node_b] += 1
    
    # IP-Adressen: 10.0.X.1/30 und 10.0.X.2/30
    ip_a = f"10.0.{link_num}.1/30"
    ip_b = f"10.0.{link_num}.2/30"
    
    # Speichern
    connections[node_a].append({
        'neighbor': node_b,
        'interface': f'eth{eth_a}',
        'ip': ip_a,
        'neighbor_ip': ip_b.split('/')[0]
    })
    
    connections[node_b].append({
        'neighbor': node_a,
        'interface': f'eth{eth_b}',
        'ip': ip_b,
        'neighbor_ip': ip_a.split('/')[0]
    })
    
    link_details.append({
        'endpoints': [f"{node_a}:eth{eth_a}", f"{node_b}:eth{eth_b}"]
    })

import os

os.makedirs('generated/configs', exist_ok=True)

# ========== 1. LAB.CLAB.YAML ==========
topology = {
    'name': data['name'],
    'topology': {
        'nodes': {},
        'links': []
    }
}

# ROUTER NODES
for router in routers:
    num = int(router.replace('router', ''))
    topology['topology']['nodes'][router] = {
        'kind': 'linux',
        'image': 'frrouting/frr:latest',
        'binds': [
            f'./configs/frr{num}.conf:/etc/frr/frr.conf',
            '../configs/daemons:/etc/frr/daemons'
        ]
    }

# CENSOR NODES (FRR)
for censor in censors:
    censor_name = censor['name']
    
    topology['topology']['nodes'][censor_name] = {
        'kind': 'linux',
        'image': 'frrouting/frr:latest',
        'binds': [
            f'./configs/{censor_name}.conf:/etc/frr/frr.conf',
            '../configs/daemons:/etc/frr/daemons'
        ]
    }

# LINKS
topology['topology']['links'] = link_details

# Schreiben
with open('generated/lab.clab.yaml', 'w') as f:
    yaml.dump(topology, f, default_flow_style=False, sort_keys=False)


# ========== 2. ROUTER CONFIGS ==========
from collections import defaultdict

for router in routers:
    num = int(router.replace('router', ''))
    router_connections = connections[router]
    my_policies = [p for p in policies if p['node'] == router]
    
    config = f"""frr defaults traditional
!
hostname {router}
!"""
    
    # Interfaces
    for conn in router_connections:
        config += f"""
interface {conn['interface']}
 ip address {conn['ip']}
!"""
    
    # Loopback
    config += f"""
interface lo
 ip address 192.168.{num}.1/24
!"""
    
    # Policies
    policies_by_neighbor = defaultdict(list)
    for p in my_policies:
        policies_by_neighbor[p['neighbor']].append(p)

    prefix_lists = ""
    route_maps = ""
    neighbor_route_maps = {}

    for neighbor, pols in policies_by_neighbor.items():
        rmap_name = f"RM-IN-{neighbor.upper()}"
        seq = 10
        neighbor_ip = next((c['neighbor_ip'] for c in router_connections if c['neighbor'] == neighbor), None)
        if not neighbor_ip: continue
        
        neighbor_route_maps[neighbor_ip] = rmap_name
        
        for p in pols:
            target = p['target_node']
            lp = p['local_preference']
            target_num = int(target.replace('router', ''))
            plist_name = f"PFX-{target.upper()}"
            
            if f"ip prefix-list {plist_name}" not in prefix_lists:
                 prefix_lists += f"""
ip prefix-list {plist_name} seq 5 permit 192.168.{target_num}.0/24
!"""
            
            route_maps += f"""
route-map {rmap_name} permit {seq}
 match ip address prefix-list {plist_name}
 set local-preference {lp}
!"""
            seq += 10
            
        route_maps += f"""
route-map {rmap_name} permit {seq}
!"""

    if prefix_lists:
        config += prefix_lists
    if route_maps:
        config += route_maps
    
    # BGP
    config += f"""
router bgp 6500{num}
 bgp router-id {num}.{num}.{num}.{num}
 no bgp ebgp-requires-policy"""
    
    # Neighbors
    for conn in router_connections:
        neighbor = conn['neighbor']
        neighbor_ip = conn['neighbor_ip']
        
        if neighbor.startswith('router'):
            neighbor_asn = 65000 + int(neighbor.replace('router', ''))
        elif neighbor.startswith('censor'):
            neighbor_asn = 65900 + int(neighbor.replace('censor', ''))
        
        config += f"""
 neighbor {neighbor_ip} remote-as {neighbor_asn}"""
    
    # Address family
    config += f"""
 !
 address-family ipv4 unicast
  network 192.168.{num}.0/24"""
    
    for conn in router_connections:
        config += f"""
  neighbor {conn['neighbor_ip']} activate"""
    
    # Route-map assignment
    for nip, rmap in neighbor_route_maps.items():
        config += f"""
  neighbor {nip} route-map {rmap} in"""

    config += """
 exit-address-family
!
!
"""
    
    # Schreiben
    with open(f'generated/configs/frr{num}.conf', 'w') as f:
        f.write(config)


# ========== 3. CENSOR CONFIGS ==========
for censor in censors:
    censor_name = censor['name']
    censor_num = int(censor_name.replace('censor', ''))
    target_router = censor['target_router']
    target_num = int(target_router.replace('router', ''))
    attack_type = censor['attack_type']
    
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
    
    # Loopback
    config += f"""
interface lo
 ip address 10.255.255.{censor_num}/32
!"""

    # Static routes for hijacked prefixes
    static_routes = ""
    networks = ""
    route_maps = ""
    attack_rmap_name = f"RM-ATTACK-{attack_type.upper()}"
    has_rmap = False
    
    if attack_type == 'subprefix_hijack':
        prefix = f"192.168.{target_num}.0/25"
        static_routes += f"ip route {prefix} blackhole\n"
        networks += f"  network {prefix}\n"
    elif attack_type == 'exact_prefix_hijack':
        prefix = f"192.168.{target_num}.0/24"
        static_routes += f"ip route {prefix} blackhole\n"
        networks += f"  network {prefix}\n"
    elif attack_type == 'as_path_prepending':
        prefix = f"192.168.{target_num}.0/24"
        static_routes += f"ip route {prefix} blackhole\n"
        prepend_count = censor.get('prepend_count', 3)
        prepend = " ".join([str(censor_asn)] * prepend_count)
        networks += f"  network {prefix} route-map {attack_rmap_name}\n"
        route_maps += f"""route-map {attack_rmap_name} permit 10
 set as-path prepend {prepend}
!
"""
        has_rmap = True
    elif attack_type == 'blackhole':
        prefix = f"192.168.{target_num}.0/24"
        static_routes += f"ip route {prefix} blackhole\n"
        community = censor.get('community', '65535:666')
        networks += f"  network {prefix} route-map {attack_rmap_name}\n"
        route_maps += f"""route-map {attack_rmap_name} permit 10
 set community {community}
!
"""
        has_rmap = True
    else:
        print(f"WARNING: Unknown attack type '{attack_type}', using default exact prefix hijack")
        prefix = f"192.168.{target_num}.0/24"
        static_routes += f"ip route {prefix} blackhole\n"
        networks += f"  network {prefix}\n"

    if static_routes:
        config += f"\n{static_routes.strip()}"
    if route_maps:
        config += f"\n!\n{route_maps.strip()}"

    # BGP
    config += f"""
!
router bgp {censor_asn}
 bgp router-id 9{censor_num}.9{censor_num}.9{censor_num}.9{censor_num}
 no bgp ebgp-requires-policy"""

    # Neighbors
    for conn in censor_connections:
        neighbor = conn['neighbor']
        if neighbor.startswith('router'):
            neighbor_asn = 65000 + int(neighbor.replace('router', ''))
        elif neighbor.startswith('censor'):
            neighbor_asn = 65900 + int(neighbor.replace('censor', ''))
        config += f"""
 neighbor {conn['neighbor_ip']} remote-as {neighbor_asn}"""

    # Address family
    config += f"""
 !
 address-family ipv4 unicast"""
    if networks:
        config += "\n" + networks.rstrip()
    
    for conn in censor_connections:
        if has_rmap and attack_type in ['as_path_prepending', 'blackhole'] and False: # Apply to network, not neighbor
            pass
        config += f"""
  neighbor {conn['neighbor_ip']} activate"""
        # If we wanted to send community, we need `neighbor X.X.X.X send-community both`
        if attack_type == 'blackhole':
            config += f"""
  neighbor {conn['neighbor_ip']} send-community both"""

    config += """
 exit-address-family
!
!
"""
    
    # Schreiben
    with open(f'generated/configs/{censor_name}.conf', 'w') as f:
        f.write(config)
