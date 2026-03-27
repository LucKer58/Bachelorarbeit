import yaml
import os
import shutil

# Wechsle in das Verzeichnis BGP_Testbed, in dem sich die Ordner 'scenarios' und 'generated' befinden
bash_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(bash_dir)

def attack_subprefix_hijack(target_num, local_ip, **kwargs):
    """Sub-Prefix Hijacking: /25 instead of /24 (more specific)"""
    prefix = f"192.168.{target_num}.0/25"
    return f"        route {prefix} next-hop {local_ip};"

def attack_exact_prefix_hijack(target_num, local_ip, **kwargs):
    """Exact-Prefix Hijacking: same /24"""
    prefix = f"192.168.{target_num}.0/24"
    return f"        route {prefix} next-hop {local_ip};"

def attack_as_path_prepending(target_num, local_ip, censor_asn, prepend_count=3, **kwargs):
    """AS-Path Prepending: make path artificially longer"""
    prefix = f"192.168.{target_num}.0/24"
    prepend = " ".join([str(censor_asn)] * prepend_count)
    return f"        route {prefix} next-hop {local_ip} as-path [ {prepend} ];"

def attack_blackhole(target_num, local_ip, community="65535:666", **kwargs):
    """Blackhole with Community Tag"""
    prefix = f"192.168.{target_num}.0/24"
    return f"        route {prefix} next-hop {local_ip} community [ {community} ];"

ATTACK_HANDLERS = {
    'subprefix_hijack': attack_subprefix_hijack,
    'exact_prefix_hijack': attack_exact_prefix_hijack,
    'as_path_prepending': attack_as_path_prepending,
    'blackhole': attack_blackhole,
}

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

# CENSOR NODES (SEPARAT!)
for censor in censors:
    censor_name = censor['name']
    
    # Erste IP des Zensors finden
    censor_ip = connections[censor_name][0]['ip'] if connections[censor_name] else None
    
    topology['topology']['nodes'][censor_name] = {
        'kind': 'linux',
        'image': 'exabgp-censor:latest',
        'binds': [
            f'./configs/{censor_name}.conf:/root/exabgp.conf'
        ]
    }
    
    if censor_ip:
        topology['topology']['nodes'][censor_name]['exec'] = [
            f'ip addr add {censor_ip} dev eth1',
            'ip link set dev eth1 up'
        ]

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
    
    # Neighbor-Info
    neighbor_info = connections[censor_name][0]
    local_ip = neighbor_info['ip'].split('/')[0]
    neighbor_ip = neighbor_info['neighbor_ip']
    neighbor_name = neighbor_info['neighbor']
    neighbor_asn = 65000 + int(neighbor_name.replace('router', ''))
    censor_asn = 65900 + censor_num
    
    # Get attack handler
    handler = ATTACK_HANDLERS.get(attack_type)
    if handler:
        attack_params = {
            'target_num': target_num,
            'local_ip': local_ip,
            'censor_asn': censor_asn,
            'prepend_count': censor.get('prepend_count', 3),
            'community': censor.get('community', '65535:666')
        }
        static_route = handler(**attack_params)
    else:
        print(f"WARNING: Unknown attack type '{attack_type}', using default subprefix hijack")
        static_route = f"        route 192.168.{target_num}.0/25 next-hop {local_ip};"
    
    config = f"""neighbor {neighbor_ip} {{
    router-id 9{censor_num}.9{censor_num}.9{censor_num}.9{censor_num};
    local-address {local_ip};
    local-as {censor_asn};
    peer-as {neighbor_asn};
    hold-time 180;
    
    family {{
        ipv4 unicast;
    }}
    
    static {{
{static_route}
    }}
}}
"""
    
    # Schreiben
    with open(f'generated/configs/{censor_name}.conf', 'w') as f:
        f.write(config)
