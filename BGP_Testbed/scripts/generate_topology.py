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
rpki_routers = data.get('rpki_routers', [])  # Neu: Router, die RPKI nutzen sollen
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

# RPKI VALIDATOR (GoRTR)
if rpki_routers:
    topology['topology']['nodes']['rpki-validator'] = {
        'kind': 'linux',
        'image': 'cloudflare/gortr',
        'cmd': '-bind :3323 -cache /roas.json -verify=false -checktime=false',
        'binds': [
            './configs/roas.json:/roas.json:ro'
        ]
    }

# LINKS
topology['topology']['links'] = link_details

# Schreiben
with open('generated/lab.clab.yaml', 'w') as f:
    yaml.dump(topology, f, default_flow_style=False, sort_keys=False)

# RPKI ROAs (JSON) generieren
if rpki_routers:
    import json
    roas_data = {"roas": []}
    for r in routers:
        r_num = int(r.replace('router', ''))
        roas_data["roas"].append({
            "asn": f"AS6500{r_num}",
            "prefix": f"192.168.{r_num}.0/24",
            "maxLength": 24,
            "ta": "Testbed"
        })
    with open('generated/configs/roas.json', 'w') as f:
        json.dump(roas_data, f, indent=2)


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
    
    if router in rpki_routers:
        config += """
rpki
 rpki polling_period 10
 rpki cache rpki-validator 3323 preference 1
 exit
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
            target_num = int(target.replace('router', ''))
            plist_name = f"PFX-{target.upper()}"
            
            if f"ip prefix-list {plist_name}" not in prefix_lists:
                 prefix_lists += f"""
ip prefix-list {plist_name} seq 5 permit 192.168.{target_num}.0/24
!"""
            
            route_maps += f"""
route-map {rmap_name} permit {seq}
 match ip address prefix-list {plist_name}"""
            
            if 'local_preference' in p:
                route_maps += f"\n set local-preference {p['local_preference']}"
            
            if 'prepend_asn' in p:
                prepend_count = p.get('prepend_count', 3)
                prepend = " ".join([str(p['prepend_asn'])] * prepend_count)
                route_maps += f"\n set as-path prepend {prepend}"
                
            if 'origin_code' in p:
                route_maps += f"\n set origin {p['origin_code']}"
                
            route_maps += "\n!\n"
            seq += 10
            
        route_maps += f"""
route-map {rmap_name} permit {seq}
!"""

    if router in rpki_routers:
        # Standard-Routemap für RPKI (falls keine spezifischen Policies existieren)
        rpki_route_maps = f"""
route-map RM-RPKI-IN deny 10
 match rpki invalid
!
route-map RM-RPKI-IN permit 20
!"""
        # Inject RPKI deny rule into all existing policy route-maps
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

    if router in rpki_routers:
        for conn in router_connections:
            if conn['neighbor_ip'] not in neighbor_route_maps:
                config += f"""
  neighbor {conn['neighbor_ip']} route-map RM-RPKI-IN in"""

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

    # Static routes for hijacked prefixes und Modulare Angriffs-Logik
    static_routes = ""
    networks = ""
    route_maps = ""
    attack_rmap_name = f"RM-ATTACK-{attack_type.upper()}"
    has_rmap = False
    
    my_censor_policies = [p for p in policies if p['node'] == censor_name]
    policies_by_neighbor_censor = defaultdict(list)
    for p in my_censor_policies:
        policies_by_neighbor_censor[p['neighbor']].append(p)

    censor_prefix_lists = ""
    censor_in_route_maps = ""
    censor_neighbor_in_rmaps = {}

    for neighbor, pols in policies_by_neighbor_censor.items():
        rmap_name = f"RM-IN-{neighbor.upper()}"
        seq = 10
        neighbor_ip = next((c['neighbor_ip'] for c in censor_connections if c['neighbor'] == neighbor), None)
        if not neighbor_ip: continue
        
        censor_neighbor_in_rmaps[neighbor_ip] = rmap_name
        
        for p in pols:
            target = p['target_node']
            target_num = int(target.replace('router', ''))
            plist_name = f"PFX-{target.upper()}"
            
            if f"ip prefix-list {plist_name}" not in censor_prefix_lists:
                 censor_prefix_lists += f"""
ip prefix-list {plist_name} seq 5 permit 192.168.{target_num}.0/24
!"""
            
            censor_in_route_maps += f"""
route-map {rmap_name} permit {seq}
 match ip address prefix-list {plist_name}"""
            
            if 'local_preference' in p:
                censor_in_route_maps += f"\n set local-preference {p['local_preference']}"
            
            if 'prepend_asn' in p:
                prepend_count = p.get('prepend_count', 3)
                prepend = " ".join([str(p['prepend_asn'])] * prepend_count)
                censor_in_route_maps += f"\n set as-path prepend {prepend}"
                
            if 'origin_code' in p:
                censor_in_route_maps += f"\n set origin {p['origin_code']}"
                
            censor_in_route_maps += "\n!\n"
            seq += 10
            
        censor_in_route_maps += f"""
route-map {rmap_name} permit {seq}
!"""

    # 1. PRÄFIX BESTIMMEN
    # Wir erwarten entweder 'subprefix' oder 'exact' (Standard: 'exact').
    # Die Angriffsart (attack_type) entscheidet NUR noch über die BGP-Attribute (Route-Maps).
    prefix_type = censor.get('prefix_type', 'exact')
            
    if prefix_type == 'subprefix':
        prefix = f"192.168.{target_num}.0/25"
    else:
        prefix = f"192.168.{target_num}.0/24"
        
    mitm_forward_node = censor.get('mitm_forward_node')
    if attack_type == 'mitm' and mitm_forward_node:
        # Finde die IP des Forward-Nodes für die statische Route
        forward_ip = "blackhole"
        for conn in censor_connections:
            if conn['neighbor'] == mitm_forward_node:
                forward_ip = conn['neighbor_ip']
        if forward_ip != "blackhole":
            static_routes += f"ip route {prefix} {forward_ip}\n"
        else:
            static_routes += f"ip route {prefix} blackhole\n"
    else:
        static_routes += f"ip route {prefix} blackhole\n"

    # 2. BGP-ATTRIBUTE MANIPULIEREN
    # Standard-Hijacks ohne spezielle BGP-Attribute
    if attack_type in ['hijack', 'mitm']:
        # Kein spezielles BGP-Attribut, einfach nur ankündigen
        networks += f"  network {prefix}\n"
    else:
        # Route-Map für BGP-Manipulationen wird benötigt
        networks += f"  network {prefix} route-map {attack_rmap_name}\n"
        route_maps += f"route-map {attack_rmap_name} permit 10\n"
        has_rmap = True
        
        if attack_type == 'as_path_poisoning':
            poison_asn = censor.get('poison_asn', 65000 + target_num)
            route_maps += f" set as-path prepend {poison_asn}\n"
            
        elif attack_type == 'as_path_forgery':
            fake_path = censor.get('fake_path', f'65004 65003')
            route_maps += f" set as-path prepend {fake_path}\n"
            
        elif attack_type == 'origin_spoofing':
            target_asn = 65000 + target_num
            route_maps += f" set as-path prepend {target_asn}\n"
        elif attack_type == 'origin_code_manipulation':
            origin_code = censor.get('origin_code', 'incomplete')
            route_maps += f" set origin {origin_code}\n"
        elif attack_type == 'blackhole':
            community = censor.get('community', '65535:666')
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
        if conn['neighbor_ip'] in censor_neighbor_in_rmaps:
            rmap = censor_neighbor_in_rmaps[conn['neighbor_ip']]
            config += f"\n  neighbor {conn['neighbor_ip']} route-map {rmap} in"
            
        # If we wanted to send community, we need `neighbor X.X.X.X send-community both`
        if attack_type in ['blackhole', 'mitm']:
            config += f"""
  neighbor {conn['neighbor_ip']} send-community both"""

        # Wenn der Zensor als MitM fungiert, darf er die manipulierte Fake-Route nicht seinem Forward-Node ankündigen!
        if attack_type == 'mitm':
            if mitm_forward_node == conn['neighbor']:
                config += f"\n  neighbor {conn['neighbor_ip']} route-map RM-NO-MITM out\n"
            else:
                # An Opfer (router1) senden wir es MIT no-export, damit diese es nicht an den Transit-Router (router2) zurückwerfen!
                config += f"\n  neighbor {conn['neighbor_ip']} route-map RM-MITM-VICTIM out\n"

    config += """
 exit-address-family
!
!
"""
    if attack_type == 'mitm':
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
    
    # Schreiben
    with open(f'generated/configs/{censor_name}.conf', 'w') as f:
        f.write(config)
