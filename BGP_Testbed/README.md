# Virtualized Testbed for Censorship Research

## Overview
This repository contains the virtualized BGP/IP testbed using Docker, Containerlab, and FRRouting.

## Requirements
- WSL2 (Windows Subsystem for Linux) - for Windows users
- Docker Desktop (with WSL2 integration enabled)
- Containerlab
- VS Code

## Setup of the Topology using FRRouting

All commands below are run from the `BGP_Testbed/` directory.

### 1. Generate and Deploy the Topology
The generator compiles a scenario YAML into FRRouting configs and a Containerlab topology
under `generated/`, then deploys it with `containerlab deploy --reconfigure`:
```bash
python3 scripts/generate_topology.py --scenario scenarios/1_subprefix_hijack.yaml --sudo
```

Generate, deploy, and start the web UI in one step:
```bash
python3 scripts/generate_topology.py --scenario scenarios/sub_prefix_30.yaml --start-ui --sudo
```

To redeploy the already-generated topology directly with Containerlab:
```bash
sudo containerlab deploy -t generated/lab.clab.yaml --reconfigure
```

### 2. Verify Deployment
```bash
# Check containers are running
sudo containerlab inspect -t generated/lab.clab.yaml
```

### 3. Observe BGP Status

#### Check BGP Neighbors
```bash
# On AS1
docker exec -it clab-bgp-testbed-AS1 vtysh -c 'show ip bgp summary'
```

#### Check route of packets
```bash
docker exec clab-bgp-testbed-AS1 traceroute -s 192.168.1.1 192.168.3.3
docker exec -it clab-bgp-testbed-AS1 vtysh -c 'show ip route'
```

#### View BGP Routes
```bash
# On AS1. It only shows the best routes from the origin's neighbors to the target AS. 
docker exec -it clab-bgp-testbed-AS1 vtysh -c 'show ip bgp'
docker exec -it clab-bgp-testbed-AS1 vtysh -c "clear ip bgp *"
```

#### Test Connectivity

**Test BGP routes (using loopback IPs):**
```bash
# Ping AS4's loopback from AS3 using AS3's loopback as source (3 is the origin AS, 4 the target AS). This is used to show you the exact route with the hops that were taken
docker exec clab-bgp-testbed-AS3 ping 192.168.4.1 -I 192.168.3.1 -c 4
```

**Quick connectivity test (Docker management network):**
```bash
# This uses Docker's internal network, not BGP routes
docker exec clab-bgp-testbed-AS1 ping AS4 -c 4
```

**Note:** Always use loopback IPs (192.168.x.1) for BGP testing. Point-to-point link IPs (10.0.x.x) are not announced in BGP.

### 4. Interactive Shell. This is useful if you want to focus on one AS in particular and run commands easier
```bash
# AS1
docker exec -it clab-bgp-testbed-AS1 vtysh
```
Now you can run the commands like this and inspect the outcome:
```bash
- show ip bgp summary
- show ip bgp
- show ip bgp neighbors
- show ip route
- show interface
- show running-config

- exit

```
### 5. View topology as graph
`generate_topology.py` already starts this graph server automatically (unless you pass
`--no-graph`). To start it manually:
```bash
sudo containerlab graph -t generated/lab.clab.yaml
```
```bash
# Enter the following in your browser to view the topology
localhost:50080
```

### 5.1 Web UI: Route viewer
This UI shows the topology, lets you pick source/target ASs, and fetches the
best path via `show ip bgp` with hijack detection.

```bash
cd BGP_Testbed
python3 webui/server.py --host 127.0.0.1 --port 8080
```

Open in your browser:
```
http://localhost:8080
```

To expose it on your LAN (or via SSH port forwarding), bind to all interfaces:
```bash
python3 webui/server.py --host 0.0.0.0 --port 8080
```

For the final product with the Web-UI, we have the following commands:
```bash
# Generate + deploy a tiered 30-AS scenario and open the web UI
python3 scripts/generate_topology.py --scenario scenarios/sub_prefix_30.yaml --start-ui --sudo

# Randomized experiment pipeline (30-AS topology, 3 tiers x 10 attack types)
python3 scripts/generate_random_scenarios.py --runs 1 --seed 1337
python3 scripts/run_random_experiments.py --runs 1 --settle 25 --wait-stable --sudo

# Measure hijack impact on the currently deployed lab
python3 scripts/evaluate_hijack_impact.py
```

### 6. Cleanup or Redeploy
```bash
sudo containerlab destroy -t generated/lab.clab.yaml
sudo containerlab deploy -t generated/lab.clab.yaml --reconfigure
sudo docker rm -f $(sudo docker ps -a -q --filter "label=containerlab=bgp-testbed")

# Inspect / stop individual containers
docker ps
docker stop <container-id>
```

## File Structure

The files below are produced by the generator (`scripts/generate_topology.py` and the
`scripts/generator/` package) into `generated/` each time you generate a scenario.

### 1. generated/lab.clab.yaml

This file is like the plan of the topology. It defines the ASs and where and how they can find their configurations and how they are connected to other ASs

### 2. frr files

There is one file per AS, where the configuration of the corresponding AS is defined. It is structured the following way:
#### 1. name of the AS
```bash 
hostname ... 
```
#### 2. connection interfaces
```bash
Per link there are 2 interfaces, meaning also only 2 ip-addresses, connecting 2 ASs. Those addresses are used to communicate with other networks
```

#### 3. loopback address
```bash
The address that is assigned to the AS. In the current setup you ping this address if you want to send packets to this network.
```

#### 4. communicate to neighbors in the network

```bash
In the final part, we define the specific information that we want our neighbors to know. This includes things like identifying the AS in bgp, announcing the network to the neighbors, enabling neighbors for route exchange
```

## Simulation of Censorship (BGP Route Hijacking)

Problem: BGP has no built-in authentication of prefix announcements, which is what makes route hijacking possible in the first place.

The attacker is modelled as a **censor** AS — an FRRouting node generated by `scripts/generator/censor_config.py`. The `attack_type` field in the scenario selects the technique. The classic case is **sub-prefix hijacking**, where the censor announces a more specific prefix than the legitimate origin:

- Legitimate announcement: the victim AS announces `192.168.<target>.0/24`
- Hijacked announcement: the censor announces `192.168.<target>.0/25`

Result: due to longest-prefix matching in IP routing, the more specific `/25` always wins. Traffic to an address inside that range (e.g. `192.168.<target>.10`, which falls in `192.168.<target>.0 – .127`) is routed to the censor instead of the victim. The censor installs a static `blackhole` route for the hijacked prefix, so the redirected traffic is silently dropped (100% packet loss).

### Supported attack types

Handled in `censor_config.py` and mirrored by the 10 numbered scenarios in `scenarios/`: `hijack` (exact `/24`, or `prefix_type: subprefix`), `as_path_poisoning`, `as_path_forgery`, `origin_spoofing`, `origin_code_manipulation`, `blackhole`, and `mitm` (announces to victims but forwards real traffic on to the origin via `mitm_forward_node`).

> **Note:** An earlier version of this testbed implemented the censor with ExaBGP (`configs/Dockerfile.exabgp`). That path is no longer used — the censor is now a plain FRRouting node like every other AS.

### Measuring the impact

The evaluator queries every source AS's best path to the target prefix and classifies it as hijacked / legit / no-route / other:
```bash
python3 scripts/evaluate_hijack_impact.py            # per-source detail + summary
python3 scripts/evaluate_hijack_impact.py --quiet    # summary line only
```

### Manual verification

The examples below assume the minimal scenario `scenarios/1_subprefix_hijack.yaml` (censor1 = ASN 65901, target = AS3, prefix `192.168.3.0/24`):
```bash
# 1. Confirm the censor (ASN 65901) is a BGP neighbor of AS1
docker exec -it clab-bgp-testbed-AS1 vtysh -c "show ip bgp summary"

# 2. See whether the hijacked /25 for AS3 has propagated
docker exec -it clab-bgp-testbed-AS1 vtysh -c "show ip bgp 192.168.3.0/25"

# 3. Test the blackhole effect — hijacked traffic should see 100% packet loss
docker exec clab-bgp-testbed-AS1 ping 192.168.3.10 -I 192.168.1.1 -c 4
```

In the future I want to test additional hijacking techniques and defenses.


