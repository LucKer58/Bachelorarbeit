# Virtualized Testbed for Censorship Research

## Overview
This repository contains the virtualized BGP/IP testbed using Docker, Containerlab, and FRRouting.

## Requirements
- WSL2 (Windows Subsystem for Linux) - for Windows users
- Docker Desktop (with WSL2 integration enabled)
- Containerlab
- VS Code

## Quick Start - Two Router Setup

### 1. Deploy the Topology
```bash
cd /mnt/c/Dev/Bachelorarbeit/BGP_Testbed
sudo containerlab deploy -t topologies/lab.clab.yaml
```

### 2. Verify Deployment
```bash
# Check containers are running
sudo containerlab inspect -t topologies/lab.clab.yaml
```

### 3. Observe BGP Status

#### Check BGP Neighbors
```bash
# On routerX (select X as the explicit router you want to observe)
docker exec -it clab-bgp-testbed-routerX vtysh -c 'show ip bgp summary'
```

#### View BGP Routes
```bash
# On routerX (again, select X as the explicit router). It only shows the best routes from the origin's neighbors to the target router. 
docker exec -it clab-bgp-testbed-routerX vtysh -c 'show ip bgp'
```

#### Test Connectivity

**Test BGP routes (using loopback IPs):**
```bash
# Ping routerY's loopback from routerX using RouterX's loopback as source (X is the origin router, Y the target router). This is used to show you the exact route with the hops that were taken
docker exec clab-bgp-testbed-router1 ping 192.168.Y.1 -I 192.168.X.1 -c 4
```

**Quick connectivity test (Docker management network):**
```bash
# This uses Docker's internal network, not BGP routes
docker exec clab-bgp-testbed-router1 ping router4 -c 4
```

**Note:** Always use loopback IPs (192.168.x.1) for BGP testing. Point-to-point link IPs (10.0.x.x) are not announced in BGP.

### 4. Interactive Shell. This is useful if you want to focus on one router in particular and run commands easier
```bash
# routerX, where X is the router you want to inspect
docker exec -it clab-bgp-testbed-routerX vtysh
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
```bash
# Run the following command
sudo containerlab graph -t topologies/lab.clab.yaml
```
```bash
# Enter the following in your browser to view the topology
localhost:50080
```

### 6. Cleanup or Redeploy
```bash
- sudo containerlab destroy -t topologies/lab.clab.yaml
- sudo containerlab deploy -t topologies/lab.clab.yaml --reconfigure
```

## File Structure

In this part we want to focus on the structure of the different files that make it work

### 1. lab.clab.yaml

This file is like the plan of the topology. It defines the routers and where and how they can find their configurations and how they are connected to other routers

### 2. frr files

There is one file per router, where the configuration of the corresponding router is defined. It is structured the following way:
#### 1. name of the router
```bash 
hostname ... 
```
#### 2. connection interfaces
```bash
Per link there are 2 interfaces, meaning also only 2 ip-addresses, connecting 2 routers. Those addresses are used to communicate with other networks
```

#### 3. loopback address
```bash
The address that is assigned to the router. In the current setup you ping this address if you want to send packets to this network.
```

#### 4. communicate to neighbors in the network

```bash
In the final part, we define the specific information that we want our neighbors to know. This includes things like identifying the router in bgp, announcing the network to the neighbors, enabling neighbors for route exchange
```
