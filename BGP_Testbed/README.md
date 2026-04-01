# Virtualized Testbed for Censorship Research

## Overview
This repository contains the virtualized BGP/IP testbed using Docker, Containerlab, and FRRouting.

## Requirements
- WSL2 (Windows Subsystem for Linux) - for Windows users
- Docker Desktop (with WSL2 integration enabled)
- Containerlab
- VS Code

## Setup of the Topology using FRRouting

### 1. Deploy the Topology
```bash
cd /mnt/c/Dev/Bachelorarbeit/BGP_Testbed/...
sudo containerlab deploy -t lab.clab.yaml
```

### 2. Verify Deployment
```bash
# Check containers are running
sudo containerlab inspect -t lab.clab.yaml
```

### 3. Observe BGP Status

#### Check BGP Neighbors
```bash
# On router1
docker exec -it clab-bgp-testbed-router1 vtysh -c 'show ip bgp summary'
```

#### View BGP Routes
```bash
# On router1. It only shows the best routes from the origin's neighbors to the target router. 
docker exec -it clab-bgp-testbed-router1 vtysh -c 'show ip bgp'
```

#### Test Connectivity

**Test BGP routes (using loopback IPs):**
```bash
# Ping router4's loopback from router3 using Router3's loopback as source (3 is the origin router, 4 the target router). This is used to show you the exact route with the hops that were taken
docker exec clab-bgp-testbed-router3 ping 192.168.4.1 -I 192.168.3.1 -c 4
```

**Quick connectivity test (Docker management network):**
```bash
# This uses Docker's internal network, not BGP routes
docker exec clab-bgp-testbed-router1 ping router4 -c 4
```

**Note:** Always use loopback IPs (192.168.x.1) for BGP testing. Point-to-point link IPs (10.0.x.x) are not announced in BGP.

### 4. Interactive Shell. This is useful if you want to focus on one router in particular and run commands easier
```bash
# router1
docker exec -it clab-bgp-testbed-router1 vtysh
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
sudo containerlab graph -t lab.clab.yaml
```
```bash
# Enter the following in your browser to view the topology
localhost:50080
```

### 6. Cleanup or Redeploy
```bash
- sudo containerlab destroy -t lab.clab.yaml
- sudo containerlab deploy -t lab.clab.yaml --reconfigure
- containerlab destroy -t lab.clab.yaml && containerlab deploy -t lab.clab.yaml
- sudo docker rm -f $(sudo docker ps -a -q --filter "label=containerlab=bgp-testbed")
```
docker ps
docker stop (id)

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

## Simulation of Censorship using ExaBGP

Problem: BGP has no implemented authentication of prefixes, which allows sub-prefix hijacking in the first place

We implement sub-prefix hijacking where the censor announces a more specific prefix than the legitimate network:

- Legitimate announcement: Router1 announces `192.168.1.0/24`
- Hijacked announcement: ExaBGP censor announces `192.168.1.0/25`

Result: Due to longest-prefix matching in IP routing, the /25 announcement wins and traffic is routed to the censor (blackhole). If for example define the packet destination 192.168.1.10, instead of taking the direct route to the 192.168.1.0/24 network (192-168.1.0 - 192.168.1.255), the packet takes the route to the censor which defines a more specific prefix (192.168.1.0 - 192.168.1.127), of which the packet is part. In BGP, the more specific prefix always wins.

### Configuration Files

- `configs/Dockerfile.exabgp` Makes the image (building plan) for the docker files. With the frrouting docker containers, the image is given by frrouting, while for the exabgp docker containers, the image or content of the docker files is defined in this file.
- `configs/exabgp-censor.conf` Defines what the censor tells to who. The structure can be found under this link: https://github.com/Exa-Networks/exabgp/blob/main/etc/exabgp/conf-ipself4.conf It is similar, except that we focus on eBGP instead of iBGP
- `configs/frr2.conf` Router2 with connection to censor, doesn't change the structure of the files
- `topologies/lab.clab.yaml` ExaBGP container definition

### Testing the Censorship

#### 1. Verify ExaBGP is Running
```bash
# You should see "connected to peer-1 with outgoing-1 10.0.5.2-10.0.5.1". This means that the connection between the censor and router2 is successfully established.
sudo docker logs clab-bgp-testbed-exabgp-censor
```

#### 2. Check BGP Session
```bash
# You can see that the censor AS 65999 is also part of the neighbors of router 2
sudo docker exec -it clab-bgp-testbed-router2 vtysh -c "show ip bgp summary"
```

#### 3. Verify Route Hijacking
```bash
# Shows routes from router3 to the network 192.168.1.0/25. This shows you, if the BGP-session to the censor works.
sudo docker exec -it clab-bgp-testbed-router3 vtysh -c "show ip bgp 192.168.1.0/25"
```

#### 4. Test Blackhole Effect
```bash
# Now we really want to test, if the censor does its work by redirecting the sent packets to a deadend and are lost, not reaching its intended destination. You should see 100% packet loss.
sudo docker exec clab-bgp-testbed-router3 ping 192.168.1.10 -I 192.168.3.1 -c 4
```


In the future I want to test additional hijacking techniques


