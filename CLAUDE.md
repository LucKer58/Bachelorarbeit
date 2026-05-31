# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A virtualized BGP testbed (bachelor thesis) for studying internet censorship via BGP route
hijacking. A scenario YAML is compiled into FRRouting configs + a Containerlab topology, deployed
as Docker containers, then probed to measure how far an attacker ("censor") AS hijacks traffic
destined for a victim AS. Everything lives under `BGP_Testbed/`.

## Working directory

**All scripts assume the current directory is `BGP_Testbed/`.** They reference `scenarios/`,
`generated/`, and `results/` as relative paths, and `run_random_experiments.py` shells out to
`python3 scripts/...`. `generate_topology.py` is the exception — it `os.chdir`s to `BGP_Testbed/`
itself (`ensure_repo_root` in `scripts/generator/core.py`), so it works from anywhere. The VS Code
terminal is pre-set to `BGP_Testbed/` via `.vscode/settings.json`.

## Dependencies

No dependency manifest exists. Requirements: **Docker**, **Containerlab**, and Python 3 with
**PyYAML** (the only third-party Python import — everything else is stdlib). On this WSL2/Docker
setup, Containerlab/Docker generally need root: pass `--sudo` to the generator/experiment scripts,
which prepends `sudo` to the `docker`/`containerlab` invocations.

There is **no automated test suite**. Verification is empirical: deploy a scenario and run
`evaluate_hijack_impact.py` against the live containers.

## Core commands

Run from `BGP_Testbed/`:

```bash
# Generate configs + topology from a scenario and deploy it (containerlab deploy --reconfigure)
python3 scripts/generate_topology.py --scenario scenarios/1_subprefix_hijack.yaml --sudo
#   --no-deploy   only write generated/ files, skip containerlab
#   --no-graph    skip the containerlab graph server (port 50080)
#   --start-ui    launch the web UI after deploying
#   --no-hard-clean  skip force-removing existing lab containers first

# Measure hijack impact on the currently deployed lab (reads generated/scenario.yaml by default)
python3 scripts/evaluate_hijack_impact.py            # per-source detail + Summary line
python3 scripts/evaluate_hijack_impact.py --quiet    # Summary line only
#   prints: Summary: total=.. hijacked=.. legit=.. no-route=.. other=.. hijack_rate=..%

# Randomized experiment pipeline (30-AS topology, 3 tiers x 10 attack types)
python3 scripts/generate_random_scenarios.py --runs 1 --seed 1337   # -> scenarios/random_runs/
python3 scripts/run_random_experiments.py --runs 1 --settle 25 --wait-stable --sudo  # -> results/random_runs.csv

# Time BGP + ping recovery after a hijack is withdrawn (stops/starts the censor container)
python3 scripts/measure_convergence.py --auto-withdraw --auto-restore --wait-hijack

# Web UI: topology graph + interactive source->target route/hijack viewer
python3 webui/server.py --host 127.0.0.1 --port 8080

# Inspect a running node (container name = clab-<lab_name>-<node>, e.g. clab-bgp-testbed-AS3)
docker exec -it clab-bgp-testbed-AS3 vtysh -c 'show ip bgp summary'
docker exec -it clab-bgp-testbed-AS3 vtysh -c 'show ip bgp 192.168.21.0/24'

# Teardown
sudo containerlab destroy -t generated/lab.clab.yaml
```

## Pipeline architecture

`scenario YAML` → **generator** → `generated/` (FRR `.conf` per node + `lab.clab.yaml`) →
`containerlab deploy` → FRR Docker containers → **evaluator/UI** queries `vtysh` over `docker exec`.

`scripts/generate_topology.py` is the orchestrator. It calls the `scripts/generator/` package:

- **`core.py`** — `ensure_repo_root`, scenario loading, `build_connections` (assigns interfaces +
  link /30 IPs), `write_lab_file` (the Containerlab YAML — every node, router *and* censor, uses
  the `frrouting/frr:latest` image; RPKI scenarios add a `cloudflare/gortr` validator), `write_roas`.
- **`router_config.py`** — `build_router_configs` emits one FRR config per legit AS: interfaces,
  loopback, BGP, per-neighbor inbound route-maps, Gao-Rexford communities, and RPKI invalid-drop.
- **`censor_config.py`** — `build_censor_configs` emits the attacker's FRR config. The `attack_type`
  selects the technique (see below).
- **`deploy.py`** — `run_deploy` force-removes old lab containers, runs `containerlab deploy
  --reconfigure`, and starts the graph server.

`generate_topology.py` also computes **tier policies** (`build_tier_policies`, Gao-Rexford from the
`tiers` + `tier_policy` blocks) and **customer cones**, then merges them into the policy list before
config generation.

**State coupling:** `reset_generated_dir()` **wipes `generated/` on every generate run.**
`generate_topology.py` writes `generated/scenario.yaml` (a `{meta, scenario}` snapshot of the source
scenario); `evaluate_hijack_impact.py` and `webui/server.py` read that snapshot to learn the target,
censor names, prefix type, and tiers of whatever is currently deployed. `generated/` is gitignored.

## Naming & addressing conventions (critical — assumed everywhere)

Node numbers are parsed by regex `\d+` from the name (`AS21` → 21, `censor1` → 1). From that number:

| | Legit AS `ASn` | Censor `censorN` |
|---|---|---|
| ASN | `65000 + n` | `65900 + N` |
| Loopback / announced prefix | `192.168.n.1/24` → `192.168.n.0/24` | loopback `10.255.255.N/32` |
| Router-id | `n.n.n.n` | `9N.9N.9N.9N` |

- **Point-to-point link IPs are `10.0.<link_index>.1/30` / `.2/30` and are NOT announced in BGP.**
  Always test reachability with loopback IPs (`192.168.x.1`), never link IPs. A subprefix hijack
  announces `192.168.<target>.0/25`; the evaluator probes both `/24` and `/25`.
- `is_censor_name` / censor detection is **case-insensitive and name-prefix based** (`censor*`).
  Scenario files mix `Censor1` and `censor1`. ASN range (`65900–65999`) is what actually marks a
  hijacker in `path_asns` during classification.
- `no bgp ebgp-requires-policy` is set on every node so routes propagate without an explicit policy.

## Scenario YAML shape

`name`, `routers` (list of `ASn`), `links` (list of `[nodeA, nodeB]` pairs), and `censors` (each
with `name`, `target_router`, `attack_type`, and attack-specific keys). Optional: `tiers`
(`tier1/2/3` → AS lists) + `tier_policy` (Gao-Rexford local-prefs) to auto-derive customer/peer/
provider policies; `policies` (manual per-neighbor overrides: `local_preference`, `prepend_asn`,
`origin_code`, `target_node`, …); `rpki_routers` (ASes that drop RPKI-invalid routes, adds the gortr
validator). See `scenarios/sub_prefix_30.yaml` for the full tiered form, `scenarios/1_subprefix_hijack.yaml`
for the minimal form.

**`attack_type` values** (handled in `censor_config.py`): `hijack` (exact or `prefix_type:
subprefix`), `as_path_poisoning`, `as_path_forgery`, `origin_spoofing`, `origin_code_manipulation`,
`blackhole`, `mitm` (announces to victims but forwards real traffic via `mitm_forward_node`). The 10
numbered files in `scenarios/` are the canonical attack catalog mirrored by `SCENARIO_SPECS` in the
random-scenario scripts.

## Evaluation logic

`evaluate_hijack_impact.py` queries each source AS's best BGP path to the target prefix, parses the
AS-path, and classifies: **hijacked** (a censor ASN appears in the path), **legit** (path ends at the
origin ASN), **no-route**, or **other**. `run_random_experiments.py` drives this across all generated
scenarios, optionally waiting for BGP sessions (`--wait-bgp`), RPKI cache (`--wait-rpki`), and a
stable summary across repeated polls (`--wait-stable`) before recording each row.

## Notes

- The README's ExaBGP censor section is **legacy** — the censor is now an FRRouting node generated by
  `censor_config.py` (static blackhole route + crafted announcement), not the `configs/Dockerfile.exabgp`
  ExaBGP container. The README also has a stale path in its "final product" command block.
- `final_testbeds/` holds curated scenarios; `results/` holds experiment CSV output.
