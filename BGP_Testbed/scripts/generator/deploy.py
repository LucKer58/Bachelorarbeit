import os
import subprocess


def run_deploy(args, bash_dir):
    if args.no_deploy:
        return

    deploy_cwd = os.path.join(bash_dir, "generated")
    if not args.no_hard_clean:
        list_cmd = [
            "docker",
            "ps",
            "-a",
            "-q",
            "--filter",
            "label=containerlab=bgp-testbed",
        ]
        if args.sudo:
            list_cmd.insert(0, "sudo")
        result = subprocess.run(list_cmd, capture_output=True, text=True, check=False)
        container_ids = [cid for cid in result.stdout.split() if cid]
        if container_ids:
            rm_cmd = ["docker", "rm", "-f", *container_ids]
            if args.sudo:
                rm_cmd.insert(0, "sudo")
            subprocess.run(rm_cmd, check=False)

    deploy_cmd = ["containerlab", "deploy", "-t", "lab.clab.yaml", "--reconfigure"]
    if args.sudo:
        deploy_cmd.insert(0, "sudo")
    subprocess.run(deploy_cmd, cwd=deploy_cwd, check=True)

    if not args.no_graph:
        subprocess.run(["pkill", "-f", "containerlab graph"], check=False)
        graph_cmd = ["containerlab", "graph", "-t", "lab.clab.yaml"]
        if args.sudo:
            graph_cmd.insert(0, "sudo")
        subprocess.Popen(
            graph_cmd,
            cwd=deploy_cwd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
