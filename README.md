# Project 09 - Isolated Ephemeral Code-Execution Sandbox Harness for AI Coding Agents

Docker Rootless, Seccomp and Zero-Egress. Red-vs-Blue prototype.

AI-generated Python code is executed in an ephemeral, rootless Docker container.
Five Red Team attacks are run against three configurations: a vulnerable baseline,
a hardened container, and a hardened container with a custom seccomp profile.
Results are measured with Attack Success Rate (ASR), false-positive rate and latency.

## Requirements
- Ubuntu 22.04 (tested in a VMware VM)
- Docker in rootless mode
- Python 3 with the Docker SDK (pip install docker)

## Setup
    dockerd-rootless-setuptool.sh install
    python3 -m venv ~/sandbox-env && source ~/sandbox-env/bin/activate
    pip install docker
    docker pull python:3.12-slim
    mkdir -p results/host_secret
    echo "TOP-SECRET-HOST-DATA" > results/host_secret/secret.txt
    python blue_team/make_profile.py

Note: the root Docker service must be stopped before the rootless setup:
    sudo systemctl disable --now docker.service docker.socket

## Run
    python runner/run_experiment.py     # ASR (10 runs) and latency -> results/results.csv
    python runner/false_positive.py     # false positives -> results/false_positive.csv
    python demo/demo.py a1              # live demo of one attack (a1 to a5)

## Project layout
- red_team/    Attack scripts a1 to a5, and a0_benign.py (harmless script used for latency)
- benign/      Five harmless workloads for the false-positive test
- blue_team/   make_profile.py builds seccomp_profile.json from Docker's default profile
- runner/      run_experiment.py and false_positive.py
- demo/        Step-by-step demo script (before hardening, after hardening, with seccomp)
- results/     CSV results (results_initial.csv is the first experimental run)
- slides/      Threat model and sequence diagrams (Mermaid / PlantUML sources)

## Where baseline and hardened are defined
In runner/run_experiment.py, function run(script, mode):
- baseline: host folder mounted at /host, network on, no memory limit, process cap raised only as a VM safety net
- hardened: network_mode none, read-only filesystem, 64 MB memory, 64 processes, all capabilities dropped, no-new-privileges
- hardened+seccomp: hardened plus the custom seccomp profile (Docker default minus ptrace, process_vm_readv, process_vm_writev, kcmp)

## Attacks (Red Team)
- a1: reads a file of the host (CWE-668, CWE-552)
- a2: fork bomb, bounded to 500 processes (CWE-770, CWE-400)
- a3: network egress (CWE-200, CWE-668)
- a4: memory exhaustion, 256 MB against a 64 MB limit (CWE-770, CWE-400)
- a5: ptrace syscall (CWE-653, CWE-269)

## Results
ASR, 10 runs per attack and mode:

    attack   baseline  hardened  hardened+seccomp
    a1       100%      0%        0%
    a2       100%      0%        0%
    a3       100%      0%        0%
    a4       100%      0%        0%
    a5       100%      100%      0%

Only the custom seccomp profile stops a5 (ptrace). The other attacks are stopped by
isolation, cgroups and the network setting.

False positives, 5 harmless scripts x 5 runs:

    baseline                 0%
    hardened                 20%  (b4_tmpfile: read-only filesystem blocks writes to /tmp)
    hardened+seccomp         20%  (b4_tmpfile)
    hardened+seccomp+tmpfs   0%   (a 16 MB in-memory tmpfs on /tmp removes the false positive)

Latency of a harmless script, mean of 20 runs: baseline 880 ms, hardened 722 ms,
hardened+seccomp 770 ms. Container startup dominates; the differences are within noise.

## Limits
- Kernel and container-runtime escapes are out of scope.
- Only five attacks were tested; 0% ASR applies to these attacks only.
- The tmpfs variant was tested for false positives only. The ASR table was measured without it.
- Five harmless scripts is a small sample for the false-positive rate.
