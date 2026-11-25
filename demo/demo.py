import docker, os, sys, time, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
client = docker.from_env()
IMAGE = "python:3.12-slim"
SECRET = ROOT / "results" / "host_secret"
PROFILE = ROOT / "blue_team" / "seccomp_profile.json"

R, G, Y, B, W, E = "\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[1m", "\033[0m"

ATTACKS = {
    "a1": "reads a secret file that belongs to the HOST",
    "a2": "fork bomb: tries to create 500 processes",
    "a3": "tries to send data out to the internet",
    "a4": "tries to use 256 MB of RAM",
    "a5": "calls the ptrace syscall (process spying)",
}

MODES = {
    "baseline": ("1) BEFORE HARDENING (baseline)",
                 "host folder mounted, network ON, no RAM limit, no custom seccomp"),
    "hardened": ("2) AFTER HARDENING (without custom seccomp)",
                 "--network none --read-only --memory 64m --pids-limit 64 "
                 "--cap-drop ALL --security-opt no-new-privileges"),
    "seccomp":  ("3) HARDENED + CUSTOM SECCOMP",
                 "same as 2) + --security-opt seccomp=seccomp_profile.json"),
}

def run(script, mode):
    vols = {str(script): {"bind": "/attack.py", "mode": "ro"}}
    kw = dict(image=IMAGE, command=["python", "/attack.py"], detach=True)
    if mode == "baseline":
        vols[str(SECRET)] = {"bind": "/host", "mode": "ro"}
        kw["pids_limit"] = 1024   # safety net for the VM
    else:
        kw.update(network_mode="none", read_only=True, mem_limit="64m",
                  pids_limit=64, cap_drop=["ALL"],
                  security_opt=["no-new-privileges"])
        if mode == "seccomp":
            kw["security_opt"].append("seccomp=" + PROFILE.read_text())
    kw["volumes"] = vols
    t = time.perf_counter()
    c = client.containers.run(**kw)
    code = c.wait()["StatusCode"]
    out = c.logs().decode().strip()
    lat = (time.perf_counter() - t) * 1000
    c.remove(force=True)
    return out, code, lat

def main():
    key = sys.argv[1] if len(sys.argv) > 1 else ""
    if key not in ATTACKS:
        print("usage: python demo/demo.py a1|a2|a3|a4|a5")
        return
    script = next((ROOT / "red_team").glob(key + "_*.py"))
    benign = ROOT / "red_team" / "a0_benign.py"
    os.system("clear")
    print(f"{W}ATTACK {key.upper()}: {ATTACKS[key]}{E}\n")
    print(f"{Y}--- attack code ({script.name}) ---{E}")
    for i, line in enumerate(script.read_text().splitlines(), 1):
        print(f"{i:2}  {line}")

    summary = []
    for mode in ("baseline", "hardened", "seccomp"):
        input(f"\n{B}[Enter] to run: {MODES[mode][0]}{E}")
        print(f"{W}{MODES[mode][0]}{E}")
        print(f"config: {MODES[mode][1]}")
        out, code, lat = run(script, mode)
        print("container output:")
        print(out)
        print(f"exit code: {code}")
        success = "ATTACK_SUCCESS" in out
        asr = 100 if success else 0
        if success:
            print(f"{R}{W}>>> ATTACK SUCCEEDED{E}")
        else:
            print(f"{G}{W}>>> ATTACK BLOCKED{E}")
        col = R if success else G
        print(f"{W}ASR = {col}{asr}%{E}   {W}latency = {lat:.0f} ms{E}")
        summary.append((MODES[mode][0], asr, lat))

    input(f"\n{B}[Enter] to measure the cost of the defenses on harmless code{E}")
    print(f"{W}Benign script (print hello):{E}")
    for mode in ("baseline", "hardened", "seccomp"):
        out, _, lat = run(benign, mode)
        ok = "works" if "hello" in out else "BROKEN"
        print(f"  {MODES[mode][0]:46} {lat:6.0f} ms   ({ok})")

    print(f"\n{W}SUMMARY for attack {key.upper()}{E}")
    print(f"{'stage':48}{'ASR':>6}{'latency':>12}")
    for name, asr, lat in summary:
        print(f"{name:48}{asr:5d}%{lat:9.0f} ms")
    print()

main()
