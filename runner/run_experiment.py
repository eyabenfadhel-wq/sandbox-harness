import docker, time, csv, statistics, pathlib

client = docker.from_env()
ROOT = pathlib.Path(__file__).resolve().parent.parent
ATTACKS = sorted((ROOT / "red_team").glob("a[1-9]*.py"))
BENIGN = ROOT / "red_team" / "a0_benign.py"
SECRET = ROOT / "results" / "host_secret"
PROFILE = ROOT / "blue_team" / "seccomp_profile.json"
IMAGE = "python:3.12-slim"
RUNS = 10
MODES = ["baseline", "hardened", "hardened+seccomp"]

def run(script, mode):
    vols = {str(script): {"bind": "/attack.py", "mode": "ro"}}
    kw = dict(image=IMAGE, command=["python", "/attack.py"], detach=True)
    if mode == "baseline":
        vols[str(SECRET)] = {"bind": "/host", "mode": "ro"}  # naive harness
        kw["pids_limit"] = 1024  # safety net for the VM
    else:
        kw.update(network_mode="none", read_only=True, mem_limit="64m",
                  pids_limit=64, cap_drop=["ALL"],
                  security_opt=["no-new-privileges"])
        if mode == "hardened+seccomp":
            kw["security_opt"].append("seccomp=" + PROFILE.read_text())
    kw["volumes"] = vols
    t = time.perf_counter()
    c = client.containers.run(**kw)
    c.wait()
    out = c.logs().decode()
    lat = (time.perf_counter() - t) * 1000
    c.remove(force=True)
    return "ATTACK_SUCCESS" in out, lat

rows = []
for atk in ATTACKS:
    for mode in MODES:
        res = [run(atk, mode) for _ in range(RUNS)]
        asr = 100 * sum(r[0] for r in res) / RUNS
        rows.append([atk.stem, mode, asr, ""])
        print(f"{atk.stem:14} {mode:17} ASR={asr:5.1f}%")

print()
for mode in MODES:   # real overhead: harmless code, same work in every mode
    lat = statistics.mean(run(BENIGN, mode)[1] for _ in range(20))
    rows.append(["a0_benign", mode, "", round(lat, 1)])
    print(f"benign         {mode:17} latency={lat:7.1f} ms")

with open(ROOT / "results" / "results.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["attack", "mode", "ASR_percent", "latency_ms"])
    w.writerows(rows)
