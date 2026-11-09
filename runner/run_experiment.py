import docker, time, csv, statistics, pathlib

client = docker.from_env()
ROOT = pathlib.Path(__file__).resolve().parent.parent
ATTACKS = sorted((ROOT / "red_team").glob("a*.py"))
SECRET = ROOT / "results" / "host_secret"
IMAGE = "python:3.12-slim"
RUNS = 10

def run(attack, hardened):
    vols = {str(attack): {"bind": "/attack.py", "mode": "ro"}}
    kw = dict(image=IMAGE, command=["python", "/attack.py"], detach=True)
    if hardened:
        kw.update(network_mode="none", read_only=True, mem_limit="64m",
                  pids_limit=64, cap_drop=["ALL"],
                  security_opt=["no-new-privileges"])
    else:
        vols[str(SECRET)] = {"bind": "/host", "mode": "ro"}  # naive harness
        kw["pids_limit"] = 1024  # safety net for your VM
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
    for mode, hard in (("baseline", False), ("hardened", True)):
        res = [run(atk, hard) for _ in range(RUNS)]
        asr = 100 * sum(r[0] for r in res) / RUNS
        lat = statistics.mean(r[1] for r in res)
        rows.append([atk.stem, mode, asr, round(lat, 1)])
        print(f"{atk.stem:15} {mode:9} ASR={asr:5.1f}%  latency={lat:7.1f} ms")

with open(ROOT / "results" / "results.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["attack", "mode", "ASR_percent", "latency_ms"])
    w.writerows(rows)
