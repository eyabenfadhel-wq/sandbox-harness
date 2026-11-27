import docker, csv, pathlib
client = docker.from_env()
ROOT = pathlib.Path(__file__).resolve().parent.parent
PROFILE = (ROOT / "blue_team" / "seccomp_profile.json").read_text()
WORK = sorted((ROOT / "benign").glob("b*.py"))
RUNS = 5
MODES = ["baseline", "hardened", "hardened+seccomp", "hardened+seccomp+tmpfs"]

def ok(script, mode):
    kw = dict(image="python:3.12-slim", command=["python", "/w.py"], detach=True,
              volumes={str(script): {"bind": "/w.py", "mode": "ro"}})
    if mode != "baseline":
        kw.update(network_mode="none", read_only=True, mem_limit="64m", pids_limit=64,
                  cap_drop=["ALL"], security_opt=["no-new-privileges"])
        if "seccomp" in mode:
            kw["security_opt"].append("seccomp=" + PROFILE)
        if "tmpfs" in mode:
            kw["tmpfs"] = {"/tmp": "size=16m"}
    c = client.containers.run(**kw)
    c.wait()
    out = c.logs().decode()
    c.remove(force=True)
    return "BENIGN_OK" in out

rows = []
for mode in MODES:
    failed = {}
    for wk in WORK:
        for _ in range(RUNS):
            if not ok(wk, mode):
                failed[wk.stem] = failed.get(wk.stem, 0) + 1
    fp = 100 * sum(failed.values()) / (len(WORK) * RUNS)
    names = ", ".join(sorted(failed)) or "-"
    rows.append([mode, round(fp, 1), names])
    print(f"{mode:24} false-positive rate = {fp:5.1f}%   failing: {names}")

with open(ROOT / "results" / "false_positive.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["mode", "false_positive_percent", "failing_workloads"])
    w.writerows(rows)
