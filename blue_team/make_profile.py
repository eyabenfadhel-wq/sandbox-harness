import json, urllib.request, pathlib

URLS = [
 "https://raw.githubusercontent.com/moby/profiles/main/seccomp/default.json",
 "https://raw.githubusercontent.com/moby/moby/master/profiles/seccomp/default.json",
]
DENY = {"ptrace", "process_vm_readv", "process_vm_writev", "kcmp"}

data = None
for u in URLS:
    try:
        data = json.load(urllib.request.urlopen(u, timeout=20))
        break
    except Exception as e:
        print("failed:", u, e)
assert data, "could not download the default profile"

for rule in data["syscalls"]:
    rule["names"] = [n for n in rule["names"] if n not in DENY]
data["syscalls"] = [r for r in data["syscalls"] if r["names"]]

out = pathlib.Path(__file__).parent / "seccomp_profile.json"
out.write_text(json.dumps(data, indent=2))
print("written:", out, "| denied:", sorted(DENY))
