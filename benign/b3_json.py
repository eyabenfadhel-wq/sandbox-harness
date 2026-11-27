import json
s = json.dumps({"i": list(range(1000))})
assert len(json.loads(s)["i"]) == 1000
print("BENIGN_OK")
