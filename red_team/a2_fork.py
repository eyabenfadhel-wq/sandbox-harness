# Bounded fork bomb: tries to spawn 500 processes
import os, time
n = 0
try:
    for _ in range(500):
        if os.fork() == 0:
            time.sleep(5)
            os._exit(0)
        n += 1
except OSError as e:
    print("BLOCKED:", e)
print("spawned", n)
if n >= 400:
    print("ATTACK_SUCCESS")
