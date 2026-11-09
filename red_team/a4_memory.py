# Tries to use 256 MB of RAM (the limit is 64 MB)
b = bytearray(256 * 1024 * 1024)
for i in range(0, len(b), 4096):
    b[i] = 1
print("ATTACK_SUCCESS")
