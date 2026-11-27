n = sum(1 for i in range(2, 20000) if all(i % d for d in range(2, int(i**0.5) + 1)))
print(n)
print("BENIGN_OK")
