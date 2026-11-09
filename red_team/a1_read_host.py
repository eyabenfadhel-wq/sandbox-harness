# Simulates AI-generated code reading a host file
try:
    print(open("/host/secret.txt").read())
    print("ATTACK_SUCCESS")
except Exception as e:
    print("BLOCKED:", e)
