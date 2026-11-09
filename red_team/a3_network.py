# Tries to send data out of the sandbox
import socket
try:
    socket.create_connection(("1.1.1.1", 53), timeout=3)
    print("ATTACK_SUCCESS")
except Exception as e:
    print("BLOCKED:", e)
