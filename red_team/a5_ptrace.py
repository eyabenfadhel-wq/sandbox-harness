# Tries the ptrace syscall (process spying / injection)
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
r = libc.ptrace(0, 0, 0, 0)   # PTRACE_TRACEME
if r == 0:
    print("ATTACK_SUCCESS")
else:
    print("BLOCKED: errno", ctypes.get_errno())
