from pwn import *

FLAG_REGEX = r"CTF{.*}"


ANSWERS = [
    "80, 443, 22",
    "nmap",
    "sql injection",
    "John Doe",
]

io = process(['python3', 'server.py'])

for i, ans in enumerate(ANSWERS, 1):
    io.recvuntil(b">")
    io.sendline(ans.encode())

print(io.recvall().decode())
