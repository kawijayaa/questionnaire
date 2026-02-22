from pwn import *
import re

FLAG_REGEX = "CTF{.*}"

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

flag = re.search(FLAG_REGEX, io.recvall().decode())
if flag:
    print(flag.group())
