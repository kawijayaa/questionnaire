import re
import sys

from pwn import *

# context.log_level = 'debug'

FLAG_REGEX = r"CTF\{.*?\}"

ANSWERS = [
    "80, 443, 22",
    "nmap",
    "sql injection",
    "John Doe",
    "192.168.1.100",
]

if len(sys.argv) == 3:
    io = remote(sys.argv[1], int(sys.argv[2]))
    log.info(f"Connected to remote {sys.argv[1]}:{sys.argv[2]}")
else:
    io = process(["python3", "server.py"], env={"FLAG": "CTF{test_flag_local}"})
    log.info("Started local server process")

for i, ans in enumerate(ANSWERS, 1):
    q_text_bytes = io.recvuntil(b">")
    q_text = q_text_bytes.decode("utf-8", errors="ignore")

    log.info(f"Answering question {i} with: '{ans}'")
    io.sendline(ans.encode())

    resp_bytes = io.recvline()
    resp = resp_bytes.decode("utf-8", errors="ignore")

    if "INCORRECT" in resp:
        log.failure(f"Answer for Question {i} was INCORRECT!")
        log.failure("Question context was:")
        for line in q_text.split("\n"):
            if line.strip():
                log.failure(line.strip())
        sys.exit(1)
    else:
        log.success(f"Question {i} correct!")

log.info("Searching for flag in remaining output...")
try:
    output = io.recvall(timeout=2).decode("utf-8", errors="ignore")
    flag = re.search(FLAG_REGEX, output)
    if flag:
        log.success(f"Found flag: {flag.group()}")
    else:
        log.failure("Flag not found in final output!")
except Exception as e:
    log.error(f"Error receiving flag: {e}")
