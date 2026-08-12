import socket
import sys
import time


ANSWERS = (
    "80, 443, 22",
    "nmap",
    "sql injection",
    "John Doe",
    "192.168.1.100",
)


def connect(host: str, port: int) -> socket.socket:
    last_error = None
    for _ in range(20):
        try:
            connection = socket.create_connection((host, port), timeout=2)
            connection.settimeout(5)
            return connection
        except OSError as error:
            last_error = error
            time.sleep(0.25)
    raise ConnectionError(f"could not connect to {host}:{port}") from last_error


def receive_until(connection: socket.socket, marker: bytes) -> bytes:
    output = bytearray()
    while marker not in output:
        chunk = connection.recv(4096)
        if not chunk:
            raise ConnectionError(f"connection closed before {marker!r}")
        output.extend(chunk)
    return bytes(output)


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: smoke_client.py HOST PORT EXPECTED_FLAG")

    host, port, expected_flag = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    output = bytearray()
    with connect(host, port) as connection:
        for answer in ANSWERS:
            output.extend(receive_until(connection, b">"))
            connection.sendall(answer.encode("utf-8") + b"\n")

        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            output.extend(chunk)

    decoded = output.decode("utf-8", errors="replace")
    if "INCORRECT" in decoded:
        raise SystemExit("container smoke test received an incorrect answer")
    if expected_flag not in decoded:
        raise SystemExit("container smoke test did not receive the expected flag")
    print("container network smoke test passed")


if __name__ == "__main__":
    main()
