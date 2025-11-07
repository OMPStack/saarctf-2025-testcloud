#!/usr/bin/env python3

import socket
import time
import hashlib
import threading

HOST = "0.0.0.0"
PORT = 4444
PER_CONN_TIMEOUT = 60  # seconds

def send(s, msg):
    """Send a string safely, append newline if not present."""
    if not msg.endswith("\n"):
        msg = msg + "\n"
    try:
        s.sendall(msg.encode("utf-8", errors="replace"))
    except OSError:
        pass

def current_millis():
    """Return current time in milliseconds as an int."""
    return int(time.time() * 1000)

def generate_flag(prefix="CTF_"):
    """
    Create a flag by hashing the current time (milliseconds) with SHA-1.
    """
    ms = current_millis()
    ms_bytes = str(ms).encode("utf-8")
    digest = hashlib.sha1(ms_bytes).hexdigest()  # 40 hex chars
    return f"{prefix}{digest}"

def handle_client(conn, addr):
    conn.settimeout(PER_CONN_TIMEOUT)

    send(conn, "Welcome to the dummy ctf service!")
    send(conn, "What do you want to do?")

    send(conn, "\t - giv_flag_pls: returns you some flag looking thing")
    send(conn, "\t - attackerino: you wont get nothing if you are not nice")
    send(conn, "> ")

    iter = 0
    while iter < 10:
        iter += 1

        try:
            data = conn.recv(1000)
            if not data:
                break
        except socket.timeout:
            send(conn, "Timeout. Closing connection.")
            break
        except Exception:
            break

        print("Got: ", data)

        if data[:12] == b"giv_flag_pls":
            send(conn, "Here you go: " + generate_flag("FLAG_"))
        elif b"exit" in data:
            send(conn, "Bye.")
            break
        else:
            send(conn, "You have been a bad boy! You get nothing.")

    conn.close()

def start_server(host=HOST, port=PORT):
    print(f"Starting CTF service on {host}:{port}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # SO_REUSEADDR is helpful during development
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(8)
        print("Listening... (Ctrl-C to stop)")
        try:
            while True:
                conn, addr = s.accept()
                print(f"[+] Connection from {addr}")
                t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
                t.start()
        except KeyboardInterrupt:
            print("\nServer shutting down.")

if __name__ == "__main__":
    start_server()