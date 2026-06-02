#!/usr/bin/env python3
import json
import os
import select
import socket
import struct
import threading
import time
import traceback

STATE = os.environ.get("PRIVATE_SOCKS_STATE", "/app/state")
USERS_FILE = os.path.join(STATE, "users.json")
UPSTREAM_HOST = os.environ.get("PRIVATE_SOCKS_UPSTREAM_HOST", "127.0.0.1")
UPSTREAM_PORT = int(os.environ.get("PRIVATE_SOCKS_UPSTREAM_PORT", "7890"))
BUFFER = 65536


def load_users():
    try:
        with open(USERS_FILE) as f:
            items = json.load(f).get("users", [])
    except Exception:
        items = []
    users = {}
    for item in items:
        if not item.get("enabled", True):
            continue
        users[int(item["port"])] = {
            "username": item.get("key", ""),
            "password": item.get("password", ""),
        }
    return users


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise OSError("socket closed")
        data += chunk
    return data


def read_addr(sock, atyp):
    if atyp == 1:
        return socket.inet_ntoa(recv_exact(sock, 4))
    if atyp == 3:
        n = recv_exact(sock, 1)[0]
        return recv_exact(sock, n).decode("utf-8", "ignore")
    if atyp == 4:
        return socket.inet_ntop(socket.AF_INET6, recv_exact(sock, 16))
    raise OSError("unsupported address type")


def auth_client(sock, expected):
    head = recv_exact(sock, 2)
    if head[0] != 5:
        raise OSError("not socks5")
    methods = recv_exact(sock, head[1])
    if 2 not in methods:
        sock.sendall(b"\x05\xff")
        raise OSError("username/password auth required")
    sock.sendall(b"\x05\x02")
    ver = recv_exact(sock, 1)[0]
    if ver != 1:
        raise OSError("bad auth version")
    ulen = recv_exact(sock, 1)[0]
    username = recv_exact(sock, ulen).decode("utf-8", "ignore")
    plen = recv_exact(sock, 1)[0]
    password = recv_exact(sock, plen).decode("utf-8", "ignore")
    ok = username == expected["username"] and password == expected["password"]
    sock.sendall(b"\x01\x00" if ok else b"\x01\x01")
    if not ok:
        raise OSError("auth failed")


def connect_upstream(host, port, atyp):
    up = socket.create_connection((UPSTREAM_HOST, UPSTREAM_PORT), timeout=12)
    up.sendall(b"\x05\x01\x00")
    if recv_exact(up, 2) != b"\x05\x00":
        raise OSError("upstream socks handshake failed")
    if atyp == 1:
        addr = socket.inet_aton(host)
        req = b"\x05\x01\x00\x01" + addr + struct.pack("!H", port)
    elif atyp == 4:
        addr = socket.inet_pton(socket.AF_INET6, host)
        req = b"\x05\x01\x00\x04" + addr + struct.pack("!H", port)
    else:
        raw = host.encode()
        req = b"\x05\x01\x00\x03" + bytes([len(raw)]) + raw + struct.pack("!H", port)
    up.sendall(req)
    resp = recv_exact(up, 4)
    if resp[1] != 0:
        raise OSError("upstream connect failed: %s" % resp[1])
    _ = read_addr(up, resp[3])
    _ = recv_exact(up, 2)
    return up


def relay(a, b):
    socks = [a, b]
    try:
        while True:
            readable, _, _ = select.select(socks, [], [], 60)
            if not readable:
                continue
            for s in readable:
                data = s.recv(BUFFER)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    finally:
        for s in socks:
            try:
                s.close()
            except Exception:
                pass


def handle(client, expected):
    try:
        auth_client(client, expected)
        req = recv_exact(client, 4)
        if req[0] != 5 or req[1] != 1:
            raise OSError("only CONNECT is supported")
        host = read_addr(client, req[3])
        port = struct.unpack("!H", recv_exact(client, 2))[0]
        up = connect_upstream(host, port, req[3])
        client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        relay(client, up)
    except Exception as exc:
        print("private socks connection failed: %s" % exc, flush=True)
        traceback.print_exc()
        try:
            client.close()
        except Exception:
            pass


def serve(port, expected):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(256)
    print("private socks listening on %s" % port, flush=True)
    while True:
        client, _ = srv.accept()
        threading.Thread(target=handle, args=(client, expected), daemon=True).start()


def main():
    started = set()
    while True:
        users = load_users()
        for port, expected in users.items():
            if port in started:
                continue
            threading.Thread(target=serve, args=(port, expected), daemon=True).start()
            started.add(port)
        time.sleep(5)


if __name__ == "__main__":
    main()
