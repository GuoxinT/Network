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
UDP_ASSOC_TTL = 180


class UdpAssoc:
    def __init__(self, client_addr, upstream_ctrl, upstream_udp_addr):
        self.client_addr = client_addr
        self.upstream_ctrl = upstream_ctrl
        self.upstream_udp_addr = upstream_udp_addr
        self.last_seen = time.time()

    def close(self):
        try:
            self.upstream_ctrl.close()
        except Exception:
            pass


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


def pack_addr(host, port):
    try:
        raw = socket.inet_aton(host)
        return b"\x01" + raw + struct.pack("!H", port)
    except OSError:
        pass
    try:
        raw = socket.inet_pton(socket.AF_INET6, host)
        return b"\x04" + raw + struct.pack("!H", port)
    except OSError:
        pass
    raw = host.encode()
    if len(raw) > 255:
        raise OSError("hostname too long")
    return b"\x03" + bytes([len(raw)]) + raw + struct.pack("!H", port)


def unpack_addr_from(data, offset):
    atyp = data[offset]
    offset += 1
    if atyp == 1:
        host = socket.inet_ntoa(data[offset:offset + 4])
        offset += 4
    elif atyp == 3:
        n = data[offset]
        offset += 1
        host = data[offset:offset + n].decode("utf-8", "ignore")
        offset += n
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])
        offset += 16
    else:
        raise OSError("unsupported udp address type")
    port = struct.unpack("!H", data[offset:offset + 2])[0]
    offset += 2
    return host, port, offset


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


def open_upstream_socks():
    up = socket.create_connection((UPSTREAM_HOST, UPSTREAM_PORT), timeout=12)
    up.sendall(b"\x05\x01\x00")
    if recv_exact(up, 2) != b"\x05\x00":
        raise OSError("upstream socks handshake failed")
    return up


def socks_request(up, cmd, host, port):
    req = b"\x05" + bytes([cmd]) + b"\x00" + pack_addr(host, port)
    up.sendall(req)
    resp = recv_exact(up, 4)
    if resp[1] != 0:
        raise OSError("upstream connect failed: %s" % resp[1])
    bind_host = read_addr(up, resp[3])
    bind_port = struct.unpack("!H", recv_exact(up, 2))[0]
    return bind_host, bind_port


def connect_upstream(host, port):
    up = open_upstream_socks()
    socks_request(up, 1, host, port)
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


def udp_loop(sock, assocs, upstreams, lock):
    while True:
        try:
            data, addr = sock.recvfrom(BUFFER)
            now = time.time()
            with lock:
                expired = [a for a, assoc in assocs.items() if now - assoc.last_seen > UDP_ASSOC_TTL]
                for a in expired:
                    assoc = assocs.pop(a, None)
                    if assoc:
                        upstreams.pop(assoc.upstream_udp_addr, None)
                        assoc.close()
                assoc = assocs.get(addr)
                client_addr = upstreams.get(addr)
                if not assoc and not client_addr:
                    for candidate_addr, candidate in list(assocs.items()):
                        if candidate_addr[0] == addr[0]:
                            assocs.pop(candidate_addr, None)
                            candidate.client_addr = addr
                            assocs[addr] = candidate
                            upstreams[candidate.upstream_udp_addr] = addr
                            assoc = candidate
                            break
                if assoc:
                    assoc.last_seen = now
                    target = assoc.upstream_udp_addr
                elif client_addr:
                    target = client_addr
                else:
                    continue
            sock.sendto(data, target)
        except Exception as exc:
            print("private socks udp relay failed: %s" % exc, flush=True)
            traceback.print_exc()


def handle_udp_associate(client, udp_sock, client_addr, assocs, upstreams, lock, bind_port):
    up = open_upstream_socks()
    bind_host, upstream_port = socks_request(up, 3, "0.0.0.0", 0)
    upstream_udp_addr = (bind_host, int(upstream_port))
    assoc = UdpAssoc(client_addr, up, upstream_udp_addr)
    with lock:
        old = assocs.get(client_addr)
        if old:
            upstreams.pop(old.upstream_udp_addr, None)
            old.close()
        assocs[client_addr] = assoc
        upstreams[upstream_udp_addr] = client_addr
    client.sendall(b"\x05\x00\x00" + pack_addr("0.0.0.0", bind_port))
    try:
        while client.recv(1):
            assoc.last_seen = time.time()
    finally:
        with lock:
            for key, cur in list(assocs.items()):
                if cur is assoc:
                    assocs.pop(key, None)
            upstreams.pop(upstream_udp_addr, None)
        assoc.close()


def handle(client, expected, udp_sock, assocs, upstreams, lock, bind_port, client_addr):
    try:
        auth_client(client, expected)
        req = recv_exact(client, 4)
        if req[0] != 5:
            raise OSError("bad socks version")
        host = read_addr(client, req[3])
        port = struct.unpack("!H", recv_exact(client, 2))[0]
        if req[1] == 1:
            up = connect_upstream(host, port)
            client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            relay(client, up)
        elif req[1] == 3:
            handle_udp_associate(client, udp_sock, client_addr, assocs, upstreams, lock, bind_port)
        else:
            raise OSError("only CONNECT and UDP ASSOCIATE are supported")
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
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.bind(("0.0.0.0", port))
    assocs = {}
    upstreams = {}
    lock = threading.Lock()
    threading.Thread(target=udp_loop, args=(udp_sock, assocs, upstreams, lock), daemon=True).start()
    print("private socks listening on %s" % port, flush=True)
    while True:
        client, client_addr = srv.accept()
        threading.Thread(
            target=handle,
            args=(client, expected, udp_sock, assocs, upstreams, lock, port, client_addr),
            daemon=True,
        ).start()


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
