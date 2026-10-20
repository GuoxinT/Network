#!/usr/bin/env python3
import json
import os
import base64
import select
import socket
import struct
import threading
import time
import traceback

STATE = os.environ.get("PRIVATE_SOCKS_STATE", "/app/state")
USERS_FILE = os.path.join(STATE, "users.json")
LOG_DIR = os.path.join(STATE, "logs")
UPSTREAM_HOST = os.environ.get("PRIVATE_SOCKS_UPSTREAM_HOST", "127.0.0.1")
UPSTREAM_PORT = int(os.environ.get("PRIVATE_SOCKS_UPSTREAM_PORT", "7890"))
UPSTREAM_AUTH_PASSWORD = os.environ.get("PRIVATE_SOCKS_UPSTREAM_AUTH_PASSWORD", "schoolvpn-private-route")
BUFFER = 65536
UDP_ASSOC_TTL = 180

# Per-connection byte accounting. The portal (server.py) tails one log file per
# listening port and bills the bytes to the key that owns that port. We mirror
# ssserver's close-line grammar so a single parser covers both proxies, and we
# log on *every* close (clean or error), unlike ssserver, so no bytes are lost.
_log_lock = threading.Lock()


def log_conn(port, expected, client_addr, host, dport, up_bytes, down_bytes):
    if up_bytes <= 0 and down_bytes <= 0:
        return
    key = (expected or {}).get("username") or "unknown"
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        path = os.path.join(LOG_DIR, "user-%s-%s.log" % (port, key))
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        cip = client_addr[0] if client_addr else "?"
        cport = client_addr[1] if client_addr else 0
        # L2R = client→remote = upload; R2L = download.
        line = ("%s tcp tunnel %s:%s <-> %s:%s closed, "
                "L2R %d bytes, R2L %d bytes\n"
                % (ts, cip, cport, host, dport, int(up_bytes), int(down_bytes)))
        with _log_lock, open(path, "a") as f:
            f.write(line)
    except Exception:
        pass


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


def route_from_username(username, expected):
    base = expected["username"]
    if username == base:
        return "private-default"
    prefix = base + "__"
    if username.startswith(prefix):
        route = username[len(prefix):]
        if route:
            return route
    return None


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
    route_user = route_from_username(username, expected)
    ok = bool(route_user) and password == expected["password"]
    sock.sendall(b"\x01\x00" if ok else b"\x01\x01")
    if not ok:
        raise OSError("auth failed")
    return route_user


def check_basic_auth(headers, expected):
    raw = headers.get("proxy-authorization", "")
    prefix = "basic "
    if not raw.lower().startswith(prefix):
        return False
    try:
        decoded = base64.b64decode(raw[len(prefix):].strip()).decode("utf-8", "ignore")
    except Exception:
        return False
    username, sep, password = decoded.partition(":")
    if not sep or password != expected["password"]:
        return None
    return route_from_username(username, expected)


def recv_http_head(sock):
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = sock.recv(4096)
        if not chunk:
            raise OSError("socket closed")
        data += chunk
    head, rest = data.split(b"\r\n\r\n", 1)
    text = head.decode("iso-8859-1", "ignore")
    lines = text.split("\r\n")
    request_line = lines[0]
    headers = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip().lower()] = value.strip()
    return request_line, headers, rest


def http_error(sock, code, reason, headers=None):
    extra = ""
    for name, value in (headers or {}).items():
        extra += "%s: %s\r\n" % (name, value)
    body = ("%s %s\n" % (code, reason)).encode("utf-8")
    sock.sendall(("HTTP/1.1 %s %s\r\n%sContent-Length: %d\r\nConnection: close\r\n\r\n"
                  % (code, reason, extra, len(body))).encode("ascii") + body)


def parse_host_port(authority, default_port):
    authority = authority.strip()
    if authority.startswith("["):
        host, _, tail = authority[1:].partition("]")
        port = default_port
        if tail.startswith(":"):
            port = int(tail[1:])
        return host, port
    if ":" in authority:
        host, raw_port = authority.rsplit(":", 1)
        return host, int(raw_port)
    return authority, default_port


def handle_http_proxy(client, expected, bind_port, client_addr):
    request_line, headers, rest = recv_http_head(client)
    route_user = check_basic_auth(headers, expected)
    if not route_user:
        http_error(client, 407, "Proxy Authentication Required",
                   {"Proxy-Authenticate": "Basic realm=\"PrivateVPN\""})
        raise OSError("http proxy auth failed")
    parts = request_line.split()
    if len(parts) != 3:
        http_error(client, 400, "Bad Request")
        raise OSError("bad http request line")
    method, target, version = parts
    method_upper = method.upper()
    if method_upper == "CONNECT":
        host, port = parse_host_port(target, 443)
        up = connect_upstream(host, port, route_user)
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        acct = [0, 0]
        try:
            relay(client, up, acct)
        finally:
            log_conn(bind_port, expected, client_addr, host, port, acct[0], acct[1])
        return

    # Plain HTTP proxy requests use absolute-form URLs. Convert to origin-form
    # before forwarding after the upstream SOCKS connection is established.
    if target.startswith("http://"):
        without_scheme = target[7:]
        authority, slash, path = without_scheme.partition("/")
        host, port = parse_host_port(authority, 80)
        origin = "/" + path if slash else "/"
    else:
        host_header = headers.get("host")
        if not host_header:
            http_error(client, 400, "Bad Request")
            raise OSError("missing host header")
        host, port = parse_host_port(host_header, 80)
        origin = target
    up = connect_upstream(host, port, route_user)
    filtered = []
    for name, value in headers.items():
        if name in ("proxy-authorization", "proxy-connection"):
            continue
        filtered.append("%s: %s" % (name, value))
    outbound = ("%s %s %s\r\n%s\r\n\r\n" %
                (method, origin, version, "\r\n".join(filtered))).encode("iso-8859-1") + rest
    acct = [len(outbound), 0]
    up.sendall(outbound)
    try:
        relay(client, up, acct)
    finally:
        log_conn(bind_port, expected, client_addr, host, port, acct[0], acct[1])


def open_upstream_socks(route_user=None):
    up = socket.create_connection((UPSTREAM_HOST, UPSTREAM_PORT), timeout=12)
    route_user = route_user or "private-default"
    up.sendall(b"\x05\x01\x02")
    if recv_exact(up, 2) != b"\x05\x02":
        raise OSError("upstream socks handshake failed")
    user_b = route_user.encode()
    pass_b = UPSTREAM_AUTH_PASSWORD.encode()
    if len(user_b) > 255 or len(pass_b) > 255:
        raise OSError("upstream auth field too long")
    up.sendall(b"\x01" + bytes([len(user_b)]) + user_b + bytes([len(pass_b)]) + pass_b)
    if recv_exact(up, 2) != b"\x01\x00":
        raise OSError("upstream socks auth failed")
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


def connect_upstream(host, port, route_user=None):
    up = open_upstream_socks(route_user)
    socks_request(up, 1, host, port)
    return up


def relay(client, upstream, acct):
    """Pump bytes both ways. acct is a mutable [up, down] counter so the caller
    can log totals even when the connection ends by exception."""
    socks = [client, upstream]
    try:
        while True:
            readable, _, _ = select.select(socks, [], [], 60)
            if not readable:
                continue
            for s in readable:
                data = s.recv(BUFFER)
                if not data:
                    return
                if s is client:
                    upstream.sendall(data)
                    acct[0] += len(data)          # client→remote = upload
                else:
                    client.sendall(data)
                    acct[1] += len(data)          # remote→client = download
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


def handle_udp_associate(client, udp_sock, client_addr, assocs, upstreams, lock, bind_port, route_user):
    up = open_upstream_socks(route_user)
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
        first = client.recv(1, socket.MSG_PEEK)
        if first and first != b"\x05":
            handle_http_proxy(client, expected, bind_port, client_addr)
            return
        route_user = auth_client(client, expected)
        req = recv_exact(client, 4)
        if req[0] != 5:
            raise OSError("bad socks version")
        host = read_addr(client, req[3])
        port = struct.unpack("!H", recv_exact(client, 2))[0]
        if req[1] == 1:
            up = connect_upstream(host, port, route_user)
            client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            acct = [0, 0]
            try:
                relay(client, up, acct)
            finally:
                log_conn(bind_port, expected, client_addr, host, port, acct[0], acct[1])
        elif req[1] == 3:
            handle_udp_associate(client, udp_sock, client_addr, assocs, upstreams, lock, bind_port, route_user)
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
