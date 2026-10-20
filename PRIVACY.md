# Privacy model and encrypted-exit design

## Implemented data minimization

The portal retains authorization credentials, device labels/types, approval
state, recent activity markers and per-authorization hourly/daily byte totals.
Labels can be aliases; legal names are unnecessary.

It no longer implements destination auditing, keyword classification, client IP
history or HTTP request history. Existing IP fields in `keys.json` are removed
at startup. The built-in HTTP request handler does not log paths, tokens or IPs.
External web servers must independently disable or sanitize their access logs.

Both proxy services write `state/traffic/user-<port>.log`, containing only
`<uploaded bytes> <downloaded bytes>` per line. Shared Shadowsocks uses
`shared-8388.log`. Filenames no longer contain authorization credentials.
Shadowsocks output passes through `traffic_filter.py` before storage; unrecognized
lines, addresses, errors and credentials are discarded. New users use the same
filter as container startup. Private SOCKS writes counts directly.
Mihomo uses `log-level: silent`; the three project proxy containers use Docker's
`none` logging driver. Counts remain available through their volume mounts.

The deprecated `gateway/` OpenVPN experiment is not part of the active deployment
or this migration. Do not run it under the privacy guarantees described here.

The server samples counts and stores totals in SQLite. TCP counts still arrive
when connections close. Private SOCKS UDP is not yet metered; Shadowsocks UDP is.
SSH fallback attribution uses only a transient IP-to-authorization heartbeat
mapping that expires after 120 seconds; it is never persisted or returned by APIs.
Shared/NAT SSH attribution remains approximate. Operational activity timestamps
and traffic volumes are still metadata, so this is minimization, not anonymity.

Historical project logs are not automatically erased by a code update.
After stopping the old Web process and proxy writers, run
`python3 ops/privacy_cleanup.py`. It removes only recognized files in the two
legacy `state/logs` directories, clears `server.log`, and strips old IP fields
from `keys.json`. It preserves credentials and `traffic.sqlite3`.
It does not inspect or modify OS, SSH, security-agent or Docker historical logs.
Backups, snapshots and copies already collected elsewhere are outside its scope.

## Required network constraint

Devices have LAN connectivity to the campus server but cannot reach the Internet
directly. The campus server must remain the physical transit point. End-to-end
encryption does not require a physically direct client-to-exit connection.

Current path:

```text
client -> campus proxy decodes destination -> optional upstream -> website
```

The private SOCKS/HTTP listener also leaves the client-to-campus proxy leg
unencrypted; its protocol is not a substitute for an encrypted tunnel.

Proposed path (not implemented by this privacy cleanup):

```text
client encrypts destination + traffic
    -> campus fixed TCP/UDP forwarding port (opaque ciphertext)
    -> independent exit decrypts -> website
```

## Recommended first implementation

Use a maintained layer-4 forwarder with fixed upstream mappings on the campus
server. It forwards TCP/UDP without terminating the inner proxy encryption.
NGINX stream supports TCP and UDP forwarding:
https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html

Reuse Shadowsocks AEAD as the inner client-to-exit protocol where supported.
The client's server address is the campus IP and assigned forwarding port, but
the cipher/password belong to the independent exit. The campus forwarder needs
only that exit's IP/port, never the password. Different ports can map to different
exits, retaining node selection without decoding destination addresses on campus.
Mihomo documents Shadowsocks TCP/UDP and supported ciphers:
https://wiki.metacubex.one/en/config/proxies/ss/
Protocol reference: https://shadowsocks.org/doc/aead.html

Prefer a maintained protocol/server implementation, with high-entropy credentials,
replay protection and a cipher supported by the actual Shadowrocket and Clash
versions. iOS TCP/UDP compatibility must be tested on-device before rollout;
configuration generation tests alone are insufficient. A TLS-authenticated proxy
is another option: certificate verification must remain enabled, TLS must
terminate at the independent exit, and the campus relay must not terminate it.

## DNS, bootstrap and fail-closed routing

- Pin a reachable exit IP in the campus forwarder to avoid circular bootstrap.
- Client proxy connection addresses remain campus IPs, reachable before a tunnel.
- Send Internet DNS through the encrypted exit (including DoH transport).
  Fake-IP alone does not guarantee DNS privacy.
- Mihomo's DNS routing settings and `proxy-server-nameserver` require coordinated
  configuration: https://wiki.metacubex.one/en/config/dns/
- Bootstrap the exit credentials on a trusted device, or retrieve them through
  HTTPS terminating at the independent exit via the relay. Do not store exit
  passwords in campus-generated subscriptions or serve them over campus HTTP.
- Keep campus-only destinations such as `gpu1.bucea.edu.cn` in a clearly separate
  route. Their campus access/DNS remains observable; do not claim privacy there.
- Remove Internet `GEOIP,CN`/Tencent -> campus-direct exceptions in the new
  encrypted profile. Do not silently fall back to the old direct outlet on exit
  failure. Cover UDP, IPv6 and applications bypassing the proxy; unsupported
  transport must fail closed.

## Authorization and accounting changes

The independent exit validates per-user credentials. Campus control can maintain
port-to-authorization mappings and count ciphertext bytes without target logging,
but port assignment alone is not authentication. Revocation must disable the
exit credential and close relevant relay sessions. Giving users direct access to
the exit's master/provider subscription would undermine per-user revocation.
Ciphertext counters include protocol overhead and will differ from old payload
totals; show a consistent definition after migration.

The present upstream subscription may or may not permit safe individual-client
credentials. An independent exit with delegated per-user management is the
clearest design; confirm ownership, allowed transit, capacity and UDP support
before selecting a concrete implementation.

## What this can and cannot protect

Assuming passive campus observation and uncompromised clients/exits, the campus
server can see client/exit IPs, ports, timing, size and availability, but should
not see final Internet domains, inner URLs, DNS questions or payloads.
Traffic analysis can still infer activity. The independent exit can observe
destinations; HTTPS continues to protect application contents from that exit.
This moves the trust boundary, rather than eliminating it.

Not being able to edit project files does not by itself exclude packet capture,
process inspection, snapshots or credential reads. Keeping exit secrets and
plaintext destinations off campus is therefore necessary even under the user's
passive-log threat model. Active modification, compromised endpoints, traffic
correlation and copies previously collected by administrators are not solved by
turning off application logging.
