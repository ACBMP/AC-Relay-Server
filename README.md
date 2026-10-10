# ac-relay-server

A small TURN-style UDP relay for **AC Relay**, the client patch that lets
Assassin's Creed multiplayer (Quazal PRUDP peer-to-peer) work between
players whose NATs can't reach each other directly.

## How it fits

1. Each player picks a relay server by hand in AC Relay's ini.
2. That player's patch (the "owner") sends `ALLOCATE` to the relay's control
   port from the game's own UDP socket. The relay reserves one public UDP
   port for it from the allocation pool.
3. The patch makes the game publish `prudp:/address=<relay_ip>;port=<alloc_port>`
   as one more station URL. Other players' games probe it like any other
   address.
4. Raw datagrams that peers send to the allocation port are wrapped as `RECV`
   and forwarded to the owner over the control port. The owner sends back with
   `SEND`, and the relay emits the payload to the peer **from the allocation
   port**.
5. The game's own probe race picks direct vs relayed per peer. No game logic
   changes.

The wire protocol is in [docs/PROTOCOL.md](docs/PROTOCOL.md). It is shared
with the client patch, so don't change it here alone.

**Firewall:** open UDP on the control port (default `21100`) and the whole
allocation range (default `40200-40999`). Each connected player uses one
allocation port.

## Build

Needs a C++20 compiler and CMake. No third-party dependencies.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

This produces `build/ac-relay`. The build also works on Windows (MSVC or
MinGW, linked against `ws2_32`) for players who want to self-host.

## Test

The end-to-end test needs Python 3 (stdlib only). It starts the binary on
localhost and checks allocate, idempotent re-allocate, wrong password,
bad version, RECV/SEND relaying, the 1488-byte payload limit, keepalive,
release, the per-IP cap, the rate limit, pool exhaustion and lease expiry.

```sh
ctest --test-dir build --output-on-failure
# or directly:
python3 tests/e2e_test.py build/ac-relay
```

## Run

```sh
./build/ac-relay --public-ip 203.0.113.5
```

| flag | default | meaning |
|------|---------|---------|
| `--public-ip <ipv4\|host>` | required | public address returned to owners in `ALLOCATED.relay_ip`. A hostname (e.g. `relay.example.org`) is resolved to its first IPv4 once at startup; restart after the address changes (dynamic DNS) |
| `--bind <ipv4>` | `0.0.0.0` | local address for the control and allocation sockets |
| `--control-port <port>` | `21100` | control port |
| `--port-range <lo-hi>` | `40200-40999` | allocation port pool |
| `--password <str>` | none | if set, `ALLOCATE` must carry it |
| `--lease <s>` | `60` | lease length; refreshed by ALLOCATE, KEEPALIVE and SEND |
| `--max-allocations <n>` | pool size | total allocation cap |
| `--max-per-ip <n>` | `4` | allocations per source IP |
| `--alloc-rate <n/s>` | `2` | new allocations per second per source IP (token bucket) |
| `--alloc-burst <n>` | `5` | token bucket size |
| `--config <file>` | | read `key=value` lines; keys are the flag names without `--`, `#` starts a comment |
| `--verbose` | off | log every relayed packet |

Flags are applied in order, so flags after `--config` override the file.
Both `--flag value` and `--flag=value` work.

Logs go to stdout: allocations created, refreshed, released and expired
(with owner address and port), denials, and a stats line every 60 s
(allocations, packets/bytes in and out, drops). SIGINT/SIGTERM shuts down
cleanly and prints final stats.

### Docker Compose

```sh
cp .env.example .env      # set AC_RELAY_PUBLIC_IP; optionally AC_RELAY_PASSWORD
docker compose up -d --build
docker compose logs -f
```

`docker-compose.yml` runs the relay with host networking, a read-only
filesystem and no capabilities. Every setting comes from `.env` (see
`.env.example`): public IP (required), password, control port, port range,
bind address, lease, per-IP cap. Open the control port and the port range
(UDP) in the host firewall.

### Docker

```sh
docker build -t ac-relay .
docker run -d --name ac-relay --restart unless-stopped --network host \
  ac-relay --public-ip 203.0.113.5
```

Use `--network host`. Publishing 800 UDP ports through Docker's proxy is
slow. Also, the relay must see the owners' real source addresses.

### systemd

`/etc/systemd/system/ac-relay.service`:

```ini
[Unit]
Description=AC Relay UDP relay
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/ac-relay --config /etc/ac-relay.conf
Restart=on-failure
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
```

`/etc/ac-relay.conf`:

```ini
public-ip=203.0.113.5
control-port=21100
port-range=40200-40999
# password=secret
```

Then run `systemctl enable --now ac-relay` and `journalctl -u ac-relay -f`.

## Interpretation notes

docs/PROTOCOL.md leaves these cases open. This server handles them as
follows:

- **Relay without a password.** Any password in `ALLOCATE` is accepted,
  including a non-empty one. A client that has a stale password in its ini
  still works.
- **Password check on refresh.** Every `ALLOCATE` is checked, including one
  that would refresh an existing allocation.
- **Per-IP cap hit.** The relay replies `DENIED reason=4` (rate limited), not 2.
  The cap is usually hit because stale allocations from an earlier session are
  still leased. "Retry later" is the right signal for that. Reason 2 means the
  whole pool (or `--max-allocations`) is used up.
- **Rate limiting.** Only `ALLOCATE`s that would create an allocation take a
  token. Password guesses take one too. Refreshes of an existing allocation are
  never rate limited.
- **Bad version.** Any datagram with the right magic and a different version
  gets `DENIED reason=3`, whatever its type. The nonce is echoed from bytes 6-9
  if present, otherwise 0. The reply header always carries version 1.
- **`KEEPALIVE_ACK` for an unknown owner.** `SEND` has no nonce, so the
  lease-0 ack for a `SEND` from an unknown address carries nonce 0. A
  `KEEPALIVE` from an unknown address echoes its nonce. Both are limited to one
  reply per second per address, and so is `DENIED` for bad versions and rate
  limits.
- **`KEEPALIVE_ACK` lease.** A keepalive refreshes the lease, so the ack
  reports the full lease length.
- **`RELEASE`** gets no reply.
- **`SEND` limits.** A `SEND` to `0.0.0.0` or port 0 is dropped. No other
  destination filter is applied. The 1500-byte limit is enforced only on
  `RECV`, as the spec says.
- **Empty datagrams** on an allocation port are relayed as a `RECV` with an
  empty payload.
