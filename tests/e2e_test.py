#!/usr/bin/env python3
"""End-to-end test for ac-relay. Usage: e2e_test.py <path-to-ac-relay>"""
import os
import random
import socket
import struct
import subprocess
import sys
import time

MAGIC = b"ACRL"
ALLOCATE, ALLOCATED, DENIED, KEEPALIVE, KEEPALIVE_ACK, SEND, RECV, RELEASE = range(1, 9)
LOCAL = "127.0.0.1"
LOCAL_U32 = struct.unpack("!I", socket.inet_aton(LOCAL))[0]


def hdr(t, version=1):
    return MAGIC + bytes([version, t])


def allocate(nonce, pw=b""):
    return hdr(ALLOCATE) + struct.pack("!IB", nonce, len(pw)) + pw


def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((LOCAL, 0))
    s.settimeout(2.0)
    return s


def free_range(n):
    """Find n consecutive free UDP ports on localhost."""
    for _ in range(200):
        base = random.randint(42000, 60000)
        socks = []
        try:
            for p in range(base, base + n):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                socks.append(s)
                s.bind((LOCAL, p))
            return base
        except OSError:
            pass
        finally:
            for s in socks:
                s.close()
    raise RuntimeError("no free port range")


class Relay:
    def __init__(self, binary, pool, *extra):
        base = free_range(pool + 1)
        self.ctrl = (LOCAL, base)
        self.lo, self.hi = base + 1, base + pool
        args = [binary, "--bind", LOCAL, "--public-ip", LOCAL, "--control-port", str(base),
                "--port-range", f"{self.lo}-{self.hi}", "--verbose", *extra]
        self.proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True)
        time.sleep(0.3)
        assert self.proc.poll() is None, self.proc.stdout.read()

    def stop(self):
        self.proc.terminate()
        out, _ = self.proc.communicate(timeout=5)
        assert self.proc.returncode == 0, f"exit code {self.proc.returncode}"
        assert "shutting down" in out
        return out

    def rpc(self, sock, data):
        sock.sendto(data, self.ctrl)
        return parse(sock.recvfrom(2048)[0])


def parse(d):
    assert d[:5] == MAGIC + b"\x01", d
    t, p = d[5], d[6:]
    if t == ALLOCATED:
        f = struct.unpack("!IIHIHH", p)
        return t, dict(nonce=f[0], relay_ip=f[1], port=f[2], obs_ip=f[3], obs_port=f[4], lease=f[5])
    if t == DENIED:
        nonce, reason = struct.unpack("!IB", p)
        return t, dict(nonce=nonce, reason=reason)
    if t == KEEPALIVE_ACK:
        nonce, lease = struct.unpack("!IH", p)
        return t, dict(nonce=nonce, lease=lease)
    if t == RECV:
        ip, port = struct.unpack("!IH", p[:6])
        return t, dict(ip=ip, port=port, payload=p[6:])
    raise AssertionError(f"unexpected type {t}")


def expect(got, t, **fields):
    assert got[0] == t, f"expected type {t}, got {got}"
    for k, v in fields.items():
        assert got[1][k] == v, f"{k}: expected {v}, got {got[1][k]} in {got}"
    return got[1]


def silent(sock, wait=0.3):
    sock.settimeout(wait)
    try:
        d = sock.recvfrom(2048)[0]
        raise AssertionError(f"unexpected datagram {d!r}")
    except socket.timeout:
        pass
    finally:
        sock.settimeout(2.0)


def test_main(binary):
    r = Relay(binary, 8, "--password", "hunter2", "--max-per-ip", "3", "--alloc-burst", "50")
    try:
        owner, peer = udp(), udp()
        oport, pport = owner.getsockname()[1], peer.getsockname()[1]

        a = expect(r.rpc(owner, allocate(0x11223344, b"hunter2")), ALLOCATED, nonce=0x11223344,
                   relay_ip=LOCAL_U32, obs_ip=LOCAL_U32, obs_port=oport, lease=60)
        assert r.lo <= a["port"] <= r.hi
        alloc = (LOCAL, a["port"])
        print(f"ok allocate -> port {a['port']}")

        expect(r.rpc(owner, allocate(7, b"hunter2")), ALLOCATED, nonce=7, port=a["port"])
        print("ok idempotent re-allocate")

        expect(r.rpc(udp(), allocate(9, b"wrong")), DENIED, nonce=9, reason=1)
        expect(r.rpc(udp(), allocate(10)), DENIED, nonce=10, reason=1)
        print("ok wrong/missing password denied")

        expect(r.rpc(udp(), hdr(ALLOCATE, 2) + struct.pack("!IB", 12, 0)), DENIED, nonce=12,
               reason=3)
        print("ok bad version denied")

        peer.sendto(b"\x00prudp-syn", alloc)
        expect(parse(owner.recvfrom(2048)[0]), RECV, ip=LOCAL_U32, port=pport,
               payload=b"\x00prudp-syn")
        peer.sendto(b"", alloc)
        expect(parse(owner.recvfrom(2048)[0]), RECV, port=pport, payload=b"")
        print("ok peer datagram -> RECV")

        peer.sendto(b"x" * 1488, alloc)
        expect(parse(owner.recvfrom(2048)[0]), RECV, payload=b"x" * 1488)
        peer.sendto(b"x" * 1489, alloc)
        silent(owner)
        print("ok 1488-byte payload relayed, 1489 dropped")

        owner.sendto(hdr(SEND) + struct.pack("!IH", LOCAL_U32, pport) + b"reply", r.ctrl)
        data, src = peer.recvfrom(2048)
        assert data == b"reply" and src == alloc, (data, src)
        print("ok SEND -> peer from alloc port")

        expect(r.rpc(owner, hdr(KEEPALIVE) + struct.pack("!I", 0xABCD)), KEEPALIVE_ACK,
               nonce=0xABCD, lease=60)
        print("ok keepalive ack")

        # Per-IP cap: owner holds 1, two more fit, the 4th from this IP is denied.
        extra = [udp(), udp()]
        for i, s in enumerate(extra):
            expect(r.rpc(s, allocate(100 + i, b"hunter2")), ALLOCATED)
        expect(r.rpc(udp(), allocate(200, b"hunter2")), DENIED, nonce=200, reason=4)
        print("ok per-ip cap")

        owner.sendto(hdr(RELEASE), r.ctrl)
        time.sleep(0.1)
        expect(r.rpc(owner, hdr(KEEPALIVE) + struct.pack("!I", 5)), KEEPALIVE_ACK, nonce=5, lease=0)
        time.sleep(1.1)  # past the 1 s unknown-owner reply limit
        owner.sendto(hdr(SEND) + struct.pack("!IH", LOCAL_U32, pport) + b"late", r.ctrl)
        expect(parse(owner.recvfrom(2048)[0]), KEEPALIVE_ACK, nonce=0, lease=0)
        silent(peer)
        peer.sendto(b"after-release", alloc)
        silent(owner)
        # The freed slot under the per-IP cap is usable again.
        expect(r.rpc(udp(), allocate(300, b"hunter2")), ALLOCATED, nonce=300)
        print("ok release frees")

        owner.sendto(b"garbage", r.ctrl)
        owner.sendto(hdr(0x7F), r.ctrl)
        silent(owner)
        print("ok garbage dropped")
    finally:
        out = r.stop()
    assert "drops oversize 1" in out, out
    print("ok clean shutdown")


def test_pool_and_lease(binary):
    r = Relay(binary, 1, "--lease", "2")
    try:
        a, b, c = udp(), udp(), udp()
        got = expect(r.rpc(a, allocate(1)), ALLOCATED, lease=2)
        expect(r.rpc(b, allocate(2)), DENIED, reason=2)
        a.sendto(hdr(RELEASE), r.ctrl)
        time.sleep(0.1)
        expect(r.rpc(b, allocate(3)), ALLOCATED, port=got["port"])
        print("ok pool exhausted, released port reused")

        expect(r.rpc(b, hdr(KEEPALIVE) + struct.pack("!I", 4)), KEEPALIVE_ACK, lease=2)
        time.sleep(3.0)
        expect(r.rpc(b, hdr(KEEPALIVE) + struct.pack("!I", 5)), KEEPALIVE_ACK, nonce=5, lease=0)
        expect(r.rpc(c, allocate(6)), ALLOCATED, port=got["port"])
        print("ok lease expiry returns port to pool")
    finally:
        out = r.stop()
    assert "allocation expired" in out, out


def test_rate_limit(binary):
    r = Relay(binary, 8, "--alloc-burst", "2", "--alloc-rate", "0.01")
    try:
        s1 = udp()
        expect(r.rpc(s1, allocate(1)), ALLOCATED)
        expect(r.rpc(udp(), allocate(2)), ALLOCATED)
        expect(r.rpc(udp(), allocate(3)), DENIED, nonce=3, reason=4)
        expect(r.rpc(s1, allocate(4)), ALLOCATED, nonce=4)  # refresh is not rate limited
        print("ok allocate rate limit")
    finally:
        r.stop()


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(__file__), "..", "build", "ac-relay")
    test_main(binary)
    test_pool_and_lease(binary)
    test_rate_limit(binary)
    print("ALL PASSED")


if __name__ == "__main__":
    main()
