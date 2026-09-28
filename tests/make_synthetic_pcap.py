#!/usr/bin/env python3
"""Write tests/synthetic_svr.pcap: hand-built SVR packets covering the TLVs and
edge cases the plugin handles (layouts from draft-menon-svr section 10).

Frames:
  1  UDP fwd metadata, IPv4 context, NOT encrypted, inner DNS query
  2  UDP same waypoint flow, no metadata (continuation)
  3  UDP reverse metadata on the same waypoint flow
  4  UDP fwd metadata, IPv6 context
  5  UDP false-positive marker (header length 12, no TLVs)
  6  UDP truncated metadata (payload length runs past the packet)
  7  UDP header TLVs + encrypted payload TLVs
  8  UDP control message: ICMP error location + drop reason, path metrics, health check
  9  UDP multicast group context + egress list
"""
import os
import socket
import struct
import time

COOKIE = bytes.fromhex("4C48DBC6DDF6670C")


def tlv(t, v=b""):
    return struct.pack(">HH", t, len(v)) + v


def svr(header_tlvs=b"", payload_tlvs=b"", header_len=None, payload_len=None):
    hl = 12 + len(header_tlvs) if header_len is None else header_len
    pl = len(payload_tlvs) if payload_len is None else payload_len
    return COOKIE + struct.pack(">HH", 0x1000 | hl, pl) + header_tlvs + payload_tlvs


def ctx4(t, src, dst, sport, dport, proto):
    return tlv(t, socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack(">HHB", sport, dport, proto))


def ctx6(t, src, dst, sport, dport, proto):
    return tlv(t, socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)
               + struct.pack(">HHB", sport, dport, proto))


def udp_frame(src, dst, sport, dport, payload):
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     socket.inet_aton(src), socket.inet_aton(dst)) + udp
    return b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00" + ip


DNS_QUERY = bytes.fromhex("12340100000100000000000003777777076578616d706c6503636f6d0000010001")
UUID = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
A, B = "10.0.0.1", "10.0.0.2"   # waypoint addresses

frames = [
    udp_frame(A, B, 16400, 16401, svr(tlv(16, b"\x00\x00\x00\x01"),
        ctx4(2, "192.168.1.10", "8.8.8.8", 40000, 53, 17) + tlv(7, b"blue") + tlv(10, b"dns-svc")
        + tlv(6, UUID) + tlv(35, b"DNS") + tlv(14, b"branch-router") + tlv(19, b"wan0")) + DNS_QUERY),
    udp_frame(A, B, 16400, 16401, DNS_QUERY),
    udp_frame(B, A, 16401, 16400, svr(tlv(16, b"\x00\x00\x00\x01"),
        ctx4(4, "8.8.8.8", "192.168.1.10", 53, 40000, 17) + tlv(7, b"blue") + tlv(18)) + DNS_QUERY),
    udp_frame(A, B, 16402, 16403, svr(b"", ctx6(3, "2001:db8::1", "2001:db8::2", 1234, 443, 6)
        + tlv(10, b"v6-svc") + tlv(11) + tlv(12) + tlv(25, socket.inet_aton("203.0.113.9"))) + b"\xde\xad"),
    udp_frame(A, B, 16404, 16405, svr() + b"payload that happened to start with the cookie"),
    udp_frame(A, B, 16406, 16407, svr(b"", b"", payload_len=500) + b"\x00" * 10),
    udp_frame(A, B, 16408, 16409, svr(tlv(16, b"\x00\x00\x00\x02"), payload_len=24)
        + bytes(range(0x80, 0x98)) + b"inner"),
    udp_frame(B, A, 16409, 16408, svr(tlv(20, socket.inet_aton("198.51.100.7")) + tlv(24, b"\x01")
        + tlv(26, bytes.fromhex("10000064200000c8800a")) + tlv(46, b"\x01"), tlv(42, struct.pack(">I", 30)))),
    udp_frame(A, B, 16410, 16411, svr(b"", tlv(50, b"\x04\x01" + socket.inet_aton("0.0.0.0")
        + socket.inet_aton("239.1.1.1") + b"\x11") + tlv(51, b"\x00\x02\x04lhr1\x04lhr2") + tlv(99, b"future"))),
]

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "synthetic_svr.pcap")
with open(out, "wb") as fh:
    fh.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    t0 = 1_700_000_000
    for i, f in enumerate(frames):
        fh.write(struct.pack("<IIII", t0 + i, 0, len(f), len(f)) + f)
print(f"wrote {out} ({len(frames)} frames)")
