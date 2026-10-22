#!/usr/bin/env python3
"""Generate a deterministic Ethernet PCAP covering the analyzer's validation protocols.

No third-party packet library is required. The frames include valid IPv4, IPv6,
UDP and TCP checksums so a standard Wireshark/TShark installation can dissect it.
"""
from __future__ import annotations

import ipaddress
import struct
import time
from pathlib import Path

BASE_EPOCH = 1760250000.123  # deterministic; rendered in IST by the analyzer
CLIENT_MAC = "00:11:22:33:44:55"
AC_MAC = "66:77:88:99:aa:bb"
SERVER_MAC = "02:00:00:00:00:01"
LAN_MAC = "02:00:00:00:00:10"


def mac(value: str) -> bytes:
    return bytes.fromhex(value.replace(":", ""))


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data)//2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def ethernet(dst: str, src: str, ethertype: int, payload: bytes, vlan: int | None = None) -> bytes:
    if vlan is None:
        return mac(dst) + mac(src) + struct.pack("!H", ethertype) + payload
    return mac(dst) + mac(src) + struct.pack("!HHH", 0x8100, vlan & 0x0FFF, ethertype) + payload


def ipv4_packet(src: str, dst: str, proto: int, payload: bytes, ident: int) -> bytes:
    src_b, dst_b = ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed
    total = 20 + len(payload)
    base = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident, 0x4000, 64, proto, 0, src_b, dst_b)
    return base[:10] + struct.pack("!H", checksum(base)) + base[12:] + payload


def ipv6_packet(src: str, dst: str, next_header: int, payload: bytes) -> bytes:
    return struct.pack(
        "!IHBB16s16s", 6 << 28, len(payload), next_header, 64,
        ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed,
    ) + payload


def udp_segment(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes, ipv6: bool = False) -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", sport, dport, length, 0)
    if ipv6:
        pseudo = ipaddress.ip_address(src_ip).packed + ipaddress.ip_address(dst_ip).packed + struct.pack("!I3xB", length, 17)
        csum = checksum(pseudo + header + payload) or 0xFFFF
        header = struct.pack("!HHHH", sport, dport, length, csum)
    return header + payload


def tcp_segment(src_ip: str, dst_ip: str, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    offset_flags = (5 << 12) | flags
    header = struct.pack("!HHIIHHHH", sport, dport, seq, ack, offset_flags, 65535, 0, 0)
    pseudo = ipaddress.ip_address(src_ip).packed + ipaddress.ip_address(dst_ip).packed + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    csum = checksum(pseudo + header + payload)
    return struct.pack("!HHIIHHHH", sport, dport, seq, ack, offset_flags, 65535, csum, 0) + payload


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(part)]) + part.encode() for part in name.rstrip(".").split(".")) + b"\x00"


def dns_query(txid: int, name: str, qtype: int) -> bytes:
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", qtype, 1)


def dns_response(txid: int, name: str, qtype: int, answer: str | None = None, rcode: int = 0) -> bytes:
    flags = 0x8180 | (rcode & 0xF)
    question = dns_name(name) + struct.pack("!HH", qtype, 1)
    if answer is None:
        return struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0) + question
    rdata = ipaddress.ip_address(answer).packed
    rr = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(rdata)) + rdata
    return struct.pack("!HHHHHH", txid, flags, 1, 1, 0, 0) + question + rr


def dhcp4_message(op: int, xid: int, client_mac: str, yiaddr: str, giaddr: str, options: list[tuple[int, bytes]]) -> bytes:
    chaddr = mac(client_mac) + b"\x00" * 10
    fixed = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s", op, 1, 6, 0, xid, 0, 0x8000,
        b"\x00" * 4, ipaddress.ip_address(yiaddr).packed,
        b"\x00" * 4, ipaddress.ip_address(giaddr).packed,
        chaddr, b"\x00" * 64, b"\x00" * 128,
    )
    encoded = b"".join(bytes([code, len(value)]) + value for code, value in options)
    return fixed + b"\x63\x82\x53\x63" + encoded + b"\xff"


def dhcp6_option(code: int, value: bytes) -> bytes:
    return struct.pack("!HH", code, len(value)) + value


def pppoe_discovery(code: int, session: int, tags: list[tuple[int, bytes]]) -> bytes:
    body = b"".join(struct.pack("!HH", kind, len(value)) + value for kind, value in tags)
    return struct.pack("!BBHH", 0x11, code, session, len(body)) + body


def pppoe_session(session: int, protocol: int, body: bytes) -> bytes:
    payload = struct.pack("!H", protocol) + body
    return struct.pack("!BBHH", 0x11, 0, session, len(payload)) + payload


def control(code: int, ident: int, data: bytes = b"") -> bytes:
    return struct.pack("!BBH", code, ident, 4 + len(data)) + data


def add_ip4(frames: list[bytes], src_mac: str, dst_mac: str, src: str, dst: str, sport: int, dport: int, payload: bytes, ident: int, vlan: int | None = None):
    udp = udp_segment(src, dst, sport, dport, payload)
    frames.append(ethernet(dst_mac, src_mac, 0x0800, ipv4_packet(src, dst, 17, udp, ident), vlan))


def add_ip6(frames: list[bytes], src_mac: str, dst_mac: str, src: str, dst: str, sport: int, dport: int, payload: bytes):
    udp = udp_segment(src, dst, sport, dport, payload, ipv6=True)
    frames.append(ethernet(dst_mac, src_mac, 0x86DD, ipv6_packet(src, dst, 17, udp)))


def build_frames() -> list[bytes]:
    f: list[bytes] = []
    service, hostuniq = b"internet", b"\xaa\xbb\xcc\xdd"
    tags_client = [(0x0101, service), (0x0103, hostuniq)]
    tags_ac = [(0x0101, service), (0x0102, b"Airtel-BNG-01"), (0x0103, hostuniq), (0x0104, b"cookie01")]
    f += [
        ethernet("ff:ff:ff:ff:ff:ff", CLIENT_MAC, 0x8863, pppoe_discovery(0x09, 0, tags_client), 100),
        ethernet(CLIENT_MAC, AC_MAC, 0x8863, pppoe_discovery(0x07, 0, tags_ac), 100),
        ethernet(AC_MAC, CLIENT_MAC, 0x8863, pppoe_discovery(0x19, 0, tags_client + [(0x0104, b"cookie01")]), 100),
        ethernet(CLIENT_MAC, AC_MAC, 0x8863, pppoe_discovery(0x65, 0x0010, tags_ac), 100),
    ]
    lcp_options = b"\x01\x04\x05\xd4" + b"\x05\x06\x12\x34\x56\x78"
    f += [
        ethernet(AC_MAC, CLIENT_MAC, 0x8864, pppoe_session(0x10, 0xC021, control(1, 10, lcp_options)), 100),
        ethernet(CLIENT_MAC, AC_MAC, 0x8864, pppoe_session(0x10, 0xC021, control(2, 10, lcp_options)), 100),
    ]
    peer, password = b"user@airtel", b"secret"
    pap_req = bytes([len(peer)]) + peer + bytes([len(password)]) + password
    f += [
        ethernet(AC_MAC, CLIENT_MAC, 0x8864, pppoe_session(0x10, 0xC023, control(1, 20, pap_req)), 100),
        ethernet(CLIENT_MAC, AC_MAC, 0x8864, pppoe_session(0x10, 0xC023, control(2, 20, bytes([7]) + b"Welcome")), 100),
    ]
    ipcp_req = b"\x03\x06" + ipaddress.ip_address("0.0.0.0").packed + b"\x81\x06" + ipaddress.ip_address("0.0.0.0").packed
    ipcp_ack = b"\x03\x06" + ipaddress.ip_address("100.64.1.10").packed + b"\x81\x06" + ipaddress.ip_address("1.1.1.1").packed + b"\x83\x06" + ipaddress.ip_address("8.8.8.8").packed
    f += [
        ethernet(AC_MAC, CLIENT_MAC, 0x8864, pppoe_session(0x10, 0x8021, control(1, 30, ipcp_req)), 100),
        ethernet(CLIENT_MAC, AC_MAC, 0x8864, pppoe_session(0x10, 0x8021, control(2, 30, ipcp_ack)), 100),
    ]
    iid = bytes.fromhex("021122fffe334455")
    ipv6cp = b"\x01\x0a" + iid
    f += [
        ethernet(AC_MAC, CLIENT_MAC, 0x8864, pppoe_session(0x10, 0x8057, control(1, 40, ipv6cp)), 100),
        ethernet(CLIENT_MAC, AC_MAC, 0x8864, pppoe_session(0x10, 0x8057, control(2, 40, ipv6cp)), 100),
        ethernet(AC_MAC, CLIENT_MAC, 0x8864, pppoe_session(0x10, 0xC021, control(9, 244, bytes.fromhex("12345678") + b"ping")), 100),
        ethernet(CLIENT_MAC, AC_MAC, 0x8864, pppoe_session(0x10, 0xC021, control(10, 244, bytes.fromhex("12345678") + b"ping")), 100),
        ethernet(AC_MAC, CLIENT_MAC, 0x8864, pppoe_session(0x10, 0xC021, control(5, 55, b"admin reset")), 100),
        ethernet(CLIENT_MAC, AC_MAC, 0x8863, pppoe_discovery(0xA7, 0x10, [(0x0103, hostuniq)]), 100),
    ]

    xid = 0x12345678
    common_client = [(53, b"\x01"), (12, b"CPE-VALIDATION"), (60, b"Airtel-CPE"), (55, bytes([1, 3, 6, 15, 51, 54, 58, 59])), (50, ipaddress.ip_address("192.168.1.100").packed), (61, b"\x01" + mac(LAN_MAC))]
    server_opts = [(54, ipaddress.ip_address("192.168.1.1").packed), (1, ipaddress.ip_address("255.255.255.0").packed), (3, ipaddress.ip_address("192.168.1.1").packed), (6, ipaddress.ip_address("1.1.1.1").packed + ipaddress.ip_address("8.8.8.8").packed), (15, b"home.airtel"), (51, struct.pack("!I", 86400)), (58, struct.pack("!I", 43200)), (59, struct.pack("!I", 75600))]
    add_ip4(f, LAN_MAC, "ff:ff:ff:ff:ff:ff", "0.0.0.0", "255.255.255.255", 68, 67, dhcp4_message(1, xid, LAN_MAC, "0.0.0.0", "0.0.0.0", common_client), 100, 200)
    add_ip4(f, SERVER_MAC, "ff:ff:ff:ff:ff:ff", "192.168.1.1", "255.255.255.255", 67, 68, dhcp4_message(2, xid, LAN_MAC, "192.168.1.100", "0.0.0.0", [(53, b"\x02")] + server_opts), 101, 200)
    add_ip4(f, LAN_MAC, "ff:ff:ff:ff:ff:ff", "0.0.0.0", "255.255.255.255", 68, 67, dhcp4_message(1, xid, LAN_MAC, "0.0.0.0", "0.0.0.0", [(53, b"\x03")] + common_client[1:]), 102, 200)
    add_ip4(f, SERVER_MAC, "ff:ff:ff:ff:ff:ff", "192.168.1.1", "255.255.255.255", 67, 68, dhcp4_message(2, xid, LAN_MAC, "192.168.1.100", "0.0.0.0", [(53, b"\x05")] + server_opts), 103, 200)

    duid_c = struct.pack("!HHI", 1, 1, 123456) + mac(LAN_MAC)
    duid_s = struct.pack("!HHI", 1, 1, 123000) + mac(SERVER_MAC)
    txid = b"\x01\x02\x03"
    iaid = b"\x00\x00\x00\x01"
    iaaddr = dhcp6_option(5, ipaddress.ip_address("2001:db8:100::10").packed + struct.pack("!II", 3600, 7200))
    iana = dhcp6_option(3, iaid + struct.pack("!II", 1800, 2700) + iaaddr)
    prefix = dhcp6_option(26, struct.pack("!II", 3600, 7200) + b"\x38" + ipaddress.ip_address("2001:db8:200::").packed)
    iapd = dhcp6_option(25, iaid + struct.pack("!II", 1800, 2700) + prefix)
    d6base_c = dhcp6_option(1, duid_c)
    d6base_s = dhcp6_option(1, duid_c) + dhcp6_option(2, duid_s)
    add_ip6(f, LAN_MAC, "33:33:00:01:00:02", "fe80::10", "ff02::1:2", 546, 547, b"\x01" + txid + d6base_c)
    add_ip6(f, SERVER_MAC, LAN_MAC, "fe80::1", "fe80::10", 547, 546, b"\x02" + txid + d6base_s + iana + iapd)
    add_ip6(f, LAN_MAC, SERVER_MAC, "fe80::10", "fe80::1", 546, 547, b"\x03" + txid + d6base_s + iana + iapd)
    add_ip6(f, SERVER_MAC, LAN_MAC, "fe80::1", "fe80::10", 547, 546, b"\x07" + txid + d6base_s + iana + iapd + dhcp6_option(23, ipaddress.ip_address("2001:4860:4860::8888").packed))

    client_ip, resolver = "192.168.1.100", "192.168.1.1"
    dns_cases = [
        (0x1001, "tms.airtelbroadband.in", 1, "203.0.113.80", 0),
        (0x1002, "tms.airtelbroadband.in", 28, "2001:db8::80", 0),
        (0x1003, "broken.example", 1, None, 3),
        (0x1004, "broken.example", 28, None, 2),
    ]
    ident = 200
    for tx, name, qtype, answer, rcode in dns_cases:
        add_ip4(f, LAN_MAC, SERVER_MAC, client_ip, resolver, 53000 + (tx & 0xF), 53, dns_query(tx, name, qtype), ident); ident += 1
        add_ip4(f, SERVER_MAC, LAN_MAC, resolver, client_ip, 53, 53000 + (tx & 0xF), dns_response(tx, name, qtype, answer, rcode), ident); ident += 1
    add_ip4(f, LAN_MAC, "01:00:5e:00:00:fc", client_ip, "224.0.0.252", 5355, 5355, dns_query(0x2001, "gateway", 1), ident); ident += 1
    add_ip4(f, SERVER_MAC, LAN_MAC, resolver, client_ip, 5355, 5355, dns_response(0x2001, "gateway", 1, "192.168.1.1"), ident); ident += 1
    add_ip4(f, LAN_MAC, "01:00:5e:00:00:fb", client_ip, "224.0.0.251", 5353, 5353, dns_query(0, "cpe.local", 1), ident); ident += 1
    add_ip4(f, LAN_MAC, "01:00:5e:00:00:fb", client_ip, "224.0.0.251", 5353, 5353, dns_response(0, "cpe.local", 1, client_ip), ident); ident += 1

    server_ip, cport, sport = "203.0.113.80", 40000, 7547
    cseq, sseq = 1000, 5000
    def add_tcp(src_mac: str, dst_mac: str, src: str, dst: str, sp: int, dp: int, seq: int, ack: int, flags: int, data: bytes = b""):
        nonlocal ident
        seg = tcp_segment(src, dst, sp, dp, seq, ack, flags, data)
        f.append(ethernet(dst_mac, src_mac, 0x0800, ipv4_packet(src, dst, 6, seg, ident))); ident += 1
    add_tcp(LAN_MAC, SERVER_MAC, client_ip, server_ip, cport, sport, cseq, 0, 0x02)
    add_tcp(SERVER_MAC, LAN_MAC, server_ip, client_ip, sport, cport, sseq, cseq + 1, 0x12)
    add_tcp(LAN_MAC, SERVER_MAC, client_ip, server_ip, cport, sport, cseq + 1, sseq + 1, 0x10)
    body = b'''<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><soap:Body><cwmp:Inform><DeviceId><Manufacturer>Airtel</Manufacturer><OUI>001122</OUI><ProductClass>CPE</ProductClass><SerialNumber>VAL123</SerialNumber></DeviceId><Event><EventStruct><EventCode>1 BOOT</EventCode><CommandKey>validation-reboot</CommandKey></EventStruct></Event><ParameterList><ParameterValueStruct><Name>Device.DeviceInfo.SoftwareVersion</Name><Value>1.2.3</Value></ParameterValueStruct></ParameterList></cwmp:Inform></soap:Body></soap:Envelope>'''
    request = b"POST /acs HTTP/1.1\r\nHost: tms.airtelbroadband.in\r\nContent-Type: text/xml; charset=utf-8\r\nSOAPAction: \"Inform\"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    add_tcp(LAN_MAC, SERVER_MAC, client_ip, server_ip, cport, sport, cseq + 1, sseq + 1, 0x18, request)
    cseq += 1 + len(request)
    response_body = b'<soap:Body xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><cwmp:InformResponse><MaxEnvelopes>1</MaxEnvelopes></cwmp:InformResponse></soap:Body>'
    response = b"HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: " + str(len(response_body)).encode() + b"\r\n\r\n" + response_body
    add_tcp(SERVER_MAC, LAN_MAC, server_ip, client_ip, sport, cport, sseq + 1, cseq, 0x18, response)
    # Intentional retransmission of the POST segment for TCP anomaly validation.
    add_tcp(LAN_MAC, SERVER_MAC, client_ip, server_ip, cport, sport, cseq - len(request), sseq + 1, 0x18, request)
    return f


def write_pcap(path: Path, frames: list[bytes]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as out:
        out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(frames):
            epoch = BASE_EPOCH + index * 0.075
            sec, usec = int(epoch), int(round((epoch - int(epoch)) * 1_000_000))
            out.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            out.write(frame)


def main():
    output = Path(__file__).resolve().parent / "synthetic_all_protocols.pcap"
    frames = build_frames()
    write_pcap(output, frames)
    print(f"Wrote {output} with {len(frames)} frames")


if __name__ == "__main__":
    main()
