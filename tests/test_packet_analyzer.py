"""
Unit tests for core.packet_analyzer using synthetic Scapy packets.
Tests do not require live network access or administrator privileges.
"""

import unittest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from core.packet_analyzer import PacketAnalyzer
from utils.helpers import generate_hex_dump, sanitize_ascii


class TestPacketAnalyzer(unittest.TestCase):
    """Test packet parsing, layer extraction, flags, and hex dump formatting."""

    def test_tcp_packet_analysis(self):
        """Test parsing of Ethernet / IP / TCP SYN packet."""
        pkt = (
            Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
            / IP(src="192.168.1.50", dst="93.184.216.34", ttl=64)
            / TCP(sport=54321, dport=443, flags="S", seq=1000)
        )
        analyzed = PacketAnalyzer.analyze(pkt, packet_id=1)

        self.assertEqual(analyzed.packet_id, 1)
        self.assertEqual(analyzed.src_ip, "192.168.1.50")
        self.assertEqual(analyzed.dst_ip, "93.184.216.34")
        self.assertEqual(analyzed.src_port, 54321)
        self.assertEqual(analyzed.dst_port, 443)
        self.assertEqual(analyzed.protocol, "TCP")
        self.assertEqual(analyzed.ttl, 64)
        self.assertIn("SYN", analyzed.tcp_flags_list)
        self.assertIn("Ethernet", analyzed.layer_names)
        self.assertIn("IP", analyzed.layer_names)
        self.assertIn("TCP", analyzed.layer_names)

    def test_tcp_ack_psh_flags(self):
        """Test multi-flag TCP parsing (ACK + PSH)."""
        pkt = (
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=8080, dport=12345, flags="PA", seq=200, ack=500)
        )
        analyzed = PacketAnalyzer.analyze(pkt, packet_id=2)

        self.assertIn("ACK", analyzed.tcp_flags_list)
        self.assertIn("PSH", analyzed.tcp_flags_list)
        self.assertIn("ACK", analyzed.tcp_flags_str)
        self.assertIn("PSH", analyzed.tcp_flags_str)

    def test_udp_dns_query_analysis(self):
        """Test parsing of DNS Query packet."""
        pkt = (
            Ether()
            / IP(src="192.168.1.100", dst="8.8.8.8")
            / UDP(sport=52123, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
        )
        analyzed = PacketAnalyzer.analyze(pkt, packet_id=3)

        self.assertEqual(analyzed.protocol, "DNS")
        self.assertEqual(analyzed.src_port, 52123)
        self.assertEqual(analyzed.dst_port, 53)
        self.assertIn("example.com", analyzed.summary_info)

    def test_icmp_ping_analysis(self):
        """Test parsing of ICMP Echo Request."""
        pkt = (
            Ether()
            / IP(src="192.168.1.1", dst="192.168.1.254")
            / ICMP(type=8, code=0, id=12, seq=1)
        )
        analyzed = PacketAnalyzer.analyze(pkt, packet_id=4)

        self.assertEqual(analyzed.protocol, "ICMP")
        self.assertIn("Ping", analyzed.summary_info)

    def test_arp_packet_analysis(self):
        """Test parsing of Layer 2 ARP Request frame."""
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1,
            psrc="192.168.1.10",
            pdst="192.168.1.1",
            hwsrc="aa:bb:cc:dd:ee:ff",
        )
        analyzed = PacketAnalyzer.analyze(pkt, packet_id=5)

        self.assertEqual(analyzed.protocol, "ARP")
        self.assertEqual(analyzed.src_ip, "192.168.1.10")
        self.assertEqual(analyzed.dst_ip, "192.168.1.1")
        self.assertIn("Who has", analyzed.summary_info)

    def test_http_payload_detection(self):
        """Test HTTP signature recognition in payload."""
        http_data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        pkt = (
            Ether()
            / IP(src="192.168.1.10", dst="93.184.216.34")
            / TCP(sport=50000, dport=80, flags="PA")
            / Raw(load=http_data)
        )
        analyzed = PacketAnalyzer.analyze(pkt, packet_id=6)

        self.assertEqual(analyzed.protocol, "HTTP")
        self.assertIn("GET /index.html", analyzed.summary_info)
        self.assertIn("Host: example.com", analyzed.ascii_preview)

    def test_hex_dump_generation(self):
        """Test 16-byte hex dump layout."""
        sample_bytes = b"Hello, Network Security 2026!"
        dump_rows = generate_hex_dump(sample_bytes, max_bytes=64)

        self.assertTrue(len(dump_rows) >= 2)
        self.assertEqual(dump_rows[0][0], "0000")
        self.assertIn("48 65 6c 6c", dump_rows[0][1])  # "Hell"

    def test_ascii_sanitization(self):
        """Test non-printable byte masking with dots."""
        sample = b"ABC\x00\x01\x02XYZ"
        sanitized = sanitize_ascii(sample)
        self.assertEqual(sanitized, "ABC...XYZ")

    def test_malformed_truncated_packet_resilience(self):
        """Ensure analyzer does not crash on bare raw bytes or partial layers."""
        pkt = Ether() / Raw(load=b"\x00\xff\xee\xdd\xcc\xbb")
        analyzed = PacketAnalyzer.analyze(pkt, packet_id=7)

        self.assertEqual(analyzed.packet_id, 7)
        self.assertTrue(analyzed.length > 0)


if __name__ == "__main__":
    unittest.main()
