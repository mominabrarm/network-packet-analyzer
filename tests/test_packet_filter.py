"""
Unit tests for core.packet_filter (BPF and display filtering).
"""

import unittest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from core.packet_analyzer import PacketAnalyzer
from core.packet_filter import BPFValidator, PacketFilter


class TestPacketFilter(unittest.TestCase):
    """Test capture filter validation and in-memory display filtering."""

    def setUp(self):
        # Create test packets
        pkt1 = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / TCP(sport=54321, dport=443, flags="S")
        pkt2 = Ether() / IP(src="192.168.1.20", dst="1.1.1.1") / UDP(sport=50000, dport=53)
        pkt3 = Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=8080, dport=80, flags="PA") / Raw(load=b"GET /login HTTP/1.1\r\n")

        self.p1 = PacketAnalyzer.analyze(pkt1, 1)
        self.p2 = PacketAnalyzer.analyze(pkt2, 2)
        self.p3 = PacketAnalyzer.analyze(pkt3, 3)
        self.packets = [self.p1, self.p2, self.p3]

    def test_bpf_syntax_validation(self):
        """Test BPF validation helper."""
        valid, _ = BPFValidator.validate_bpf("tcp")
        self.assertTrue(valid)

        valid, _ = BPFValidator.validate_bpf("udp and port 53")
        self.assertTrue(valid)

        valid, _ = BPFValidator.validate_bpf("host 192.168.1.1 and not port 80")
        self.assertTrue(valid)

        # Mismatched parenthesis
        invalid, err = BPFValidator.validate_bpf("tcp and (port 80")
        self.assertFalse(invalid)
        self.assertIn("parentheses", err)

        # Illegal symbols
        invalid2, err2 = BPFValidator.validate_bpf("SELECT * FROM traffic")
        self.assertFalse(invalid2)
        self.assertIn("Invalid filter", err2)

    def test_protocol_display_filtering(self):
        """Test filtering by protocol."""
        f_tcp = PacketFilter(protocol="TCP")
        matches_tcp = f_tcp.filter_packet_list(self.packets)
        self.assertEqual(len(matches_tcp), 1)
        self.assertEqual(matches_tcp[0].packet_id, 1)

        f_udp = PacketFilter(protocol="UDP")
        matches_udp = f_udp.filter_packet_list(self.packets)
        self.assertEqual(len(matches_udp), 1)
        self.assertEqual(matches_udp[0].packet_id, 2)

    def test_ip_filtering(self):
        """Test filtering by IP address."""
        f_src = PacketFilter(src_ip="192.168.1.20")
        matches = f_src.filter_packet_list(self.packets)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].src_ip, "192.168.1.20")

        f_dst = PacketFilter(dst_ip="8.8.8.8")
        matches_dst = f_dst.filter_packet_list(self.packets)
        self.assertEqual(len(matches_dst), 1)
        self.assertEqual(matches_dst[0].dst_ip, "8.8.8.8")

    def test_port_filtering(self):
        """Test filtering by port."""
        f_port = PacketFilter(port=443)
        matches = f_port.filter_packet_list(self.packets)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].dst_port, 443)

        f_sport = PacketFilter(port=8080)
        matches_sport = f_sport.filter_packet_list(self.packets)
        self.assertEqual(len(matches_sport), 1)
        self.assertEqual(matches_sport[0].src_port, 8080)

    def test_keyword_search_filtering(self):
        """Test full-text keyword search across packet metadata and payload."""
        f_search = PacketFilter(search_query="login")
        matches = f_search.filter_packet_list(self.packets)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].packet_id, 3)

        f_search_ip = PacketFilter(search_query="10.0.0.5")
        matches_ip = f_search_ip.filter_packet_list(self.packets)
        self.assertEqual(len(matches_ip), 1)
        self.assertEqual(matches_ip[0].packet_id, 3)


if __name__ == "__main__":
    unittest.main()

