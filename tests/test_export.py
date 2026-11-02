"""
Unit tests for utils.export (CSV and PCAP exporting).
"""

import os
import tempfile
import unittest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from core.packet_analyzer import PacketAnalyzer
from utils.export import export_to_csv, export_to_pcap


class TestExportFunctionality(unittest.TestCase):
    """Test exporting packets to CSV and PCAP."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.pkt1 = Ether() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=1234, dport=80, flags="S")
        self.pkt2 = Ether() / IP(src="192.168.1.20", dst="8.8.8.8") / TCP(sport=4321, dport=443, flags="A")
        self.analyzed1 = PacketAnalyzer.analyze(self.pkt1, 1)
        self.analyzed2 = PacketAnalyzer.analyze(self.pkt2, 2)

    def tearDown(self):
        for f in os.listdir(self.tmp_dir):
            try:
                os.remove(os.path.join(self.tmp_dir, f))
            except Exception:
                pass
        try:
            os.rmdir(self.tmp_dir)
        except Exception:
            pass

    def test_export_to_csv(self):
        """Test CSV file generation with packet metadata."""
        csv_path = os.path.join(self.tmp_dir, "test_output.csv")
        res = export_to_csv([self.analyzed1, self.analyzed2], csv_path)

        self.assertTrue(res["success"])
        self.assertEqual(res["count"], 2)
        self.assertTrue(os.path.exists(csv_path))

        with open(csv_path, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("192.168.1.10", content)
            self.assertIn("93.184.216.34", content)
            self.assertIn("SYN", content or "S")

    def test_export_to_pcap(self):
        """Test PCAP file generation with Scapy frames."""
        pcap_path = os.path.join(self.tmp_dir, "test_output.pcap")
        res = export_to_pcap([self.pkt1, self.pkt2], pcap_path)

        self.assertTrue(res["success"])
        self.assertEqual(res["count"], 2)
        self.assertTrue(os.path.exists(pcap_path))
        self.assertGreater(os.path.getsize(pcap_path), 0)

    def test_export_empty_cases(self):
        """Ensure empty packet collections fail gracefully without crashing."""
        csv_path = os.path.join(self.tmp_dir, "empty.csv")
        res_csv = export_to_csv([], csv_path)
        self.assertFalse(res_csv["success"])

        pcap_path = os.path.join(self.tmp_dir, "empty.pcap")
        res_pcap = export_to_pcap([], pcap_path)
        self.assertFalse(res_pcap["success"])


if __name__ == "__main__":
    unittest.main()

