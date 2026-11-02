"""
Packet Filtering Engine for Network Packet Analyzer.
Distinguishes between BPF Capture Filters and Real-Time GUI Display Filters.
"""

import re
from typing import Any, Dict, List, Optional, Tuple
try:
    from scapy.arch.bpf.core import test_filter
except Exception:
    test_filter = None

from core.packet_analyzer import AnalyzedPacket


class BPFValidator:
    """Validates Berkeley Packet Filter (BPF) capture syntax."""

    # Common BPF keywords and structure validation
    BPF_PATTERN = re.compile(
        r"^(?:ip|ip6|arp|rarp|tcp|udp|icmp|icmp6|port\s+\d+|src\s+port\s+\d+|dst\s+port\s+\d+|"
        r"host\s+[a-zA-Z0-9\.:]+|src\s+host\s+[a-zA-Z0-9\.:]+|dst\s+host\s+[a-zA-Z0-9\.:]+|"
        r"net\s+[a-zA-Z0-9\.:/]+|and|or|not|&&|\|\||!|\(|\)|\s+)+$",
        re.IGNORECASE,
    )

    COMMON_PRESETS: Dict[str, str] = {
        "All Traffic": "",
        "TCP Only": "tcp",
        "UDP Only": "udp",
        "ICMP (Ping)": "icmp",
        "DNS (Port 53)": "udp port 53 or tcp port 53",
        "Web (HTTP/HTTPS)": "tcp port 80 or tcp port 443",
        "ARP Only": "arp",
        "No Broadcast/Multicast": "not broadcast and not multicast",
    }

    @classmethod
    def validate_bpf(cls, filter_expr: str) -> Tuple[bool, Optional[str]]:
        """
        Validate whether a BPF string is safe and syntactically plausible.
        Returns: (is_valid: bool, error_message: Optional[str])
        """
        expr = filter_expr.strip()
        if not expr:
            return True, None

        # Check basic parenthesis balance
        if expr.count("(") != expr.count(")"):
            return False, "Mismatched parentheses in capture filter."

        # Check against regex token pattern
        if not cls.BPF_PATTERN.match(expr):
            return False, (
                f"Invalid filter syntax '{expr}'. "
                "Supported tokens: tcp, udp, icmp, arp, port <n>, host <ip>, and, or, not."
            )

        return True, None


class PacketFilter:
    """
    In-memory display filter applied to captured AnalyzedPacket instances.
    Evaluates protocol, source IP, destination IP, port, and search query.
    """

    def __init__(
        self,
        protocol: str = "ALL",
        src_ip: str = "",
        dst_ip: str = "",
        port: Optional[int] = None,
        search_query: str = "",
    ):
        self.protocol = (protocol or "ALL").upper().strip()
        self.src_ip = (src_ip or "").strip()
        self.dst_ip = (dst_ip or "").strip()
        self.port = port
        self.search_query = (search_query or "").strip().lower()

    def is_active(self) -> bool:
        """Returns True if any filtering criteria are currently set."""
        return bool(
            (self.protocol and self.protocol != "ALL")
            or self.src_ip
            or self.dst_ip
            or self.port is not None
            or self.search_query
        )

    def matches(self, packet: AnalyzedPacket) -> bool:
        """Check if an analyzed packet satisfies all active filter conditions."""
        # 1. Protocol filter
        if self.protocol and self.protocol != "ALL":
            p_upper = packet.protocol.upper()
            if self.protocol == "OTHER":
                if p_upper in ("TCP", "UDP", "ICMP", "DNS", "ARP", "HTTP", "HTTPS", "TLS"):
                    return False
            elif self.protocol == "HTTP/HTTPS":
                if p_upper not in ("HTTP", "HTTPS", "TLS"):
                    return False
            elif p_upper != self.protocol:
                return False

        # 2. Source IP filter
        if self.src_ip:
            if self.src_ip.lower() not in packet.src_ip.lower():
                return False

        # 3. Destination IP filter
        if self.dst_ip:
            if self.dst_ip.lower() not in packet.dst_ip.lower():
                return False

        # 4. Port filter (either source or destination matches)
        if self.port is not None:
            matches_port = (packet.src_port == self.port) or (packet.dst_port == self.port)
            if not matches_port:
                return False

        # 5. Full-text search keyword across info, IPs, ports, flags, and ASCII payload
        if self.search_query:
            query = self.search_query
            searchable_fields = [
                str(packet.packet_id),
                packet.src_ip.lower(),
                packet.dst_ip.lower(),
                str(packet.src_port or ""),
                str(packet.dst_port or ""),
                packet.protocol.lower(),
                packet.tcp_flags_str.lower(),
                packet.summary_info.lower(),
                packet.ascii_preview.lower(),
            ]
            if not any(query in field_val for field_val in searchable_fields):
                return False

        return True

    def filter_packet_list(self, packets: List[AnalyzedPacket]) -> List[AnalyzedPacket]:
        """Filter a list of packets in memory."""
        if not self.is_active():
            return packets
        return [p for p in packets if self.matches(p)]
