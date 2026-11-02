"""
Packet Analysis Engine for Network Packet Analyzer.
Extracts protocol layers, addresses, ports, flags, TTL, metadata, and safe previews
from captured Scapy packets.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# Scapy layer imports
try:
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.packet import Raw
    SCAPY_LAYERS_AVAILABLE = True
except Exception:
    SCAPY_LAYERS_AVAILABLE = False

from utils.helpers import (
    format_timestamp,
    generate_hex_dump,
    get_protocol_color,
    sanitize_ascii,
)


# TCP Flag Bitmask constants and mappings
TCP_FLAGS_MAP = {
    0x01: "FIN",
    0x02: "SYN",
    0x04: "RST",
    0x08: "PSH",
    0x10: "ACK",
    0x20: "URG",
    0x40: "ECE",
    0x80: "CWR",
}

# DNS Query Types mapping
DNS_QTYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}


@dataclass
class AnalyzedPacket:
    """Structured representation of an analyzed network packet."""
    packet_id: int
    timestamp: float
    timestamp_formatted: str
    length: int
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    ttl: Optional[int] = None
    tcp_flags_str: str = ""
    tcp_flags_list: List[str] = field(default_factory=list)
    summary_info: str = ""
    layer_names: List[str] = field(default_factory=list)
    layer_details: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    payload_bytes: bytes = b""
    hex_dump: List[Tuple[str, str, str]] = field(default_factory=list)
    ascii_preview: str = ""
    raw_packet: Any = None

    @property
    def protocol_color(self) -> str:
        return get_protocol_color(self.protocol)

    def to_table_row(self) -> Tuple[int, str, str, str, str, int, str]:
        """Format data for dashboard Treeview table."""
        return (
            self.packet_id,
            self.timestamp_formatted,
            self.src_ip,
            self.dst_ip,
            self.protocol,
            self.length,
            self.summary_info,
        )

    def to_csv_row(self) -> Dict[str, Any]:
        """Format data for CSV export."""
        return {
            "No": self.packet_id,
            "Timestamp": self.timestamp_formatted,
            "Source IP": self.src_ip,
            "Source Port": self.src_port if self.src_port is not None else "",
            "Destination IP": self.dst_ip,
            "Destination Port": self.dst_port if self.dst_port is not None else "",
            "Protocol": self.protocol,
            "Length (Bytes)": self.length,
            "TTL": self.ttl if self.ttl is not None else "",
            "TCP Flags": self.tcp_flags_str,
            "Info": self.summary_info,
        }


class PacketAnalyzer:
    """Core parser and analyzer for raw network packets."""

    @classmethod
    def analyze(cls, packet: Any, packet_id: int) -> AnalyzedPacket:
        """
        Parse a Scapy packet into an AnalyzedPacket instance.
        Safely handles any layer combination or malformed packet.
        """
        # Timestamp
        try:
            ts = float(getattr(packet, "time", datetime.now().timestamp()))
        except Exception:
            ts = datetime.now().timestamp()
        ts_formatted = format_timestamp(ts)

        # Packet Length
        try:
            length = len(packet)
        except Exception:
            length = 0

        # Layer Extraction
        layer_names: List[str] = []
        layer_details: Dict[str, Dict[str, Any]] = {}
        cls._extract_layers(packet, layer_names, layer_details)

        # Initialize core metadata
        src_ip = "Unknown"
        dst_ip = "Unknown"
        src_port = None
        dst_port = None
        ttl = None
        protocol = "OTHER"
        tcp_flags_str = ""
        tcp_flags_list: List[str] = []
        summary_info = ""

        # 1. Check Network Layer (IP / IPv6 / ARP)
        if SCAPY_LAYERS_AVAILABLE and packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            ttl = ip_layer.ttl
            protocol = "IPv4"
        elif SCAPY_LAYERS_AVAILABLE and packet.haslayer(IPv6):
            ip6_layer = packet.getlayer(IPv6)
            src_ip = ip6_layer.src
            dst_ip = ip6_layer.dst
            ttl = getattr(ip6_layer, "hlim", None)
            protocol = "IPv6"
        elif SCAPY_LAYERS_AVAILABLE and packet.haslayer(ARP):
            arp_layer = packet.getlayer(ARP)
            src_ip = arp_layer.psrc
            dst_ip = arp_layer.pdst
            protocol = "ARP"
            op = "Request" if arp_layer.op == 1 else ("Reply" if arp_layer.op == 2 else f"Op:{arp_layer.op}")
            if arp_layer.op == 1:
                summary_info = f"Who has {arp_layer.pdst}? Tell {arp_layer.psrc}"
            elif arp_layer.op == 2:
                summary_info = f"{arp_layer.psrc} is at {arp_layer.hwsrc}"
            else:
                summary_info = f"ARP {op} {arp_layer.psrc} -> {arp_layer.pdst}"
        elif SCAPY_LAYERS_AVAILABLE and packet.haslayer(Ether):
            eth_layer = packet.getlayer(Ether)
            src_ip = eth_layer.src
            dst_ip = eth_layer.dst
            protocol = "Ethernet"
            summary_info = f"Ethernet Frame: {eth_layer.src} -> {eth_layer.dst} (type {hex(eth_layer.type)})"

        # 2. Check Transport Layer (TCP / UDP / ICMP)
        if SCAPY_LAYERS_AVAILABLE and packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            protocol = "TCP"
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            tcp_flags_str, tcp_flags_list = cls._parse_tcp_flags(tcp_layer.flags)
            seq = getattr(tcp_layer, "seq", 0)
            ack = getattr(tcp_layer, "ack", 0)
            window = getattr(tcp_layer, "window", 0)
            summary_info = (
                f"{src_port} -> {dst_port} [{tcp_flags_str or 'NONE'}] "
                f"Seq={seq} Ack={ack} Win={window} Len={length}"
            )
        elif SCAPY_LAYERS_AVAILABLE and packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            protocol = "UDP"
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            udp_len = getattr(udp_layer, "len", length)
            summary_info = f"{src_port} -> {dst_port} Len={udp_len}"
        elif SCAPY_LAYERS_AVAILABLE and packet.haslayer(ICMP):
            icmp_layer = packet.getlayer(ICMP)
            protocol = "ICMP"
            icmp_type = icmp_layer.type
            icmp_code = icmp_layer.code
            type_desc = cls._get_icmp_description(icmp_type, icmp_code)
            summary_info = f"Echo/Ping {type_desc} (Type {icmp_type}, Code {icmp_code})"

        # 3. Check Application Layer: DNS
        if SCAPY_LAYERS_AVAILABLE and packet.haslayer(DNS):
            protocol = "DNS"
            dns_layer = packet.getlayer(DNS)
            summary_info = cls._parse_dns_summary(dns_layer, src_port, dst_port)

        # 4. Check Application Layer: HTTP / TLS (Safe inspection without assuming by port)
        payload_bytes = b""
        if SCAPY_LAYERS_AVAILABLE and packet.haslayer(Raw):
            try:
                payload_bytes = bytes(packet.getlayer(Raw).load)
            except Exception:
                payload_bytes = b""

        # Check for actual HTTP signatures in payload
        if payload_bytes:
            http_sig = cls._detect_http_payload(payload_bytes)
            if http_sig:
                protocol = "HTTP"
                summary_info = http_sig
            elif cls._detect_tls_handshake(payload_bytes):
                protocol = "TLS"
                if not summary_info:
                    summary_info = f"TLS Handshake / Record ({src_port} -> {dst_port})"

        # Fallback summary if empty
        if not summary_info:
            summary_info = f"{protocol} packet ({src_ip} -> {dst_ip}, {length} bytes)"

        # Generate Safe Hex and ASCII views
        hex_dump = generate_hex_dump(payload_bytes, max_bytes=512)
        ascii_preview = sanitize_ascii(payload_bytes, max_bytes=512)

        return AnalyzedPacket(
            packet_id=packet_id,
            timestamp=ts,
            timestamp_formatted=ts_formatted,
            length=length,
            protocol=protocol,
            src_ip=str(src_ip),
            dst_ip=str(dst_ip),
            src_port=src_port,
            dst_port=dst_port,
            ttl=ttl,
            tcp_flags_str=tcp_flags_str,
            tcp_flags_list=tcp_flags_list,
            summary_info=summary_info,
            layer_names=layer_names,
            layer_details=layer_details,
            payload_bytes=payload_bytes,
            hex_dump=hex_dump,
            ascii_preview=ascii_preview,
            raw_packet=packet,
        )

    @classmethod
    def _extract_layers(cls, packet: Any, layer_names: List[str], layer_details: Dict[str, Dict[str, Any]]) -> None:
        """Walk packet layers and collect human-readable layer fields."""
        curr = packet
        while curr:
            layer_name = curr.__class__.__name__
            if layer_name == "Ether":
                layer_name = "Ethernet"
            if layer_name not in layer_names:
                layer_names.append(layer_name)
            
            # Extract non-private fields
            fields_dict: Dict[str, Any] = {}
            if hasattr(curr, "fields"):
                for k, v in curr.fields.items():
                    if k == "load":  # skip raw bytes in summary dict
                        continue
                    if isinstance(v, bytes):
                        try:
                            fields_dict[k] = v.decode("utf-8", errors="replace")
                        except Exception:
                            fields_dict[k] = f"<{len(v)} bytes>"
                    else:
                        fields_dict[k] = str(v)
            layer_details[layer_name] = fields_dict
            
            if hasattr(curr, "payload") and curr.payload:
                curr = curr.payload
                # Stop if payload is empty NoPayload
                if curr.__class__.__name__ == "NoPayload":
                    break
            else:
                break

    @staticmethod
    def _parse_tcp_flags(flags: Any) -> Tuple[str, List[str]]:
        """Parse Scapy TCP flags into readable strings and list of active flags."""
        active_flags: List[str] = []
        try:
            # Scapy flags can be a FlagValue or int
            int_val = int(flags)
            for mask, name in TCP_FLAGS_MAP.items():
                if int_val & mask:
                    active_flags.append(name)
        except Exception:
            # Fallback if flag object has string representation like 'PA'
            flag_str = str(flags)
            letter_map = {
                'F': 'FIN', 'S': 'SYN', 'R': 'RST', 'P': 'PSH',
                'A': 'ACK', 'U': 'URG', 'E': 'ECE', 'C': 'CWR'
            }
            for char in flag_str:
                if char in letter_map:
                    active_flags.append(letter_map[char])

        return ", ".join(active_flags), active_flags

    @staticmethod
    def _get_icmp_description(icmp_type: int, icmp_code: int) -> str:
        """Map ICMP type and code to standard network descriptions."""
        icmp_types = {
            0: "Echo Reply",
            3: {
                0: "Dest Net Unreachable",
                1: "Dest Host Unreachable",
                3: "Dest Port Unreachable",
            }.get(icmp_code, "Destination Unreachable"),
            8: "Echo Request (Ping)",
            11: "Time Exceeded (TTL expired)",
        }
        return icmp_types.get(icmp_type, f"Type {icmp_type}")

    @classmethod
    def _parse_dns_summary(cls, dns_layer: Any, src_port: Optional[int], dst_port: Optional[int]) -> str:
        """Extract DNS query or response information."""
        try:
            qr = getattr(dns_layer, "qr", 0)
            is_response = (qr == 1)
            
            # DNS Query (qr == 0)
            if not is_response and hasattr(dns_layer, "qd") and dns_layer.qd:
                qd_list = dns_layer.qd
                qd_item = qd_list[0] if hasattr(qd_list, "__getitem__") and len(qd_list) > 0 else qd_list
                qname = getattr(qd_item, "qname", b"")
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", errors="replace").rstrip(".")
                qtype_num = getattr(qd_item, "qtype", 1)
                qtype_str = DNS_QTYPES.get(qtype_num, f"TYPE{qtype_num}")
                return f"DNS Query: {qname} ({qtype_str})"
            
            # DNS Response (qr == 1)
            elif is_response:
                ancount = getattr(dns_layer, "ancount", 0)
                qname = "DNS Response"
                if hasattr(dns_layer, "qd") and dns_layer.qd:
                    qd_list = dns_layer.qd
                    qd_item = qd_list[0] if hasattr(qd_list, "__getitem__") and len(qd_list) > 0 else qd_list
                    qn = getattr(qd_item, "qname", b"")
                    if isinstance(qn, bytes):
                        qname = qn.decode("utf-8", errors="replace").rstrip(".")
                return f"DNS Response: {qname} (Answers: {ancount})"
        except Exception:
            pass
        return f"DNS Traffic ({src_port} -> {dst_port})"

    @staticmethod
    def _detect_http_payload(payload: bytes) -> Optional[str]:
        """
        Verify if payload begins with valid HTTP request method or response header.
        Never blindly tags HTTP based solely on port 80.
        """
        try:
            sample = payload[:256].decode("latin-1", errors="ignore")
            # HTTP Request methods
            methods = ("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "TRACE ", "CONNECT ")
            for m in methods:
                if sample.startswith(m):
                    first_line = sample.split("\r\n")[0] if "\r\n" in sample else sample.split("\n")[0]
                    return f"HTTP {first_line.strip()}"
            
            # HTTP Response
            if sample.startswith("HTTP/1.0 ") or sample.startswith("HTTP/1.1 ") or sample.startswith("HTTP/2.0 "):
                first_line = sample.split("\r\n")[0] if "\r\n" in sample else sample.split("\n")[0]
                return f"HTTP {first_line.strip()}"
        except Exception:
            pass
        return None

    @staticmethod
    def _detect_tls_handshake(payload: bytes) -> bool:
        """Check for TLS ContentType 22 (Handshake) or 23 (Application Data)."""
        if len(payload) >= 5:
            # 0x16 = Handshake, 0x17 = Application Data, 0x15 = Alert
            if payload[0] in (0x16, 0x17, 0x15) and payload[1] == 0x03 and payload[2] in (0x01, 0x02, 0x03, 0x04):
                return True
        return False
