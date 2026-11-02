"""
Packet Capture Engine for Network Packet Analyzer.
Manages background packet sniffing via Scapy, thread synchronization,
packet queues, and educational traffic generation.
"""

import queue
import random
import threading
import time
from typing import Any, Callable, Dict, List, Optional

# Scapy imports
try:
    from scapy.all import AsyncSniffer, sniff
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.dns import DNS, DNSQR
    from scapy.packet import Raw
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

from core.network_interface import NetworkInterfaceManager
from core.packet_analyzer import AnalyzedPacket, PacketAnalyzer
from core.packet_filter import BPFValidator


class PacketCaptureEngine:
    """
    Multithreaded packet capture engine using Scapy.
    Executes in a background thread to keep the GUI fluid and responsive.
    """

    def __init__(
        self,
        packet_queue: Optional[queue.Queue] = None,
        on_packet_callback: Optional[Callable[[AnalyzedPacket], None]] = None,
        on_error_callback: Optional[Callable[[str], None]] = None,
        on_stats_callback: Optional[Callable[[Dict[str, int]], None]] = None,
    ):
        self.packet_queue = packet_queue or queue.Queue(maxsize=10000)
        self.on_packet_callback = on_packet_callback
        self.on_error_callback = on_error_callback
        self.on_stats_callback = on_stats_callback

        self._is_capturing = False
        self._is_simulation = False
        self._stop_event = threading.Event()
        self._capture_thread: Optional[threading.Thread] = None
        self._sniffer_instance: Optional[Any] = None

        # Lock for thread-safe access to packet archives
        self._lock = threading.Lock()
        self.analyzed_packets: List[AnalyzedPacket] = []
        self.raw_packets: List[Any] = []
        self.packet_counter = 0

        # Statistics
        self.stats = {
            "total": 0,
            "tcp": 0,
            "udp": 0,
            "other": 0,
            "icmp": 0,
            "dns": 0,
            "arp": 0,
            "http": 0,
        }
        self.capture_start_time: Optional[float] = None

    @property
    def is_capturing(self) -> bool:
        return self._is_capturing

    @property
    def is_simulation(self) -> bool:
        return self._is_simulation

    def start_capture(
        self,
        interface: Optional[str] = None,
        bpf_filter: str = "",
        use_simulation: bool = False,
    ) -> bool:
        """
        Start packet capture on specified interface with optional BPF filter.
        
        Args:
            interface: Name or description of adapter.
            bpf_filter: Berkeley Packet Filter expression.
            use_simulation: If True, generate realistic educational Scapy traffic.
        """
        if self._is_capturing:
            return True

        # Validate BPF filter syntax
        if bpf_filter:
            is_valid, err = BPFValidator.validate_bpf(bpf_filter)
            if not is_valid:
                if self.on_error_callback:
                    self.on_error_callback(f"BPF Syntax Error: {err}")
                return False

        # Check Windows Npcap requirement
        env = NetworkInterfaceManager.get_environment_status()
        if not use_simulation and env["os"] == "Windows" and not env["npcap_installed"]:
            # Inform caller Npcap is missing
            if self.on_error_callback:
                self.on_error_callback(
                    "Npcap is not installed on this Windows system.\n\n"
                    "Live packet capture requires Npcap (https://npcap.com/).\n"
                    "You can test and explore all dashboard features using "
                    "the built-in Educational Simulation Traffic Generator."
                )
            return False

        self._stop_event.clear()
        self._is_capturing = True
        self._is_simulation = use_simulation
        self.capture_start_time = time.time()

        if use_simulation:
            self._capture_thread = threading.Thread(
                target=self._run_simulation_worker,
                daemon=True,
                name="SimulationPacketCaptureThread",
            )
        else:
            self._capture_thread = threading.Thread(
                target=self._run_sniff_worker,
                args=(interface, bpf_filter),
                daemon=True,
                name="LivePacketCaptureThread",
            )

        self._capture_thread.start()
        return True

    def stop_capture(self) -> None:
        """Gracefully stop packet capture."""
        if not self._is_capturing:
            return

        self._is_capturing = False
        self._stop_event.set()

        # Stop AsyncSniffer if active
        if self._sniffer_instance and hasattr(self._sniffer_instance, "stop"):
            try:
                self._sniffer_instance.stop()
            except Exception:
                pass
            self._sniffer_instance = None

        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=1.0)
        self._capture_thread = None

    def clear(self) -> None:
        """Clear all stored packets and reset statistics."""
        with self._lock:
            self.analyzed_packets.clear()
            self.raw_packets.clear()
            self.packet_counter = 0
            self.stats = {
                "total": 0,
                "tcp": 0,
                "udp": 0,
                "other": 0,
                "icmp": 0,
                "dns": 0,
                "arp": 0,
                "http": 0,
            }
        # Drain queue
        while not self.packet_queue.empty():
            try:
                self.packet_queue.get_nowait()
            except queue.Empty:
                break

    def get_packets(self) -> List[AnalyzedPacket]:
        """Return a thread-safe snapshot copy of analyzed packets."""
        with self._lock:
            return list(self.analyzed_packets)

    def get_raw_packets(self) -> List[Any]:
        """Return a thread-safe snapshot copy of raw Scapy packets for PCAP export."""
        with self._lock:
            return list(self.raw_packets)

    def _process_packet(self, scapy_pkt: Any) -> None:
        """Internal callback invoked for every captured Scapy packet."""
        try:
            with self._lock:
                self.packet_counter += 1
                pid = self.packet_counter

            analyzed = PacketAnalyzer.analyze(scapy_pkt, pid)

            with self._lock:
                self.analyzed_packets.append(analyzed)
                self.raw_packets.append(scapy_pkt)

                # Update stats
                self.stats["total"] += 1
                proto = analyzed.protocol.upper()
                if proto == "TCP":
                    self.stats["tcp"] += 1
                elif proto == "UDP":
                    self.stats["udp"] += 1
                elif proto == "ICMP":
                    self.stats["icmp"] += 1
                    self.stats["other"] += 1
                elif proto == "DNS":
                    self.stats["dns"] += 1
                    self.stats["udp"] += 1  # Standard DNS is UDP
                elif proto == "ARP":
                    self.stats["arp"] += 1
                    self.stats["other"] += 1
                elif proto in ("HTTP", "HTTPS", "TLS"):
                    self.stats["http"] += 1
                    self.stats["tcp"] += 1
                else:
                    self.stats["other"] += 1

            # Put into UI queue (non-blocking)
            try:
                self.packet_queue.put_nowait(analyzed)
            except queue.Full:
                pass

            if self.on_packet_callback:
                self.on_packet_callback(analyzed)

            if self.on_stats_callback:
                self.on_stats_callback(dict(self.stats))

        except Exception as e:
            # Defensive isolation so one malformed packet never kills capture
            pass

    def _run_sniff_worker(self, interface: Optional[str], bpf_filter: str) -> None:
        """Background worker thread executing Scapy sniffing."""
        try:
            sniff_kwargs: Dict[str, Any] = {
                "prn": self._process_packet,
                "store": False,
                "stop_filter": lambda p: self._stop_event.is_set(),
            }

            if interface:
                sniff_kwargs["iface"] = interface

            if bpf_filter:
                sniff_kwargs["filter"] = bpf_filter

            # Run sniff in chunks with timeout to check stop event reliably
            while not self._stop_event.is_set():
                sniff_kwargs["timeout"] = 1.0  # 1-second slices for clean interruptibility
                sniff(**sniff_kwargs)

        except PermissionError:
            self._is_capturing = False
            if self.on_error_callback:
                self.on_error_callback(
                    "Permission Denied: Administrator or root privileges are required "
                    "to capture raw network packets on this interface."
                )
        except Exception as e:
            self._is_capturing = False
            err_msg = str(e)
            if self.on_error_callback:
                self.on_error_callback(f"Capture Error: {err_msg}")
        finally:
            self._is_capturing = False

    def _run_simulation_worker(self) -> None:
        """
        Background worker generating authentic Scapy packets for demonstration
        and educational study without requiring driver/admin privileges.
        """
        domains = ["google.com", "github.com", "openai.com", "python.org", "wikipedia.org", "cloudflare.com"]
        client_ips = ["192.168.1.105", "192.168.1.142", "192.168.1.88", "10.0.0.15"]
        server_ips = ["142.250.190.46", "140.82.121.4", "104.16.132.229", "1.1.1.1", "8.8.8.8"]
        
        while not self._stop_event.is_set():
            pkt_choice = random.choices(
                ["dns", "http", "tls", "tcp_ack", "icmp", "arp", "udp_data"],
                weights=[20, 20, 20, 15, 10, 5, 10],
                k=1,
            )[0]

            src_ip = random.choice(client_ips)
            dst_ip = random.choice(server_ips)
            sport = random.randint(49152, 65535)

            try:
                if pkt_choice == "dns":
                    # Synthetic DNS query
                    domain = random.choice(domains)
                    pkt = Ether() / IP(src=src_ip, dst="8.8.8.8") / UDP(sport=sport, dport=53) / DNS(
                        rd=1, qd=DNSQR(qname=domain, qtype="A")
                    )
                elif pkt_choice == "http":
                    # Synthetic HTTP GET request
                    domain = random.choice(domains)
                    http_payload = f"GET /api/v1/status HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n"
                    pkt = (
                        Ether()
                        / IP(src=src_ip, dst=dst_ip)
                        / TCP(sport=sport, dport=80, flags="PA", seq=random.randint(1000, 99999))
                        / Raw(load=http_payload.encode())
                    )
                elif pkt_choice == "tls":
                    # Synthetic TLS Application Data
                    tls_header = b"\x17\x03\x03\x00\x50" + (b"\xaa" * 80)
                    pkt = (
                        Ether()
                        / IP(src=src_ip, dst=dst_ip)
                        / TCP(sport=sport, dport=443, flags="PA", seq=random.randint(1000, 99999))
                        / Raw(load=tls_header)
                    )
                elif pkt_choice == "tcp_ack":
                    # Synthetic TCP Handshake ACK
                    pkt = (
                        Ether()
                        / IP(src=src_ip, dst=dst_ip)
                        / TCP(sport=sport, dport=443, flags="A", seq=random.randint(1000, 99999), ack=random.randint(1000, 99999))
                    )
                elif pkt_choice == "icmp":
                    # Synthetic ICMP Ping Request
                    pkt = (
                        Ether()
                        / IP(src=src_ip, dst="8.8.8.8")
                        / ICMP(type=8, code=0, id=random.randint(1, 100), seq=random.randint(1, 50))
                        / Raw(load=b"abcdefghijklmnopqrstuvwabcdefghi")
                    )
                elif pkt_choice == "arp":
                    # Synthetic ARP Request
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                        op=1,
                        psrc="192.168.1.105",
                        pdst="192.168.1.1",
                        hwsrc="00:1a:2b:3c:4d:5e",
                    )
                else:
                    # Generic UDP packet
                    pkt = (
                        Ether()
                        / IP(src=src_ip, dst=dst_ip)
                        / UDP(sport=sport, dport= random.choice([123, 161, 5353]))
                        / Raw(load=b"NTP/SNMP payload sample")
                    )

                self._process_packet(pkt)

            except Exception:
                pass

            # Natural bursty delay between 0.05 and 0.35 seconds
            time.sleep(random.uniform(0.05, 0.35))

