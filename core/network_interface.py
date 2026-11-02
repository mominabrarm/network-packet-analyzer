"""
Network interface detection and environment diagnostics for Network Packet Analyzer.
Safely detects system adapters across Windows, Linux, and macOS.
"""

import ctypes
import os
import platform
import socket
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import psutil

# Scapy imports
try:
    from scapy.all import conf, get_working_ifaces
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


@dataclass
class NetworkInterface:
    """Represents a discovered network interface adapter."""
    name: str                       # System name / GUID or interface identifier
    display_name: str               # Human-friendly name (e.g. "Wi-Fi", "Ethernet")
    ipv4_addresses: List[str] = field(default_factory=list)
    ipv6_addresses: List[str] = field(default_factory=list)
    mac_address: str = "N/A"
    is_up: bool = False
    is_loopback: bool = False
    description: str = ""

    @property
    def primary_ip(self) -> str:
        """Return primary IPv4 address or fallback to first IPv6 / N/A."""
        if self.ipv4_addresses:
            return self.ipv4_addresses[0]
        if self.ipv6_addresses:
            return self.ipv6_addresses[0]
        return "No IP Assigned"

    def get_dropdown_label(self) -> str:
        """Label formatted for UI dropdowns."""
        ip_str = self.primary_ip
        status_symbol = "[UP]" if self.is_up else "[DOWN]"
        return f"{self.display_name} ({ip_str}) {status_symbol}"


class NetworkInterfaceManager:
    """Manages interface discovery, selection, and system capture readiness."""

    @staticmethod
    def is_admin() -> bool:
        """Check whether the current process runs with administrative/root privileges."""
        try:
            if platform.system() == "Windows":
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            else:
                return os.geteuid() == 0
        except Exception:
            return False

    @staticmethod
    def check_npcap_installed() -> bool:
        """Check if Npcap or WinPcap driver is installed on Windows."""
        if platform.system() != "Windows":
            return True  # Linux / macOS use native libpcap / bpf

        # Common Windows paths for Npcap / WinPcap
        paths_to_check = [
            r"C:\Windows\System32\Npcap",
            r"C:\Windows\System32\wpcap.dll",
            r"C:\Program Files\Npcap",
            r"C:\Windows\SysWOW64\wpcap.dll",
        ]
        for p in paths_to_check:
            if os.path.exists(p):
                return True

        if SCAPY_AVAILABLE:
            try:
                if getattr(conf, "use_pcap", False):
                    return True
            except Exception:
                pass

        return False

    @staticmethod
    def get_environment_status() -> Dict[str, Any]:
        """Return diagnostic health of packet capture capability on this machine."""
        os_name = platform.system()
        admin = NetworkInterfaceManager.is_admin()
        npcap = NetworkInterfaceManager.check_npcap_installed()
        
        can_live_capture = False
        message = ""
        
        if os_name == "Windows":
            if not npcap:
                can_live_capture = False
                message = "Npcap driver is missing. Install from https://npcap.com/ to enable live capture."
            elif not admin:
                can_live_capture = True  # Npcap can allow non-admin if configured, but warn
                message = "Running without Administrator rights. Some adapters or raw modes may be restricted."
            else:
                can_live_capture = True
                message = "Live packet capture ready (Npcap active, Administrator privileges detected)."
        else:
            if not admin:
                can_live_capture = False
                message = "Root/sudo privileges required for packet capture on Unix/macOS."
            else:
                can_live_capture = True
                message = "Live packet capture ready (Root privileges detected)."

        return {
            "os": os_name,
            "os_release": platform.release(),
            "python_version": platform.python_version(),
            "is_admin": admin,
            "npcap_installed": npcap,
            "can_live_capture": can_live_capture,
            "message": message,
        }

    @classmethod
    def get_interfaces(cls) -> List[NetworkInterface]:
        """
        Enumerate all active and available network interfaces.
        Uses psutil as primary robust detector, cross-referenced with Scapy if available.
        """
        interfaces_dict: Dict[str, NetworkInterface] = {}

        # 1. Enumerate using psutil
        try:
            stats = psutil.net_if_stats()
        except Exception:
            stats = {}

        try:
            addrs = psutil.net_if_addrs()
        except Exception:
            addrs = {}

        for iface_name, addr_list in addrs.items():
            ipv4_list = []
            ipv6_list = []
            mac = "N/A"
            
            for addr in addr_list:
                if addr.family == socket.AF_INET:
                    ipv4_list.append(addr.address)
                elif addr.family == socket.AF_INET6:
                    # Strip interface scope ID if present (e.g. fe80::1%12)
                    clean_ip = addr.address.split("%")[0]
                    ipv6_list.append(clean_ip)
                elif hasattr(psutil, "AF_LINK") and addr.family == psutil.AF_LINK:
                    mac = addr.address or "N/A"

            stat = stats.get(iface_name)
            is_up = stat.isup if stat else bool(ipv4_list or ipv6_list)
            is_loopback = "loopback" in iface_name.lower() or "127.0.0.1" in ipv4_list

            interfaces_dict[iface_name] = NetworkInterface(
                name=iface_name,
                display_name=iface_name,
                ipv4_addresses=ipv4_list,
                ipv6_addresses=ipv6_list,
                mac_address=mac,
                is_up=is_up,
                is_loopback=is_loopback,
            )

        # 2. Cross-reference with Scapy working interfaces if available
        if SCAPY_AVAILABLE:
            try:
                scapy_ifaces = get_working_ifaces()
                for s_iface in scapy_ifaces:
                    s_name = getattr(s_iface, "name", "")
                    s_desc = getattr(s_iface, "description", "")
                    # Match by name or description
                    matched = False
                    for existing_name, iface_obj in interfaces_dict.items():
                        if existing_name == s_name or (s_desc and s_desc in existing_name):
                            iface_obj.description = s_desc or s_name
                            # Prefer Scapy's interface name for actual sniffing
                            iface_obj.name = s_name
                            matched = True
                            break
                    if not matched and s_name:
                        # Add new interface known to Scapy
                        ip = getattr(s_iface, "ip", None)
                        mac = getattr(s_iface, "mac", "N/A")
                        interfaces_dict[s_name] = NetworkInterface(
                            name=s_name,
                            display_name=s_desc or s_name,
                            ipv4_addresses=[ip] if ip else [],
                            mac_address=mac or "N/A",
                            is_up=True,
                            description=s_desc or s_name,
                        )
            except Exception:
                pass

        # Sort: adapters with IP and UP status first, then alphabetically
        sorted_ifaces = sorted(
            interfaces_dict.values(),
            key=lambda x: (not x.is_up, not bool(x.ipv4_addresses), x.is_loopback, x.display_name),
        )
        return sorted_ifaces

    @classmethod
    def get_default_interface(cls) -> Optional[NetworkInterface]:
        """Select best candidate interface for packet capture (up, has IPv4, non-loopback)."""
        ifaces = cls.get_interfaces()
        for iface in ifaces:
            if iface.is_up and iface.ipv4_addresses and not iface.is_loopback:
                return iface
        # Fallback to loopback or first available
        return ifaces[0] if ifaces else None
