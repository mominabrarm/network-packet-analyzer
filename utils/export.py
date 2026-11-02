"""
Export functionality for Network Packet Analyzer.
Supports CSV metadata export and Scapy PCAP export for Wireshark interoperability.
"""

import csv
import os
from typing import Any, Dict, List, Optional
from scapy.utils import wrpcap


def export_to_csv(analyzed_packets: List[Any], filepath: str) -> Dict[str, Any]:
    """
    Export analyzed packet metadata to a CSV file.
    
    Args:
        analyzed_packets: List of AnalyzedPacket objects or dicts.
        filepath: Destination file path.
        
    Returns:
        dict: {'success': bool, 'count': int, 'error': Optional[str]}
    """
    if not analyzed_packets:
        return {"success": False, "count": 0, "error": "No packets captured to export."}
    
    try:
        # Ensure parent directory exists
        parent_dir = os.path.dirname(os.path.abspath(filepath))
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)
            
        fieldnames = [
            "No",
            "Timestamp",
            "Source IP",
            "Source Port",
            "Destination IP",
            "Destination Port",
            "Protocol",
            "Length (Bytes)",
            "TTL",
            "TCP Flags",
            "Info",
        ]
        
        with open(filepath, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for p in analyzed_packets:
                if hasattr(p, "to_csv_row"):
                    row = p.to_csv_row()
                elif isinstance(p, dict):
                    row = p
                else:
                    row = {
                        "No": getattr(p, "packet_id", ""),
                        "Timestamp": getattr(p, "timestamp_formatted", ""),
                        "Source IP": getattr(p, "src_ip", ""),
                        "Source Port": getattr(p, "src_port", ""),
                        "Destination IP": getattr(p, "dst_ip", ""),
                        "Destination Port": getattr(p, "dst_port", ""),
                        "Protocol": getattr(p, "protocol", ""),
                        "Length (Bytes)": getattr(p, "length", 0),
                        "TTL": getattr(p, "ttl", ""),
                        "TCP Flags": getattr(p, "tcp_flags_str", ""),
                        "Info": getattr(p, "summary_info", ""),
                    }
                writer.writerow(row)
                
        return {"success": True, "count": len(analyzed_packets), "error": None}
        
    except PermissionError:
        return {"success": False, "count": 0, "error": f"Permission denied writing to '{filepath}'."}
    except Exception as e:
        return {"success": False, "count": 0, "error": f"Failed to export CSV: {str(e)}"}


def export_to_pcap(scapy_packets: List[Any], filepath: str) -> Dict[str, Any]:
    """
    Export raw Scapy packets to a standard PCAP file for Wireshark inspection.
    
    Args:
        scapy_packets: List of raw Scapy Packet objects.
        filepath: Destination file path ending with .pcap.
        
    Returns:
        dict: {'success': bool, 'count': int, 'error': Optional[str]}
    """
    if not scapy_packets:
        return {"success": False, "count": 0, "error": "No raw packets available to export."}
        
    try:
        # Ensure parent directory exists
        parent_dir = os.path.dirname(os.path.abspath(filepath))
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)
            
        wrpcap(filepath, scapy_packets)
        return {"success": True, "count": len(scapy_packets), "error": None}
        
    except PermissionError:
        return {"success": False, "count": 0, "error": f"Permission denied writing to '{filepath}'."}
    except Exception as e:
        return {"success": False, "count": 0, "error": f"Failed to export PCAP: {str(e)}"}

