"""
Utility helper functions and UI theme constants for Network Packet Analyzer.
"""

from datetime import datetime
from typing import Dict, List, Tuple

# Cyber Modern Dark Theme Palette
THEME = {
    "bg_main": "#0b0f19",          # Main window background (deep navy black)
    "bg_card": "#111827",          # Card background (slate navy)
    "bg_card_alt": "#1e293b",      # Secondary card / input background
    "bg_header": "#0f172a",        # Header dark slate
    "border": "#1e293b",           # Clean border
    "border_light": "#334155",     # Border highlight
    "text_primary": "#f8fafc",     # High contrast primary text
    "text_secondary": "#94a3b8",   # Muted secondary text
    "text_dim": "#64748b",         # Dim label text
    "cyan": "#00f0ff",             # Electric cyan accent
    "blue": "#3b82f6",             # Neon blue
    "green": "#10b981",            # Cyber green (Capturing/Active)
    "yellow": "#f59e0b",           # Warning amber
    "red": "#ef4444",              # Danger red (Stopped/Errors)
    "purple": "#a855f7",           # Secondary accent purple
    "font_family": "Segoe UI",
    "font_mono": "Consolas",
}

# Protocol Color Mapping for Table and Charts
PROTOCOL_COLORS: Dict[str, str] = {
    "TCP": "#38bdf8",     # Sky blue
    "UDP": "#fb923c",     # Orange
    "ICMP": "#f472b6",    # Pink / Magenta
    "ICMPv6": "#f472b6",  # Pink / Magenta
    "DNS": "#818cf8",     # Indigo
    "ARP": "#facc15",     # Gold Yellow
    "HTTP": "#4ade80",    # Emerald
    "HTTPS": "#2dd4bf",   # Teal
    "DHCP": "#c084fc",    # Purple
    "TLS": "#2dd4bf",     # Teal
    "OTHER": "#94a3b8",   # Slate Gray
}


def get_protocol_color(protocol: str) -> str:
    """Return standard hex color for a given protocol string."""
    proto_upper = (protocol or "OTHER").upper()
    return PROTOCOL_COLORS.get(proto_upper, PROTOCOL_COLORS["OTHER"])


def format_bytes(size: int) -> str:
    """Format byte integer into a human-readable string (B, KB, MB, GB)."""
    if size < 0:
        return "0 B"
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024.0:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"


def format_timestamp(ts: float, include_date: bool = False) -> str:
    """Format Unix epoch timestamp into local readable time with milliseconds."""
    try:
        dt = datetime.fromtimestamp(ts)
        if include_date:
            return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        return dt.strftime("%H:%M:%S.%f")[:-3]
    except Exception:
        return "--:--:--.---"


def sanitize_ascii(data: bytes, max_bytes: int = 512, max_len: int = None) -> str:
    """
    Safely convert raw payload bytes to ASCII string.
    Non-printable characters are replaced with dots ('.').
    No credentials or sensitive values are parsed or targeted.
    """
    limit = max_len if max_len is not None else max_bytes
    if not data:
        return ""
    truncated = data[:limit]
    chars = []
    for b in truncated:
        if 32 <= b <= 126:
            chars.append(chr(b))
        elif b in (10, 13):
            chars.append(" ")
        else:
            chars.append(".")
    result = "".join(chars)
    if len(data) > limit:
        result += f"\n... [Truncated at {limit} bytes; total {len(data)} bytes]"
    return result


def generate_hex_dump(data: bytes, max_bytes: int = 512) -> List[Tuple[str, str, str]]:
    """
    Generate Wireshark-style hex dump rows:
    Returns list of tuples: (Offset, Hex Dump, ASCII Dump)
    Example: ('0000', '45 00 00 3c 1a 2b 40 00  40 06 b2 c9 c0 a8 01 64', 'E..<.+@.@......d')
    """
    if not data:
        return []
    
    data_slice = data[:max_bytes]
    rows = []
    
    for i in range(0, len(data_slice), 16):
        chunk = data_slice[i:i+16]
        offset_str = f"{i:04x}"
        
        # Hex representation
        hex_bytes = [f"{b:02x}" for b in chunk]
        # Insert extra space after 8 bytes for readability
        if len(hex_bytes) > 8:
            hex_part = " ".join(hex_bytes[:8]) + "  " + " ".join(hex_bytes[8:])
        else:
            hex_part = " ".join(hex_bytes)
        # Pad to fixed 49 chars width (16 * 3 + 1 extra space)
        hex_part = f"{hex_part:<49}"
        
        # ASCII representation
        ascii_chars = [chr(b) if 32 <= b <= 126 else "." for b in chunk]
        ascii_part = "".join(ascii_chars)
        
        rows.append((offset_str, hex_part, ascii_part))
    
    return rows
