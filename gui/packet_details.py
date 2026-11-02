"""
Packet Details Component for Network Packet Analyzer.
Displays deep protocol layers, TCP flag breakdowns, safe payload hex/ASCII previews,
and educational cybersecurity guidelines.
"""

import tkinter as tk
from tkinter import ttk
from typing import Optional

from core.packet_analyzer import AnalyzedPacket
from utils.helpers import THEME, get_protocol_color


class PacketDetailsPanel(tk.Frame):
    """
    Inspector panel displaying multi-layer packet metadata,
    layer tree breakdown, Wireshark-style hex/ASCII dump, and ethical notice.
    """

    def __init__(self, parent: tk.Widget, **kwargs):
        super().__init__(parent, bg=THEME["bg_card"], **kwargs)
        self._current_packet: Optional[AnalyzedPacket] = None
        self._init_ui()

    def _init_ui(self) -> None:
        """Construct the tabs and inspector panels."""
        # Header title bar
        header_bar = tk.Frame(self, bg=THEME["bg_card_alt"], padx=12, pady=6)
        header_bar.pack(fill="x", side="top")

        lbl_title = tk.Label(
            header_bar,
            text="PACKET DETAILS & PAYLOAD INSPECTOR",
            font=(THEME["font_family"], 9, "bold"),
            fg=THEME["cyan"],
            bg=THEME["bg_card_alt"],
        )
        lbl_title.pack(side="left")

        self.lbl_selected_id = tk.Label(
            header_bar,
            text="No packet selected",
            font=(THEME["font_mono"], 9),
            fg=THEME["text_secondary"],
            bg=THEME["bg_card_alt"],
        )
        self.lbl_selected_id.pack(side="right")

        # Notebook tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=8)

        # Tab 1: Protocol & Layer Inspection
        self.tab_layers = tk.Frame(self.notebook, bg=THEME["bg_card"])
        self.notebook.add(self.tab_layers, text=" Protocol Breakdown ")

        # Tab 2: Hex & ASCII Payload Preview
        self.tab_payload = tk.Frame(self.notebook, bg=THEME["bg_card"])
        self.notebook.add(self.tab_payload, text=" Hex & ASCII Payload ")

        # Tab 3: Ethical & Security Notice
        self.tab_ethics = tk.Frame(self.notebook, bg=THEME["bg_card"])
        self.notebook.add(self.tab_ethics, text=" Ethical Safeguards ")

        self._build_layers_tab()
        self._build_payload_tab()
        self._build_ethics_tab()

    def _build_layers_tab(self) -> None:
        """Build metadata grid and layer fields treeview."""
        # Top Metadata Summary Grid
        self.meta_frame = tk.Frame(self.tab_layers, bg=THEME["bg_card_alt"], padx=10, pady=8)
        self.meta_frame.pack(fill="x", padx=6, pady=(6, 4))

        # Metadata labels
        self.meta_labels = {}
        fields = [
            ("Protocol:", "proto_val"),
            ("Length:", "len_val"),
            ("Source IP:", "src_val"),
            ("Source Port:", "sport_val"),
            ("Destination IP:", "dst_val"),
            ("Destination Port:", "dport_val"),
            ("TTL:", "ttl_val"),
            ("TCP Flags:", "flags_val"),
        ]

        for i, (label_text, key) in enumerate(fields):
            row = i // 4
            col = (i % 4) * 2

            lbl = tk.Label(
                self.meta_frame,
                text=label_text,
                font=(THEME["font_family"], 8, "bold"),
                fg=THEME["text_dim"],
                bg=THEME["bg_card_alt"],
            )
            lbl.grid(row=row, column=col, sticky="w", padx=(6, 4), pady=2)

            val = tk.Label(
                self.meta_frame,
                text="--",
                font=(THEME["font_mono"], 9),
                fg=THEME["text_primary"],
                bg=THEME["bg_card_alt"],
            )
            val.grid(row=row, column=col + 1, sticky="w", padx=(0, 14), pady=2)
            self.meta_labels[key] = val

        # Hierarchical Layer Inspector Tree
        tree_frame = tk.Frame(self.tab_layers, bg=THEME["bg_card"])
        tree_frame.pack(fill="both", expand=True, padx=6, pady=4)

        tree_scroll = ttk.Scrollbar(tree_frame, orient="vertical")
        self.layer_tree = ttk.Treeview(
            tree_frame,
            columns=("value",),
            show="tree headings",
            yscrollcommand=tree_scroll.set,
        )
        tree_scroll.config(command=self.layer_tree.yview)
        tree_scroll.pack(side="right", fill="y")
        self.layer_tree.pack(side="left", fill="both", expand=True)

        self.layer_tree.heading("#0", text="Layer / Field", anchor="w")
        self.layer_tree.heading("value", text="Value", anchor="w")
        self.layer_tree.column("#0", width=220, minwidth=140)
        self.layer_tree.column("value", width=380, minwidth=200)

    def _build_payload_tab(self) -> None:
        """Build Wireshark-style Hex and ASCII viewer."""
        # Top banner
        banner = tk.Frame(self.tab_payload, bg=THEME["bg_card_alt"], padx=8, pady=4)
        banner.pack(fill="x", padx=6, pady=(6, 4))

        lbl_warn = tk.Label(
            banner,
            text="* Payload Preview (Safely sanitized; max 512 bytes displayed. Credentials never analyzed)",
            font=(THEME["font_family"], 8),
            fg=THEME["yellow"],
            bg=THEME["bg_card_alt"],
        )
        lbl_warn.pack(side="left")

        # Text display for Hex dump
        text_frame = tk.Frame(self.tab_payload, bg=THEME["bg_card"])
        text_frame.pack(fill="both", expand=True, padx=6, pady=4)

        scroll = ttk.Scrollbar(text_frame, orient="vertical")
        self.txt_hexdump = tk.Text(
            text_frame,
            bg="#050811",
            fg=THEME["cyan"],
            insertbackground="#ffffff",
            font=(THEME["font_mono"], 9),
            wrap="none",
            relief="flat",
            yscrollcommand=scroll.set,
            padx=8,
            pady=8,
        )
        scroll.config(command=self.txt_hexdump.yview)
        scroll.pack(side="right", fill="y")
        self.txt_hexdump.pack(side="left", fill="both", expand=True)

        # Set headers inside text
        self._render_payload_empty()

    def _build_ethics_tab(self) -> None:
        """Display educational usage disclaimer and cybersecurity safeguards."""
        ethics_container = tk.Frame(self.tab_ethics, bg=THEME["bg_card"], padx=14, pady=14)
        ethics_container.pack(fill="both", expand=True)

        title = tk.Label(
            ethics_container,
            text="ETHICAL USAGE POLICY & EDUCATIONAL SAFEGUARDS",
            font=(THEME["font_family"], 11, "bold"),
            fg=THEME["cyan"],
            bg=THEME["bg_card"],
        )
        title.pack(anchor="w", pady=(0, 10))

        principles = (
            "1. AUTHORIZED MONITORING ONLY: Packet capture must strictly be executed on networks, "
            "interfaces, and systems you own or have explicit written permission to analyze.\n\n"
            "2. NO CREDENTIAL HARVESTING: This tool intentionally does NOT parse, decode, or extract "
            "cleartext passwords, session cookies, OAuth tokens, or private chat contents.\n\n"
            "3. NO OFFENSIVE ACTIONS: This analyzer operates entirely in passive monitoring mode. "
            "No ARP spoofing, packet injection, session hijacking, or MITM attacks are implemented.\n\n"
            "4. NO TLS/HTTPS DECRYPTION: Encrypted traffic remains fully encrypted; privacy and integrity "
            "of transport encryption are strictly preserved.\n\n"
            "5. LOCAL PROCESSING: All packet statistics, table rows, and PCAP exports remain strictly on "
            "your local machine. No packet data is ever transmitted to external servers.\n\n"
            "6. COMPLIANCE: Designed strictly as an educational task for network security curriculum "
            "and cybersecurity portfolio demonstration."
        )

        txt_notice = tk.Label(
            ethics_container,
            text=principles,
            font=(THEME["font_family"], 9),
            fg=THEME["text_secondary"],
            bg=THEME["bg_card"],
            justify="left",
            wraplength=650,
        )
        txt_notice.pack(anchor="w", fill="x")

    def display_packet(self, packet: AnalyzedPacket) -> None:
        """Update all inspector views with selected packet details."""
        self._current_packet = packet
        self.lbl_selected_id.config(
            text=f"Packet #{packet.packet_id} | {packet.timestamp_formatted}",
            fg=THEME["cyan"],
        )

        # Update metadata grid
        self.meta_labels["proto_val"].config(
            text=packet.protocol,
            fg=get_protocol_color(packet.protocol),
        )
        self.meta_labels["len_val"].config(text=f"{packet.length} bytes")
        self.meta_labels["src_val"].config(text=packet.src_ip)
        self.meta_labels["sport_val"].config(text=str(packet.src_port or "--"))
        self.meta_labels["dst_val"].config(text=packet.dst_ip)
        self.meta_labels["dport_val"].config(text=str(packet.dst_port or "--"))
        self.meta_labels["ttl_val"].config(text=str(packet.ttl if packet.ttl is not None else "--"))
        self.meta_labels["flags_val"].config(
            text=packet.tcp_flags_str or ("None" if packet.protocol == "TCP" else "--"),
            fg=THEME["yellow"] if packet.tcp_flags_str else THEME["text_primary"],
        )

        # Populate Layer Tree
        self.layer_tree.delete(*self.layer_tree.get_children())
        for layer_name in packet.layer_names:
            layer_node = self.layer_tree.insert("", "end", text=f"Layer: {layer_name}", open=True)
            fields = packet.layer_details.get(layer_name, {})
            for field_name, field_val in fields.items():
                self.layer_tree.insert(layer_node, "end", text=str(field_name), values=(str(field_val),))

        # Render Hex / ASCII dump
        self.txt_hexdump.config(state="normal")
        self.txt_hexdump.delete("1.0", "end")

        header = f"{'OFFSET':<7} {'HEXADECIMAL BYTES':<49} {'ASCII':<16}\n"
        divider = "=" * 74 + "\n"
        self.txt_hexdump.insert("end", header)
        self.txt_hexdump.insert("end", divider)

        if packet.hex_dump:
            for offset_str, hex_part, ascii_part in packet.hex_dump:
                line = f"{offset_str}   {hex_part}   |{ascii_part}|\n"
                self.txt_hexdump.insert("end", line)
        else:
            self.txt_hexdump.insert("end", "\n   [No higher-layer payload in this packet frame]\n")

        self.txt_hexdump.config(state="disabled")

    def _render_payload_empty(self) -> None:
        """Initial placeholder when no packet is chosen."""
        self.txt_hexdump.config(state="normal")
        self.txt_hexdump.delete("1.0", "end")
        self.txt_hexdump.insert(
            "end",
            "Select any packet in the table above to inspect its hexadecimal and ASCII payload.\n",
        )
        self.txt_hexdump.config(state="disabled")

    def clear(self) -> None:
        """Clear the inspection panel."""
        self._current_packet = None
        self.lbl_selected_id.config(text="No packet selected", fg=THEME["text_secondary"])
        for lbl in self.meta_labels.values():
            lbl.config(text="--", fg=THEME["text_primary"])
        self.layer_tree.delete(*self.layer_tree.get_children())
        self._render_payload_empty()

