"""
Packet Table Component for Network Packet Analyzer.
Displays captured network packets in a cyber-styled, sortable, filterable table.
"""

import tkinter as tk
from tkinter import ttk
from typing import Callable, Dict, List, Optional

from core.packet_analyzer import AnalyzedPacket
from core.packet_filter import PacketFilter
from utils.helpers import THEME, get_protocol_color


class PacketTable(tk.Frame):
    """
    Real-time packet monitoring table using ttk.Treeview with custom dark styling,
    protocol color tagging, and search/filtering controls.
    """

    COLUMNS = (
        ("no", "No.", 60, "center"),
        ("time", "Time", 110, "center"),
        ("src_ip", "Source IP", 140, "w"),
        ("dst_ip", "Destination IP", 140, "w"),
        ("protocol", "Protocol", 90, "center"),
        ("length", "Length", 75, "e"),
        ("info", "Packet Summary Info", 420, "w"),
    )

    def __init__(
        self,
        parent: tk.Widget,
        on_packet_select: Optional[Callable[[AnalyzedPacket], None]] = None,
        **kwargs,
    ):
        super().__init__(parent, bg=THEME["bg_card"], **kwargs)
        self.on_packet_select = on_packet_select

        # Internal state
        self._all_packets: List[AnalyzedPacket] = []
        self._filtered_packets: List[AnalyzedPacket] = []
        self._packet_map: Dict[int, AnalyzedPacket] = {}  # id -> packet
        self._filter = PacketFilter()
        self._autoscroll_enabled = tk.BooleanVar(value=True)

        self._init_ui()

    def _init_ui(self) -> None:
        """Construct filter controls and Treeview table."""
        # Top filter bar
        filter_bar = tk.Frame(self, bg=THEME["bg_card"], padx=10, pady=8)
        filter_bar.pack(fill="x", side="top")

        # Search Query
        lbl_search = tk.Label(
            filter_bar,
            text="Search:",
            font=(THEME["font_family"], 9, "bold"),
            fg=THEME["text_secondary"],
            bg=THEME["bg_card"],
        )
        lbl_search.pack(side="left", padx=(0, 6))

        self.var_search = tk.StringVar()
        self.var_search.trace_add("write", lambda *args: self._on_filter_changed())
        self.entry_search = tk.Entry(
            filter_bar,
            textvariable=self.var_search,
            bg=THEME["bg_card_alt"],
            fg=THEME["text_primary"],
            insertbackground=THEME["cyan"],
            relief="flat",
            font=(THEME["font_family"], 9),
            width=22,
        )
        self.entry_search.pack(side="left", padx=(0, 14), ipady=3)

        # Protocol dropdown
        lbl_proto = tk.Label(
            filter_bar,
            text="Protocol:",
            font=(THEME["font_family"], 9, "bold"),
            fg=THEME["text_secondary"],
            bg=THEME["bg_card"],
        )
        lbl_proto.pack(side="left", padx=(0, 6))

        self.var_proto = tk.StringVar(value="ALL")
        proto_options = ["ALL", "TCP", "UDP", "ICMP", "DNS", "ARP", "HTTP", "OTHER"]
        self.combo_proto = ttk.Combobox(
            filter_bar,
            textvariable=self.var_proto,
            values=proto_options,
            state="readonly",
            width=10,
            font=(THEME["font_family"], 9),
        )
        self.combo_proto.pack(side="left", padx=(0, 14))
        self.combo_proto.bind("<<ComboboxSelected>>", lambda e: self._on_filter_changed())

        # Port entry
        lbl_port = tk.Label(
            filter_bar,
            text="Port:",
            font=(THEME["font_family"], 9, "bold"),
            fg=THEME["text_secondary"],
            bg=THEME["bg_card"],
        )
        lbl_port.pack(side="left", padx=(0, 6))

        self.var_port = tk.StringVar()
        self.var_port.trace_add("write", lambda *args: self._on_filter_changed())
        self.entry_port = tk.Entry(
            filter_bar,
            textvariable=self.var_port,
            bg=THEME["bg_card_alt"],
            fg=THEME["text_primary"],
            insertbackground=THEME["cyan"],
            relief="flat",
            font=(THEME["font_family"], 9),
            width=8,
        )
        self.entry_port.pack(side="left", padx=(0, 14), ipady=3)

        # Clear filters button
        btn_clear_filter = tk.Button(
            filter_bar,
            text="Reset Filter",
            bg=THEME["bg_card_alt"],
            fg=THEME["cyan"],
            activebackground=THEME["border_light"],
            activeforeground="#ffffff",
            relief="flat",
            cursor="hand2",
            font=(THEME["font_family"], 8, "bold"),
            padx=10,
            pady=2,
            command=self.reset_filters,
        )
        btn_clear_filter.pack(side="left", padx=(0, 16))

        # Auto-scroll Checkbox
        chk_autoscroll = tk.Checkbutton(
            filter_bar,
            text="Auto-scroll",
            variable=self._autoscroll_enabled,
            bg=THEME["bg_card"],
            fg=THEME["text_secondary"],
            selectcolor=THEME["bg_card_alt"],
            activebackground=THEME["bg_card"],
            activeforeground=THEME["cyan"],
            font=(THEME["font_family"], 9),
        )
        chk_autoscroll.pack(side="right", padx=(10, 0))

        # Counter Label
        self.lbl_counter = tk.Label(
            filter_bar,
            text="0 packets",
            font=(THEME["font_mono"], 9),
            fg=THEME["cyan"],
            bg=THEME["bg_card"],
        )
        self.lbl_counter.pack(side="right", padx=10)

        # Treeview Table Container
        table_container = tk.Frame(self, bg=THEME["bg_card"])
        table_container.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Scrollbars
        vsb = ttk.Scrollbar(table_container, orient="vertical")
        hsb = ttk.Scrollbar(table_container, orient="horizontal")

        # Treeview
        col_ids = [col[0] for col in self.COLUMNS]
        self.tree = ttk.Treeview(
            table_container,
            columns=col_ids,
            show="headings",
            selectmode="browse",
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set,
        )

        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)

        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        self.tree.pack(side="left", fill="both", expand=True)

        # Configure columns
        for col_id, col_text, col_width, col_align in self.COLUMNS:
            self.tree.heading(col_id, text=col_text, anchor=col_align)
            self.tree.column(
                col_id,
                width=col_width,
                minwidth=col_width // 2,
                anchor=col_align,
            )

        # Bind events
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        # Configure protocol color tags
        self._configure_tree_tags()

    def _configure_tree_tags(self) -> None:
        """Assign distinct high-contrast color tags for each protocol."""
        protocols = ["TCP", "UDP", "ICMP", "DNS", "ARP", "HTTP", "HTTPS", "TLS", "OTHER"]
        for proto in protocols:
            color = get_protocol_color(proto)
            # Alternating subtle row backgrounds with colored foreground
            self.tree.tag_configure(
                proto,
                foreground=color,
                background=THEME["bg_card"],
                font=(THEME["font_mono"], 9),
            )
            self.tree.tag_configure(
                f"{proto}_alt",
                foreground=color,
                background=THEME["bg_card_alt"],
                font=(THEME["font_mono"], 9),
            )

    def append_packet(self, packet: AnalyzedPacket) -> None:
        """Add a single newly captured packet."""
        self._all_packets.append(packet)
        self._packet_map[packet.packet_id] = packet

        if self._filter.matches(packet):
            self._filtered_packets.append(packet)
            self._insert_row(packet)
            self._update_counter_label()

            if self._autoscroll_enabled.get():
                items = self.tree.get_children()
                if items:
                    self.tree.see(items[-1])

    def append_batch(self, packets: List[AnalyzedPacket]) -> None:
        """Batch append packets for smooth high-throughput rendering."""
        if not packets:
            return

        for p in packets:
            self._all_packets.append(p)
            self._packet_map[p.packet_id] = p

        matched = [p for p in packets if self._filter.matches(p)]
        if matched:
            self._filtered_packets.extend(matched)
            for p in matched:
                self._insert_row(p)
            self._update_counter_label()

            if self._autoscroll_enabled.get():
                items = self.tree.get_children()
                if items:
                    self.tree.see(items[-1])

    def _insert_row(self, packet: AnalyzedPacket) -> None:
        """Insert row into treeview with protocol tag."""
        is_even = (len(self.tree.get_children()) % 2 == 0)
        proto_tag = packet.protocol.upper()
        if proto_tag not in ["TCP", "UDP", "ICMP", "DNS", "ARP", "HTTP", "HTTPS", "TLS"]:
            proto_tag = "OTHER"
        tag = proto_tag if is_even else f"{proto_tag}_alt"

        self.tree.insert(
            "",
            "end",
            iid=str(packet.packet_id),
            values=packet.to_table_row(),
            tags=(tag,),
        )

    def _on_filter_changed(self) -> None:
        """Triggered when search query, protocol, or port inputs are edited."""
        # Parse port
        port_val = None
        raw_port = self.var_port.get().strip()
        if raw_port.isdigit():
            port_val = int(raw_port)

        self._filter = PacketFilter(
            protocol=self.var_proto.get(),
            port=port_val,
            search_query=self.var_search.get(),
        )

        self.refresh_table()

    def reset_filters(self) -> None:
        """Clear all active filter inputs."""
        self.var_search.set("")
        self.var_proto.set("ALL")
        self.var_port.set("")
        self._filter = PacketFilter()
        self.refresh_table()

    def refresh_table(self) -> None:
        """Re-evaluate active filter across all packets and rebuild table."""
        self.tree.delete(*self.tree.get_children())
        self._filtered_packets = self._filter.filter_packet_list(self._all_packets)

        for p in self._filtered_packets:
            self._insert_row(p)

        self._update_counter_label()

    def clear(self) -> None:
        """Wipe all packets and clear Treeview."""
        self.tree.delete(*self.tree.get_children())
        self._all_packets.clear()
        self._filtered_packets.clear()
        self._packet_map.clear()
        self._update_counter_label()

    def _update_counter_label(self) -> None:
        """Update count indicator."""
        total = len(self._all_packets)
        filtered = len(self._filtered_packets)
        if self._filter.is_active():
            self.lbl_counter.config(text=f"Showing {filtered} of {total} packets")
        else:
            self.lbl_counter.config(text=f"Total: {total} packets")

    def _on_tree_select(self, event) -> None:
        """Handle row click in treeview."""
        selected = self.tree.selection()
        if not selected:
            return
        item_id = selected[0]
        try:
            packet_id = int(item_id)
            packet = self._packet_map.get(packet_id)
            if packet and self.on_packet_select:
                self.on_packet_select(packet)
        except ValueError:
            pass

