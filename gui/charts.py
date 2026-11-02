"""
Traffic Analytics Charts for Network Packet Analyzer.
Embeds Matplotlib charts into Tkinter with a dark cyber theme:
- Protocol Distribution (Donut chart)
- Traffic Over Time (Line chart)
- TCP vs UDP Comparison (Bar chart)
- Top Source & Destination IP Addresses (Horizontal Bar charts)
"""

import tkinter as tk
from tkinter import ttk
from collections import Counter
from typing import Dict, List, Optional
import time

import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from core.packet_analyzer import AnalyzedPacket
from utils.helpers import PROTOCOL_COLORS, THEME


class TrafficAnalyticsPanel(tk.Frame):
    """
    Embedded analytics panel presenting real-time statistical graphs
    for captured network packets.
    """

    def __init__(self, parent: tk.Widget, **kwargs):
        super().__init__(parent, bg=THEME["bg_card"], **kwargs)

        self._packets: List[AnalyzedPacket] = []
        self._time_buckets: Dict[int, int] = {}  # second timestamp -> count
        self._last_draw_time = 0.0

        self._init_ui()

    def _init_ui(self) -> None:
        """Create tabs and embedded figures."""
        # Header bar
        header_bar = tk.Frame(self, bg=THEME["bg_card_alt"], padx=12, pady=6)
        header_bar.pack(fill="x", side="top")

        lbl_title = tk.Label(
            header_bar,
            text="NETWORK TRAFFIC ANALYTICS",
            font=(THEME["font_family"], 9, "bold"),
            fg=THEME["cyan"],
            bg=THEME["bg_card_alt"],
        )
        lbl_title.pack(side="left")

        # Tabbed Charts
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=6, pady=6)

        # Tab 1: Protocols & Transport Split
        self.tab_protocols = tk.Frame(self.notebook, bg=THEME["bg_card"])
        self.notebook.add(self.tab_protocols, text=" Protocol Breakdown ")

        # Tab 2: Traffic History & Top Talkers
        self.tab_traffic = tk.Frame(self.notebook, bg=THEME["bg_card"])
        self.notebook.add(self.tab_traffic, text=" Traffic Over Time & Top IPs ")

        self._init_protocol_figure()
        self._init_traffic_figure()

    def _init_protocol_figure(self) -> None:
        """Initialize Figure for Protocol Pie and Transport Bar."""
        self.fig_proto = Figure(figsize=(7, 3.2), dpi=100, facecolor=THEME["bg_card"])
        
        # 1x2 Subplots: Protocol Pie & TCP vs UDP
        self.ax_pie = self.fig_proto.add_subplot(1, 2, 1)
        self.ax_bar = self.fig_proto.add_subplot(1, 2, 2)
        
        self.fig_proto.subplots_adjust(left=0.08, right=0.95, top=0.88, bottom=0.18, wspace=0.35)

        self.canvas_proto = FigureCanvasTkAgg(self.fig_proto, master=self.tab_protocols)
        self.canvas_proto.get_tk_widget().pack(fill="both", expand=True)

        self._draw_empty_proto()

    def _init_traffic_figure(self) -> None:
        """Initialize Figure for Time series and Top IP addresses."""
        self.fig_traffic = Figure(figsize=(7, 3.2), dpi=100, facecolor=THEME["bg_card"])

        # 1x2 Subplots: Time series & Top Talkers
        self.ax_time = self.fig_traffic.add_subplot(1, 2, 1)
        self.ax_ips = self.fig_traffic.add_subplot(1, 2, 2)

        self.fig_traffic.subplots_adjust(left=0.12, right=0.95, top=0.88, bottom=0.20, wspace=0.35)

        self.canvas_traffic = FigureCanvasTkAgg(self.fig_traffic, master=self.tab_traffic)
        self.canvas_traffic.get_tk_widget().pack(fill="both", expand=True)

        self._draw_empty_traffic()

    def _draw_empty_proto(self) -> None:
        """Render placeholder state when no packets exist."""
        self.ax_pie.clear()
        self.ax_bar.clear()

        for ax in (self.ax_pie, self.ax_bar):
            ax.set_facecolor(THEME["bg_card"])
            ax.tick_params(colors=THEME["text_dim"])
            for spine in ax.spines.values():
                spine.set_color(THEME["border"])

        self.ax_pie.text(
            0.5, 0.5, "Waiting for packets...",
            ha="center", va="center", color=THEME["text_dim"],
            fontsize=10, transform=self.ax_pie.transAxes
        )
        self.ax_pie.set_title("Protocol Share", color=THEME["text_primary"], fontsize=10, fontweight="bold")

        self.ax_bar.text(
            0.5, 0.5, "Waiting for packets...",
            ha="center", va="center", color=THEME["text_dim"],
            fontsize=10, transform=self.ax_bar.transAxes
        )
        self.ax_bar.set_title("Transport Split", color=THEME["text_primary"], fontsize=10, fontweight="bold")

        self.canvas_proto.draw_idle()

    def _draw_empty_traffic(self) -> None:
        """Render placeholder for traffic history."""
        self.ax_time.clear()
        self.ax_ips.clear()

        for ax in (self.ax_time, self.ax_ips):
            ax.set_facecolor(THEME["bg_card"])
            ax.tick_params(colors=THEME["text_dim"])
            for spine in ax.spines.values():
                spine.set_color(THEME["border"])

        self.ax_time.text(
            0.5, 0.5, "Waiting for packets...",
            ha="center", va="center", color=THEME["text_dim"],
            fontsize=10, transform=self.ax_time.transAxes
        )
        self.ax_time.set_title("Packets / Sec Over Time", color=THEME["text_primary"], fontsize=10, fontweight="bold")

        self.ax_ips.text(
            0.5, 0.5, "Waiting for packets...",
            ha="center", va="center", color=THEME["text_dim"],
            fontsize=10, transform=self.ax_ips.transAxes
        )
        self.ax_ips.set_title("Top 5 IP Addresses", color=THEME["text_primary"], fontsize=10, fontweight="bold")

        self.canvas_traffic.draw_idle()

    def update_data(self, packets: List[AnalyzedPacket], force: bool = False) -> None:
        """
        Refresh charts with captured packet list.
        Throttled to max 1 update every 1.2 seconds unless forced.
        """
        now = time.time()
        if not force and (now - self._last_draw_time < 1.2):
            return

        self._last_draw_time = now
        self._packets = packets

        if not packets:
            self._draw_empty_proto()
            self._draw_empty_traffic()
            return

        try:
            self._update_protocol_charts()
            self._update_traffic_charts()
        except Exception:
            pass

    def _update_protocol_charts(self) -> None:
        """Re-draw Protocol Donut chart and TCP vs UDP bar chart."""
        self.ax_pie.clear()
        self.ax_bar.clear()

        self.ax_pie.set_facecolor(THEME["bg_card"])
        self.ax_bar.set_facecolor(THEME["bg_card"])

        for spine in self.ax_pie.spines.values():
            spine.set_visible(False)
        for spine in self.ax_bar.spines.values():
            spine.set_color(THEME["border"])

        # Count protocols
        proto_counts = Counter(p.protocol for p in self._packets)
        if proto_counts:
            labels = list(proto_counts.keys())
            values = list(proto_counts.values())
            colors = [PROTOCOL_COLORS.get(l, PROTOCOL_COLORS["OTHER"]) for l in labels]

            # Donut chart
            wedges, texts, autotexts = self.ax_pie.pie(
                values,
                labels=None,
                autopct=lambda pct: f"{pct:.1f}%" if pct > 5 else "",
                startangle=140,
                colors=colors,
                wedgeprops=dict(width=0.45, edgecolor=THEME["bg_card"], linewidth=1.5),
            )
            for at in autotexts:
                at.set_color("#ffffff")
                at.set_fontsize(8)
                at.set_weight("bold")

            # Center text
            self.ax_pie.text(
                0, 0, f"{len(self._packets)}\nTotal",
                ha="center", va="center", color=THEME["cyan"],
                fontsize=9, fontweight="bold"
            )
            self.ax_pie.legend(
                labels,
                loc="upper right",
                bbox_to_anchor=(1.25, 1.0),
                fontsize=7,
                facecolor=THEME["bg_card_alt"],
                edgecolor=THEME["border"],
                labelcolor=THEME["text_primary"],
            )

        self.ax_pie.set_title("Protocol Share", color=THEME["text_primary"], fontsize=10, fontweight="bold")

        # Transport Bar Chart (TCP vs UDP vs Other)
        tcp_count = sum(1 for p in self._packets if p.protocol in ("TCP", "HTTP", "HTTPS", "TLS"))
        udp_count = sum(1 for p in self._packets if p.protocol in ("UDP", "DNS"))
        other_count = len(self._packets) - tcp_count - udp_count

        categories = ["TCP", "UDP", "Other"]
        counts = [tcp_count, udp_count, max(0, other_count)]
        bar_colors = [THEME["cyan"], THEME["yellow"], THEME["purple"]]

        bars = self.ax_bar.bar(categories, counts, color=bar_colors, width=0.55, edgecolor=THEME["border"])
        self.ax_bar.tick_params(colors=THEME["text_secondary"], labelsize=8)
        self.ax_bar.set_title("Transport Split", color=THEME["text_primary"], fontsize=10, fontweight="bold")
        self.ax_bar.grid(axis="y", linestyle="--", alpha=0.2, color=THEME["border_light"])

        # Value annotations
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                self.ax_bar.annotate(
                    f"{height}",
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 2),
                    textcoords="offset points",
                    ha="center", va="bottom",
                    color=THEME["text_primary"],
                    fontsize=8,
                    fontweight="bold",
                )

        self.canvas_proto.draw_idle()

    def _update_traffic_charts(self) -> None:
        """Re-draw Traffic Over Time and Top IP Addresses."""
        self.ax_time.clear()
        self.ax_ips.clear()

        self.ax_time.set_facecolor(THEME["bg_card"])
        self.ax_ips.set_facecolor(THEME["bg_card"])

        for spine in self.ax_time.spines.values():
            spine.set_color(THEME["border"])
        for spine in self.ax_ips.spines.values():
            spine.set_color(THEME["border"])

        # Traffic over time (aggregate into 1-second buckets)
        time_counts = Counter(int(p.timestamp) for p in self._packets)
        if time_counts:
            sorted_times = sorted(time_counts.keys())
            # Keep last 30 seconds
            if len(sorted_times) > 30:
                sorted_times = sorted_times[-30:]
            
            relative_x = [t - sorted_times[0] for t in sorted_times]
            y_counts = [time_counts[t] for t in sorted_times]

            self.ax_time.plot(
                relative_x, y_counts,
                color=THEME["cyan"],
                linewidth=2,
                marker="o",
                markersize=4,
                markerfacecolor=THEME["blue"],
            )
            self.ax_time.fill_between(relative_x, y_counts, color=THEME["cyan"], alpha=0.15)
            self.ax_time.set_xlabel("Time (s)", color=THEME["text_dim"], fontsize=8)
            self.ax_time.set_ylabel("Packets / s", color=THEME["text_dim"], fontsize=8)

        self.ax_time.tick_params(colors=THEME["text_secondary"], labelsize=8)
        self.ax_time.set_title("Packets / Sec Over Time", color=THEME["text_primary"], fontsize=10, fontweight="bold")
        self.ax_time.grid(linestyle="--", alpha=0.2, color=THEME["border_light"])

        # Top 5 IP Talkers
        ip_counts = Counter()
        for p in self._packets:
            if p.src_ip and p.src_ip != "Unknown":
                ip_counts[p.src_ip] += 1
            if p.dst_ip and p.dst_ip != "Unknown":
                ip_counts[p.dst_ip] += 1

        top_5 = ip_counts.most_common(5)
        if top_5:
            ips = [item[0] for item in reversed(top_5)]
            counts = [item[1] for item in reversed(top_5)]
            bars = self.ax_ips.barh(ips, counts, color=THEME["blue"], height=0.55, edgecolor=THEME["border"])
            
            for bar in bars:
                w = bar.get_width()
                self.ax_ips.annotate(
                    f" {w}",
                    xy=(w, bar.get_y() + bar.get_height() / 2),
                    va="center",
                    color=THEME["text_primary"],
                    fontsize=8,
                    fontweight="bold",
                )

        self.ax_ips.tick_params(colors=THEME["text_secondary"], labelsize=8)
        self.ax_ips.set_title("Top 5 Active IP Addresses", color=THEME["text_primary"], fontsize=10, fontweight="bold")
        self.ax_ips.grid(axis="x", linestyle="--", alpha=0.2, color=THEME["border_light"])

        self.canvas_traffic.draw_idle()

    def clear(self) -> None:
        """Reset charts."""
        self._packets.clear()
        self._time_buckets.clear()
        self._draw_empty_proto()
        self._draw_empty_traffic()

