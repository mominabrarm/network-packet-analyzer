"""
Main Dashboard Window for Network Packet Analyzer.
Integrates live Scapy capture, statistics cards, filterable packet table,
detailed inspector, and traffic analytics into a cybersecurity-themed interface.
"""

import os
import queue
import time
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk
from typing import Optional

from core.network_interface import NetworkInterface, NetworkInterfaceManager
from core.packet_analyzer import AnalyzedPacket
from core.packet_capture import PacketCaptureEngine
from core.packet_filter import BPFValidator
from gui.charts import TrafficAnalyticsPanel
from gui.packet_details import PacketDetailsPanel
from gui.packet_table import PacketTable
from utils.export import export_to_csv, export_to_pcap
from utils.helpers import THEME, format_bytes


class PacketAnalyzerDashboard:
    """
    Complete Desktop Dashboard application for Network Packet Analyzer.
    """

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Network Packet Analyzer | Cybersecurity Educational Suite")
        self.root.geometry("1340x860")
        self.root.minsize(1100, 720)
        self.root.configure(bg=THEME["bg_main"])

        # Packet Queue for thread-safe UI updates
        self.ui_packet_queue: queue.Queue = queue.Queue(maxsize=15000)

        # Core Engines
        self.capture_engine = PacketCaptureEngine(
            packet_queue=self.ui_packet_queue,
            on_error_callback=self._on_engine_error,
        )

        # Interfaces
        self.interfaces = []
        self.selected_interface: Optional[NetworkInterface] = None

        # State tracking
        self.is_capturing = False
        self._last_stats_update = time.time()
        self._batch_buffer = []

        # Configure TTK Styles for Dark Cyber Theme
        self._configure_ttk_styles()

        # Build UI Components
        self._build_header()
        self._build_stats_cards()
        self._build_controls_bar()
        self._build_main_split_view()
        self._build_status_bar()

        # Populate Network Interfaces
        self.refresh_interfaces()

        # Show Ethical Usage Notice Modal
        self.root.after(200, self._show_ethical_dialog_on_start)

        # Start periodic GUI update poll
        self.root.after(50, self._process_packet_queue)
        self.root.after(1000, self._clock_tick)

        # Clean exit on close
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _configure_ttk_styles(self) -> None:
        """Apply modern dark cybersecurity palette to TTK widgets."""
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # Treeview styling
        style.configure(
            "Treeview",
            background=THEME["bg_card"],
            foreground=THEME["text_primary"],
            fieldbackground=THEME["bg_card"],
            font=(THEME["font_mono"], 9),
            rowheight=24,
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background=THEME["bg_header"],
            foreground=THEME["cyan"],
            font=(THEME["font_family"], 9, "bold"),
            relief="flat",
            padding=5,
        )
        style.map(
            "Treeview",
            background=[("selected", THEME["blue"])],
            foreground=[("selected", "#ffffff")],
        )

        # Notebook tabs
        style.configure(
            "TNotebook",
            background=THEME["bg_card"],
            borderwidth=0,
        )
        style.configure(
            "TNotebook.Tab",
            background=THEME["bg_card_alt"],
            foreground=THEME["text_secondary"],
            font=(THEME["font_family"], 9, "bold"),
            padding=[14, 5],
            borderwidth=0,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", THEME["bg_card"])],
            foreground=[("selected", THEME["cyan"])],
        )

        # Combobox
        style.configure(
            "TCombobox",
            fieldbackground=THEME["bg_card_alt"],
            background=THEME["bg_card_alt"],
            foreground=THEME["text_primary"],
            arrowcolor=THEME["cyan"],
            font=(THEME["font_family"], 9),
        )

        # Scrollbars
        style.configure(
            "Vertical.TScrollbar",
            background=THEME["bg_card_alt"],
            troughcolor=THEME["bg_card"],
            arrowcolor=THEME["cyan"],
            borderwidth=0,
        )
        style.configure(
            "Horizontal.TScrollbar",
            background=THEME["bg_card_alt"],
            troughcolor=THEME["bg_card"],
            arrowcolor=THEME["cyan"],
            borderwidth=0,
        )

    def _build_header(self) -> None:
        """Build top application banner and status bar."""
        header = tk.Frame(self.root, bg=THEME["bg_header"], padx=18, pady=10)
        header.pack(fill="x", side="top")

        # Left: Icon & Title
        title_box = tk.Frame(header, bg=THEME["bg_header"])
        title_box.pack(side="left")

        lbl_logo = tk.Label(
            title_box,
            text="[⚡]",
            font=(THEME["font_family"], 18, "bold"),
            fg=THEME["cyan"],
            bg=THEME["bg_header"],
        )
        lbl_logo.pack(side="left", padx=(0, 10))

        text_sub_box = tk.Frame(title_box, bg=THEME["bg_header"])
        text_sub_box.pack(side="left")

        lbl_app_name = tk.Label(
            text_sub_box,
            text="NETWORK PACKET ANALYZER",
            font=(THEME["font_family"], 14, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_header"],
        )
        lbl_app_name.pack(anchor="w")

        lbl_sub = tk.Label(
            text_sub_box,
            text="Real-Time Network Traffic Monitor & Protocol Inspection Suite",
            font=(THEME["font_family"], 8),
            fg=THEME["text_dim"],
            bg=THEME["bg_header"],
        )
        lbl_sub.pack(anchor="w")

        # Right: System status pills & Clock
        status_box = tk.Frame(header, bg=THEME["bg_header"])
        status_box.pack(side="right")

        # Capture status badge
        self.badge_status = tk.Label(
            status_box,
            text="• IDLE / READY",
            font=(THEME["font_family"], 9, "bold"),
            fg=THEME["cyan"],
            bg=THEME["bg_card_alt"],
            padx=10,
            pady=4,
            relief="flat",
        )
        self.badge_status.pack(side="left", padx=6)

        # Environment diagnostics badge
        env = NetworkInterfaceManager.get_environment_status()
        npcap_text = "NPCAP: OK" if env["npcap_installed"] else "NPCAP: MISSING"
        npcap_color = THEME["green"] if env["npcap_installed"] else THEME["yellow"]
        self.badge_npcap = tk.Label(
            status_box,
            text=npcap_text,
            font=(THEME["font_mono"], 8, "bold"),
            fg=npcap_color,
            bg=THEME["bg_card_alt"],
            padx=8,
            pady=4,
        )
        self.badge_npcap.pack(side="left", padx=4)

        admin_text = "ADMIN: YES" if env["is_admin"] else "ADMIN: NO"
        admin_color = THEME["green"] if env["is_admin"] else THEME["text_dim"]
        self.badge_admin = tk.Label(
            status_box,
            text=admin_text,
            font=(THEME["font_mono"], 8, "bold"),
            fg=admin_color,
            bg=THEME["bg_card_alt"],
            padx=8,
            pady=4,
        )
        self.badge_admin.pack(side="left", padx=4)

        # Real-time clock
        self.lbl_clock = tk.Label(
            status_box,
            text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"),
            font=(THEME["font_mono"], 9),
            fg=THEME["text_secondary"],
            bg=THEME["bg_header"],
            padx=8,
        )
        self.lbl_clock.pack(side="left", padx=(10, 0))

    def _build_stats_cards(self) -> None:
        """Build four primary live statistical metric cards."""
        cards_bar = tk.Frame(self.root, bg=THEME["bg_main"], padx=16, pady=8)
        cards_bar.pack(fill="x", side="top")

        # Configure 4 columns
        for col in range(4):
            cards_bar.columnconfigure(col, weight=1)

        self.stat_cards = {}
        card_configs = [
            (0, "TOTAL PACKETS", "0", THEME["cyan"], "All captured traffic frames", "total"),
            (1, "TCP PACKETS", "0 (0%)", THEME["blue"], "Reliable stream connections", "tcp"),
            (2, "UDP PACKETS", "0 (0%)", THEME["yellow"], "Datagrams & DNS traffic", "udp"),
            (3, "OTHER PROTOCOLS", "0 (0%)", THEME["purple"], "ICMP, ARP, and Layer 2/3 frames", "other"),
        ]

        for col, title, initial_val, color, desc, key in card_configs:
            frame = tk.Frame(cards_bar, bg=THEME["bg_card"], padx=14, pady=10, relief="flat", highlightbackground=THEME["border"], highlightthickness=1)
            frame.grid(row=0, column=col, sticky="nsew", padx=5)

            lbl_t = tk.Label(
                frame,
                text=title,
                font=(THEME["font_family"], 8, "bold"),
                fg=THEME["text_dim"],
                bg=THEME["bg_card"],
            )
            lbl_t.pack(anchor="w")

            lbl_v = tk.Label(
                frame,
                text=initial_val,
                font=(THEME["font_mono"], 16, "bold"),
                fg=color,
                bg=THEME["bg_card"],
            )
            lbl_v.pack(anchor="w", pady=(3, 2))

            lbl_d = tk.Label(
                frame,
                text=desc,
                font=(THEME["font_family"], 7),
                fg=THEME["text_secondary"],
                bg=THEME["bg_card"],
            )
            lbl_d.pack(anchor="w")

            self.stat_cards[key] = lbl_v

    def _build_controls_bar(self) -> None:
        """Build Interface selector, BPF capture filter, and capture control buttons."""
        controls_frame = tk.Frame(self.root, bg=THEME["bg_card"], padx=16, pady=8, highlightbackground=THEME["border"], highlightthickness=1)
        controls_frame.pack(fill="x", side="top", padx=16, pady=(0, 8))

        # Interface selection
        lbl_iface = tk.Label(
            controls_frame,
            text="Interface:",
            font=(THEME["font_family"], 9, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_card"],
        )
        lbl_iface.pack(side="left", padx=(0, 6))

        self.var_iface = tk.StringVar()
        self.combo_iface = ttk.Combobox(
            controls_frame,
            textvariable=self.var_iface,
            state="readonly",
            width=32,
            font=(THEME["font_family"], 9),
        )
        self.combo_iface.pack(side="left", padx=(0, 6))
        self.combo_iface.bind("<<ComboboxSelected>>", self._on_interface_selected)

        # Refresh interfaces button
        btn_refresh_iface = tk.Button(
            controls_frame,
            text="⟳ Refresh",
            font=(THEME["font_family"], 8, "bold"),
            bg=THEME["bg_card_alt"],
            fg=THEME["cyan"],
            relief="flat",
            cursor="hand2",
            padx=8,
            pady=3,
            command=self.refresh_interfaces,
        )
        btn_refresh_iface.pack(side="left", padx=(0, 16))

        # Capture BPF Filter Preset Combobox & Entry
        lbl_bpf = tk.Label(
            controls_frame,
            text="BPF Filter:",
            font=(THEME["font_family"], 9, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_card"],
        )
        lbl_bpf.pack(side="left", padx=(0, 6))

        self.var_bpf_preset = tk.StringVar(value="All Traffic")
        presets = list(BPFValidator.COMMON_PRESETS.keys())
        self.combo_bpf = ttk.Combobox(
            controls_frame,
            textvariable=self.var_bpf_preset,
            values=presets,
            state="readonly",
            width=14,
            font=(THEME["font_family"], 9),
        )
        self.combo_bpf.pack(side="left", padx=(0, 6))
        self.combo_bpf.bind("<<ComboboxSelected>>", self._on_bpf_preset_changed)

        self.var_bpf_custom = tk.StringVar()
        self.entry_bpf = tk.Entry(
            controls_frame,
            textvariable=self.var_bpf_custom,
            bg=THEME["bg_card_alt"],
            fg=THEME["text_primary"],
            insertbackground=THEME["cyan"],
            relief="flat",
            font=(THEME["font_mono"], 9),
            width=18,
        )
        self.entry_bpf.pack(side="left", padx=(0, 16), ipady=3)

        # Simulation Mode Checkbox
        self.var_simulate = tk.BooleanVar(value=not NetworkInterfaceManager.check_npcap_installed())
        self.chk_simulate = tk.Checkbutton(
            controls_frame,
            text="Demo Traffic Generator",
            variable=self.var_simulate,
            bg=THEME["bg_card"],
            fg=THEME["yellow"],
            selectcolor=THEME["bg_card_alt"],
            activebackground=THEME["bg_card"],
            activeforeground=THEME["yellow"],
            font=(THEME["font_family"], 9, "bold"),
        )
        self.chk_simulate.pack(side="left", padx=(0, 16))

        # Action Buttons (Start, Stop, Clear, Export CSV, Save PCAP)
        btn_box = tk.Frame(controls_frame, bg=THEME["bg_card"])
        btn_box.pack(side="right")

        self.btn_start = tk.Button(
            btn_box,
            text="▶ Start Capture",
            font=(THEME["font_family"], 9, "bold"),
            bg=THEME["green"],
            fg="#ffffff",
            activebackground="#059669",
            activeforeground="#ffffff",
            relief="flat",
            cursor="hand2",
            padx=12,
            pady=4,
            command=self.start_capture,
        )
        self.btn_start.pack(side="left", padx=3)

        self.btn_stop = tk.Button(
            btn_box,
            text="■ Stop",
            font=(THEME["font_family"], 9, "bold"),
            bg=THEME["red"],
            fg="#ffffff",
            activebackground="#dc2626",
            activeforeground="#ffffff",
            relief="flat",
            cursor="hand2",
            padx=12,
            pady=4,
            state="disabled",
            command=self.stop_capture,
        )
        self.btn_stop.pack(side="left", padx=3)

        self.btn_clear = tk.Button(
            btn_box,
            text="Clear",
            font=(THEME["font_family"], 9, "bold"),
            bg=THEME["bg_card_alt"],
            fg=THEME["text_secondary"],
            activebackground=THEME["border_light"],
            activeforeground="#ffffff",
            relief="flat",
            cursor="hand2",
            padx=10,
            pady=4,
            command=self.clear_packets,
        )
        self.btn_clear.pack(side="left", padx=3)

        self.btn_export_csv = tk.Button(
            btn_box,
            text="Export CSV",
            font=(THEME["font_family"], 9, "bold"),
            bg=THEME["blue"],
            fg="#ffffff",
            activebackground="#2563eb",
            activeforeground="#ffffff",
            relief="flat",
            cursor="hand2",
            padx=10,
            pady=4,
            command=self.export_csv,
        )
        self.btn_export_csv.pack(side="left", padx=3)

        self.btn_export_pcap = tk.Button(
            btn_box,
            text="Save PCAP",
            font=(THEME["font_family"], 9, "bold"),
            bg=THEME["purple"],
            fg="#ffffff",
            activebackground="#9333ea",
            activeforeground="#ffffff",
            relief="flat",
            cursor="hand2",
            padx=10,
            pady=4,
            command=self.export_pcap,
        )
        self.btn_export_pcap.pack(side="left", padx=3)

    def _build_main_split_view(self) -> None:
        """Build upper packet table and lower split notebook (details + charts)."""
        # Outer vertical PanedWindow
        self.paned_window = tk.PanedWindow(
            self.root,
            orient="vertical",
            bg=THEME["bg_main"],
            bd=0,
            sashwidth=4,
            sashrelief="flat",
        )
        self.paned_window.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        # Upper pane: Packet Table
        self.packet_table = PacketTable(
            self.paned_window,
            on_packet_select=self._on_packet_selected,
        )
        self.paned_window.add(self.packet_table, height=360)

        # Lower pane: Details & Analytics Notebook
        self.lower_notebook = ttk.Notebook(self.paned_window)
        self.paned_window.add(self.lower_notebook, height=320)

        # Tab A: Deep Packet Inspector & Hex Dump
        self.packet_details = PacketDetailsPanel(self.lower_notebook)
        self.lower_notebook.add(self.packet_details, text=" Packet Inspector & Hex/ASCII Dump ")

        # Tab B: Traffic Analytics & Charts
        self.charts_panel = TrafficAnalyticsPanel(self.lower_notebook)
        self.lower_notebook.add(self.charts_panel, text=" Traffic Analytics & Charts ")

    def _build_status_bar(self) -> None:
        """Build bottom footer status bar."""
        footer = tk.Frame(self.root, bg=THEME["bg_header"], padx=14, pady=4)
        footer.pack(fill="x", side="bottom")

        self.lbl_footer_status = tk.Label(
            footer,
            text="Ready. Select an interface and click 'Start Capture' or run 'Demo Traffic Generator'.",
            font=(THEME["font_family"], 8),
            fg=THEME["text_secondary"],
            bg=THEME["bg_header"],
        )
        self.lbl_footer_status.pack(side="left")

        self.lbl_footer_rate = tk.Label(
            footer,
            text="Rate: 0.0 pkts/s  |  Memory: In-Memory Archive",
            font=(THEME["font_mono"], 8),
            fg=THEME["cyan"],
            bg=THEME["bg_header"],
        )
        self.lbl_footer_rate.pack(side="right")

    def refresh_interfaces(self) -> None:
        """Scan and populate system network interfaces."""
        try:
            self.interfaces = NetworkInterfaceManager.get_interfaces()
            labels = [iface.get_dropdown_label() for iface in self.interfaces]
            
            if labels:
                self.combo_iface["values"] = labels
                # Select best candidate
                default_iface = NetworkInterfaceManager.get_default_interface()
                if default_iface:
                    idx = self.interfaces.index(default_iface)
                    self.combo_iface.current(idx)
                    self.selected_interface = default_iface
                else:
                    self.combo_iface.current(0)
                    self.selected_interface = self.interfaces[0]
                
                self._update_status_footer(f"Discovered {len(self.interfaces)} network adapters.")
            else:
                self.combo_iface["values"] = ["No Interfaces Detected"]
                self.combo_iface.current(0)
                self.selected_interface = None
                self._update_status_footer("Warning: No network adapters detected on this system.")
        except Exception as e:
            self._update_status_footer(f"Interface scan error: {str(e)}")

    def _on_interface_selected(self, event=None) -> None:
        """Handle selection of network adapter in dropdown."""
        idx = self.combo_iface.current()
        if 0 <= idx < len(self.interfaces):
            self.selected_interface = self.interfaces[idx]
            self._update_status_footer(
                f"Selected Adapter: {self.selected_interface.display_name} "
                f"[{self.selected_interface.primary_ip}]"
            )

    def _on_bpf_preset_changed(self, event=None) -> None:
        """Apply preset BPF filter to custom filter input."""
        preset_name = self.var_bpf_preset.get()
        filter_val = BPFValidator.COMMON_PRESETS.get(preset_name, "")
        self.var_bpf_custom.set(filter_val)

    def start_capture(self) -> None:
        """Start packet sniffing on selected interface."""
        if self.is_capturing:
            return

        is_sim = self.var_simulate.get()
        iface_name = self.selected_interface.name if self.selected_interface else None
        bpf_filter = self.var_bpf_custom.get().strip()

        # Validate BPF syntax
        if bpf_filter:
            valid, err = BPFValidator.validate_bpf(bpf_filter)
            if not valid:
                messagebox.showerror("Capture Filter Error", f"Invalid BPF filter expression:\n\n{err}")
                return

        # Check Npcap on Windows if running live capture
        env = NetworkInterfaceManager.get_environment_status()
        if not is_sim and env["os"] == "Windows" and not env["npcap_installed"]:
            ans = messagebox.askyesno(
                "Npcap Required for Live Capture",
                "Npcap was not detected on this Windows system.\n\n"
                "Live packet capture requires the Npcap driver (https://npcap.com/).\n\n"
                "Would you like to start the capture using the built-in "
                "'Demo Traffic Generator' to inspect realistic live Scapy traffic instead?",
            )
            if ans:
                self.var_simulate.set(True)
                is_sim = True
            else:
                return

        # Start capture engine
        started = self.capture_engine.start_capture(
            interface=iface_name,
            bpf_filter=bpf_filter,
            use_simulation=is_sim,
        )

        if started:
            self.is_capturing = True
            self.btn_start.config(state="disabled", bg=THEME["bg_card_alt"])
            self.btn_stop.config(state="normal", bg=THEME["red"])

            mode_str = "SIMULATED TRAFFIC" if is_sim else f"LIVE ({iface_name})"
            self.badge_status.config(
                text=f"• CAPTURING [{mode_str}]",
                fg="#ffffff",
                bg=THEME["green"],
            )
            self._update_status_footer(f"Capturing packets on {mode_str}... Press Stop to halt.")

    def stop_capture(self) -> None:
        """Stop background capture safely."""
        if not self.is_capturing:
            return

        self.capture_engine.stop_capture()
        self.is_capturing = False

        self.btn_start.config(state="normal", bg=THEME["green"])
        self.btn_stop.config(state="disabled", bg=THEME["bg_card_alt"])

        self.badge_status.config(
            text="• STOPPED",
            fg=THEME["red"],
            bg=THEME["bg_card_alt"],
        )
        self._update_status_footer(f"Capture stopped. {self.capture_engine.packet_counter} total packets collected.")

        # Force final chart update
        self.charts_panel.update_data(self.capture_engine.get_packets(), force=True)

    def clear_packets(self) -> None:
        """Clear table, charts, inspector, and packet buffers."""
        if self.is_capturing:
            ans = messagebox.askyesno("Confirm Clear", "Capture is currently running. Stop capture and clear all packets?")
            if not ans:
                return
            self.stop_capture()

        self.capture_engine.clear()
        self.packet_table.clear()
        self.packet_details.clear()
        self.charts_panel.clear()
        self._batch_buffer.clear()

        for key, lbl in self.stat_cards.items():
            lbl.config(text="0" if key == "total" else "0 (0%)")

        self.badge_status.config(text="• IDLE / READY", fg=THEME["cyan"], bg=THEME["bg_card_alt"])
        self._update_status_footer("Cleared all captured packets and reset dashboard.")

    def export_csv(self) -> None:
        """Prompt user for CSV export file path and save metadata."""
        packets = self.capture_engine.get_packets()
        if not packets:
            messagebox.showwarning("Export CSV", "No captured packets to export. Capture packets first.")
            return

        default_filename = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export Packets to CSV",
            initialfile=default_filename,
            defaultextension=".csv",
            filetypes=[("CSV Files (*.csv)", "*.csv"), ("All Files (*.*)", "*.*")],
        )

        if not filepath:
            return

        res = export_to_csv(packets, filepath)
        if res["success"]:
            messagebox.showinfo("Export Successful", f"Successfully exported {res['count']} packet records to:\n{filepath}")
            self._update_status_footer(f"Exported {res['count']} packets to CSV.")
        else:
            messagebox.showerror("Export Failed", f"Failed to export CSV:\n{res['error']}")

    def export_pcap(self) -> None:
        """Prompt user for PCAP export file path and save raw Scapy frames."""
        raw_packets = self.capture_engine.get_raw_packets()
        if not raw_packets:
            messagebox.showwarning("Save PCAP", "No raw packet frames available to export. Capture packets first.")
            return

        default_filename = f"traffic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        filepath = filedialog.asksaveasfilename(
            parent=self.root,
            title="Save Captured Packets to PCAP",
            initialfile=default_filename,
            defaultextension=".pcap",
            filetypes=[("PCAP Files (*.pcap)", "*.pcap"), ("All Files (*.*)", "*.*")],
        )

        if not filepath:
            return

        res = export_to_pcap(raw_packets, filepath)
        if res["success"]:
            messagebox.showinfo("PCAP Export Successful", f"Saved {res['count']} raw packet frames to:\n{filepath}\n\nReady for inspection in Wireshark.")
            self._update_status_footer(f"Saved {res['count']} packets to PCAP ({os.path.basename(filepath)}).")
        else:
            messagebox.showerror("PCAP Export Failed", f"Failed to save PCAP file:\n{res['error']}")

    def _process_packet_queue(self) -> None:
        """Drain background packet queue and update table in smooth batches."""
        batch = []
        # Pull up to 100 packets per 50ms tick to prevent GUI freeze
        while not self.ui_packet_queue.empty() and len(batch) < 100:
            try:
                pkt = self.ui_packet_queue.get_nowait()
                batch.append(pkt)
            except queue.Empty:
                break

        if batch:
            self.packet_table.append_batch(batch)
            self._update_stats_display()

        # Update charts throttled if new packets arrived
        if batch or (self.is_capturing and time.time() - self._last_stats_update > 1.2):
            self.charts_panel.update_data(self.capture_engine.get_packets(), force=False)
            self._last_stats_update = time.time()

        # Reschedule next queue drain tick
        self.root.after(50, self._process_packet_queue)

    def _update_stats_display(self) -> None:
        """Refresh statistics cards and rate counter."""
        stats = self.capture_engine.stats
        total = stats["total"]
        if total == 0:
            return

        tcp_pct = (stats["tcp"] / total) * 100
        udp_pct = (stats["udp"] / total) * 100
        other_pct = (stats["other"] / total) * 100

        self.stat_cards["total"].config(text=f"{total:,}")
        self.stat_cards["tcp"].config(text=f"{stats['tcp']:,} ({tcp_pct:.1f}%)")
        self.stat_cards["udp"].config(text=f"{stats['udp']:,} ({udp_pct:.1f}%)")
        self.stat_cards["other"].config(text=f"{stats['other']:,} ({other_pct:.1f}%)")

        # Calculate packet rate
        if self.is_capturing and self.capture_engine.capture_start_time:
            elapsed = max(0.1, time.time() - self.capture_engine.capture_start_time)
            rate = total / elapsed
            self.lbl_footer_rate.config(text=f"Rate: {rate:.1f} pkts/s  |  Elapsed: {int(elapsed)}s")

    def _on_packet_selected(self, packet: AnalyzedPacket) -> None:
        """Callback from PacketTable when user clicks a row."""
        self.packet_details.display_packet(packet)

    def _on_engine_error(self, err_msg: str) -> None:
        """Callback from capture thread on critical error."""
        self.root.after(0, lambda: self._handle_engine_error_ui(err_msg))

    def _handle_engine_error_ui(self, err_msg: str) -> None:
        """Thread-safe UI dialog for capture engine errors."""
        self.stop_capture()
        messagebox.showerror("Packet Capture Notification", err_msg)
        self._update_status_footer(f"Error: {err_msg[:60]}...")

    def _show_ethical_dialog_on_start(self) -> None:
        """Display educational ethics agreement on application start."""
        dlg = tk.Toplevel(self.root)
        dlg.title("Ethical Usage Notice | Network Packet Analyzer")
        dlg.geometry("560x360")
        dlg.configure(bg=THEME["bg_card"])
        dlg.transient(self.root)
        dlg.grab_set()

        # Center dialog
        dlg.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - 560) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - 360) // 2
        dlg.geometry(f"+{x}+{y}")

        content = tk.Frame(dlg, bg=THEME["bg_card"], padx=20, pady=16)
        content.pack(fill="both", expand=True)

        lbl_head = tk.Label(
            content,
            text="ETHICAL & AUTHORIZED USE NOTICE",
            font=(THEME["font_family"], 12, "bold"),
            fg=THEME["cyan"],
            bg=THEME["bg_card"],
        )
        lbl_head.pack(anchor="w", pady=(0, 10))

        text_notice = (
            "This software is developed strictly for educational instruction, cybersecurity "
            "internship demonstration, and authorized network diagnostics.\n\n"
            "Key Safeguards:\n"
            "• Monitor ONLY networks and interfaces you own or have explicit authorization to inspect.\n"
            "• Stealth capture, password harvesting, and session sniffing are strictly prevented.\n"
            "• Encrypted TLS/HTTPS payloads are NOT decrypted.\n"
            "• Captured packets remain local to this machine and are never transmitted externally.\n\n"
            "By clicking 'I Agree & Proceed', you confirm you understand and will abide by these principles."
        )

        lbl_body = tk.Label(
            content,
            text=text_notice,
            font=(THEME["font_family"], 9),
            fg=THEME["text_primary"],
            bg=THEME["bg_card"],
            justify="left",
            wraplength=510,
        )
        lbl_body.pack(anchor="w", pady=(0, 16))

        btn_agree = tk.Button(
            content,
            text="I Agree & Proceed",
            font=(THEME["font_family"], 10, "bold"),
            bg=THEME["blue"],
            fg="#ffffff",
            activebackground="#2563eb",
            activeforeground="#ffffff",
            relief="flat",
            cursor="hand2",
            padx=18,
            pady=6,
            command=dlg.destroy,
        )
        btn_agree.pack(anchor="e")

    def _clock_tick(self) -> None:
        """Update top clock once per second."""
        self.lbl_clock.config(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.root.after(1000, self._clock_tick)

    def _update_status_footer(self, message: str) -> None:
        """Update status text in footer."""
        self.lbl_footer_status.config(text=message)

    def _on_close(self) -> None:
        """Safely stop threads before window destruction."""
        if self.is_capturing:
            self.capture_engine.stop_capture()
        self.root.destroy()

