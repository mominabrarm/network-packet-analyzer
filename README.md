# Network Packet Analyzer

**Cybersecurity / Network Security Educational Suite & Real-Time Traffic Inspector**  
*Task-05: Network Packet Analyzer | Internship Project & Portfolio Showcase*

---

## 1. Project Overview

The **Network Packet Analyzer** is a functional, professional-grade desktop application developed in Python with **Scapy**, **Tkinter**, and **Matplotlib**. Designed specifically for cybersecurity students, network security interns, and defensive analysts, it captures, dissects, visualizes, and audits network traffic in real time.

The dashboard features a high-contrast dark cybersecurity aesthetic (`#0a0e17` navy/black with electric cyan and neon blue accents), multithreaded non-blocking capture engine, Wireshark-compatible PCAP export, live statistical metrics, deep multi-layer packet decoding, and embedded traffic analytics.

---

## 2. Key Features

- **Real-Time Packet Capture Engine**:
  - Threaded asynchronous sniffing via Scapy without freezing the GUI.
  - Multi-interface detection (Ethernet, Wi-Fi, Loopback, Virtual adapters) with IP, MAC, and operational status (`[UP]`/`[DOWN]`).
  - Native Berkeley Packet Filter (BPF) capture filtering (e.g. `tcp`, `udp`, `port 53`, `host 192.168.1.1`).
  - Built-in **Demo Traffic Generator** producing realistic Scapy traffic (DNS queries, HTTP GET requests, TLS handshakes, ICMP pings, and ARP requests) for offline evaluation or environments without raw capture drivers.

- **Real-Time Monitoring Table**:
  - Live structured packet table displaying: `No.`, `Time`, `Source IP`, `Destination IP`, `Protocol`, `Length`, and `Summary Info`.
  - Color-coded protocol tags (TCP in sky blue, UDP in orange, ICMP in magenta, DNS in indigo, ARP in gold, HTTP in emerald).
  - Instant text search across IPs, ports, protocol names, flags, and payload contents.
  - Quick protocol dropdown and port filters.
  - Optional smooth auto-scroll to the latest packet.

- **Deep Protocol Dissection & Layer Breakdown**:
  - Ethernet, IPv4, IPv6, TCP, UDP, ICMP, DNS, ARP, HTTP, TLS recognition.
  - Decodes TCP flags bitmask (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`, `ECE`, `CWR`).
  - DNS query name, query type (A, AAAA, MX, CNAME), and answer counts.
  - HTTP method and header extraction based on actual payload content (does not naively guess based only on port 80).
  - Full protocol layer tree hierarchy (`Ethernet` → `IP` → `TCP` → `HTTP`).

- **Safe Hexadecimal & ASCII Payload Inspector**:
  - Wireshark-style 3-column hex dump layout (`Offset` | `Hex Bytes` | `ASCII`).
  - Non-printable characters masked safely with dots (`.`).
  - Safe payload truncation (capped at 512 bytes) with ethical guardrails preventing extraction of sensitive credentials, passwords, or session cookies.

- **Embedded Traffic Analytics**:
  - Live Matplotlib dark charts:
    - **Protocol Distribution**: Donut chart illustrating percentage protocol breakdown.
    - **Transport Split**: Comparative bar chart of TCP vs UDP vs Other traffic.
    - **Traffic Over Time**: Time-series plot of packet throughput (packets/sec).
    - **Top Talkers**: Horizontal bar chart identifying Top 5 active IP addresses.

- **Forensic Export Capabilities**:
  - **CSV Export**: Exports captured packet metadata (timestamps, IPs, ports, protocol, length, TTL, flags, summary).
  - **PCAP Export**: Saves actual captured raw packet frames into standard `.pcap` files ready for Wireshark inspection.

---

## 3. Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Language** | Python 3.10+ (tested on Python 3.12) | Core programming language |
| **Packet Engine** | Scapy 2.8.0 | Raw frame sniffing, dissection, and PCAP writing |
| **GUI Framework** | Tkinter / TTK (`clam` theme) | Modern desktop dashboard layout |
| **Visualizations** | Matplotlib (TkAgg backend) | Embedded real-time traffic charts |
| **System Diagnostics** | `psutil`, `socket`, `ctypes` | Adapter discovery and admin/Npcap verification |
| **Data Export** | Python `csv`, Scapy `wrpcap` | CSV reports and PCAP packet captures |
| **Automated Testing** | Pytest 9.2+ | Unit and integration testing with synthetic packets |

---

## 4. Project Architecture

```
TASK 05 NETWORK PACKET ANALYZER/
│
├── main.py                     # Master bootstrap and dependency check
├── requirements.txt           # Python dependencies
├── README.md                  # Comprehensive documentation
├── .gitignore                 # Version control exclusions
│
├── core/                      # Packet engine and network logic
│   ├── __init__.py
│   ├── network_interface.py   # Adapter discovery and system health diagnostics
│   ├── packet_analyzer.py     # Protocol parsing, layer extraction, safe hex dump
│   ├── packet_capture.py      # Threaded Scapy sniffing and demo traffic generator
│   └── packet_filter.py       # BPF validator and in-memory display filters
│
├── gui/                       # Cybersecurity dark-themed GUI
│   ├── __init__.py
│   ├── dashboard.py           # Main window layout, cards, controls, and event loop
│   ├── packet_table.py        # Real-time Treeview table and search/filter bar
│   ├── packet_details.py      # Protocol inspector, layer tree, and hex viewer
│   └── charts.py              # Matplotlib donut charts, time-series, and top talkers
│
├── utils/                     # Supporting utilities
│   ├── __init__.py
│   ├── export.py              # CSV and Wireshark PCAP export routines
│   └── helpers.py             # Theme palette, hex generator, and sanitizers
│
└── tests/                     # Automated unit test suite
    ├── __init__.py
    ├── test_capture_engine.py  # Thread lifecycle and queue tests
    ├── test_export.py          # CSV and PCAP export verification
    ├── test_gui_launch.py      # GUI initialization and event handling test
    ├── test_packet_analyzer.py # Protocol parsing on synthetic packets
    └── test_packet_filter.py   # BPF validation and display search tests
```

---

## 5. Prerequisites & Installation

### A. Clone or Navigate to the Repository

```bash
cd "C:\Users\Asus\TASK 05 NETWORK PACKET ANALYZER"
```

### B. Install Python Dependencies

Make sure Python 3.10 or higher is installed, then run:

```bash
pip install -r requirements.txt
```

### C. Windows Prerequisites (Npcap Driver)

On Windows, raw live packet capture requires the **Npcap** packet capture driver:

1. Download the Npcap installer from official source: [https://npcap.com/#download](https://npcap.com/#download).
2. During installation, ensure the following option is **checked**:
   - **"Install Npcap in WinPcap API-compatible Mode"**
3. Complete the installation and restart your terminal or PowerShell prompt.

> **Note on Non-Npcap Environments:**  
> If Npcap is not installed or administrator privileges are not available, you can still test every feature of the dashboard using the built-in **"Demo Traffic Generator"** checkbox. It injects authentic, fully structured Scapy packets (TCP, UDP, DNS, HTTP, ICMP, ARP) into the capture pipeline.

---

## 6. How to Run the Application

Launch the application using:

```bash
python main.py
```

### Running with Administrator Privileges (For Live Capture)

To capture live traffic from physical or Wi-Fi network cards on Windows:
1. Open PowerShell or Command Prompt as **Administrator** (*Right-click -> Run as Administrator*).
2. Run `python main.py`.

---

## 7. How to Use the Packet Analyzer

1. **Ethical Agreement**:
   - Upon launching, read the ethical guidelines modal and click **"I Agree & Proceed"**.
2. **Select Adapter**:
   - In the **Interface** dropdown, select your active network card (e.g. `Wi-Fi` or `Ethernet`). Click **⟳ Refresh** if needed.
3. **Configure Capture Filter (Optional)**:
   - Select a preset BPF filter (e.g., `TCP Only`, `Web (HTTP/HTTPS)`, `DNS (Port 53)`) or type a custom filter (e.g., `port 443`).
4. **Start Sniffing**:
   - Click **▶ Start Capture**.
   - If running in an environment without Npcap, check **"Demo Traffic Generator"** to generate live synthetic packets.
5. **Inspect Live Traffic**:
   - Watch packets stream into the table in real time with live protocol statistics updated above.
   - Use the **Search** box, **Protocol** dropdown, or **Port** box to filter the table on the fly.
6. **Dissect a Packet**:
   - Click on any packet row to populate the **Packet Details** inspector below.
   - Switch between **Protocol Breakdown** (layer tree) and **Hex & ASCII Payload** (Wireshark-style 3-column view).
7. **Analyze Traffic Trends**:
   - Switch to the **Traffic Analytics & Charts** tab to view the live Protocol Share donut chart, Transport Split bar chart, Packets/Sec throughput, and Top Talker IP addresses.
8. **Export Data**:
   - Click **Export CSV** to save packet metadata for report documentation.
   - Click **Save PCAP** to save the raw packet capture for analysis in Wireshark.

---

## 8. Automated Unit Testing

The repository includes a suite of 19 automated unit tests verifying the capture engine, analyzer, filters, export routines, and GUI boot sequence using synthetic packets:

```bash
python -m pytest tests -v
```

### Test Suite Summary

- `test_packet_analyzer.py`: Verifies TCP flags, DNS queries, HTTP payloads, ICMP pings, ARP requests, hex formatting, and ASCII sanitization.
- `test_packet_filter.py`: Verifies BPF syntax rules, protocol display filters, IP address filters, port filters, and full-text keyword searches.
- `test_export.py`: Verifies CSV format and PCAP writing using Scapy's `wrpcap`.
- `test_capture_engine.py`: Verifies thread safety, queue processing, packet counting, and simulation traffic generation.
- `test_gui_launch.py`: Tests complete Tkinter dashboard instantiation and graceful shutdown.

---

## 9. Ethical Usage & Security Safeguards

This tool is created strictly for authorized educational purposes and diagnostic network observability:

- **Authorized Monitoring Only**: Capture must only be executed on networks and systems the user owns or is authorized to audit.
- **No Stealth Capture**: Prominent capture indicators (`CAPTURING` / `STOPPED` badges) clearly display the active state.
- **No Credential Harvesting**: The analyzer deliberately does NOT parse, decode, or extract credentials, session cookies, auth tokens, or private messages.
- **No Offensive Capabilities**: Operates in passive monitoring mode only; no ARP spoofing, MITM injection, or session hijacking is implemented.
- **No TLS Decryption**: Encrypted payloads are never decrypted.
- **Local Data Only**: All captured data remains strictly on the local machine and is never transmitted externally.

---

## 10. Limitations & Future Roadmap

### Current Limitations

- Live capture on Windows requires Npcap with WinPcap API compatibility installed.
- High packet rates (>20,000 pkts/s) on gigabit saturated links may saturate Python GIL queue processing (mitigated via batch queue draining).

### Future Roadmap

- Integration with GeoIP databases for geographic origin mapping of remote IPs.
- Protocol decoders for IPv6 neighbor discovery (NDP) and QUIC (HTTP/3).
- TCP stream reassembly view for multi-packet flow inspection.
- Automated anomaly detection for port scanning (SYN flood / ACK scan detection).

---

## 11. License

Developed for cybersecurity education and internship task demonstration. Free for academic and instructional use.

