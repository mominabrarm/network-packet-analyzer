"""
Network Packet Analyzer - Master Application Entry Point.
Task 05: Cybersecurity / Network Security Packet Sniffing & Inspection Suite.
"""

import os
import platform
import sys
import tkinter as tk
from tkinter import messagebox

# Enable High-DPI Awareness on Windows for crisp rendering
if platform.system() == "Windows":
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def check_prerequisites() -> bool:
    """Verify essential library imports before launching GUI."""
    missing = []
    try:
        import scapy
    except ImportError:
        missing.append("scapy")

    try:
        import matplotlib
    except ImportError:
        missing.append("matplotlib")

    try:
        import psutil
    except ImportError:
        missing.append("psutil")

    if missing:
        root = tk.Tk()
        root.withdraw()
        msg = (
            f"Missing required Python dependencies: {', '.join(missing)}\n\n"
            "Please install them via pip:\n"
            f"pip install -r requirements.txt"
        )
        messagebox.showerror("Dependency Error", msg)
        root.destroy()
        return False
    return True


def main():
    """Main application bootstrap."""
    if not check_prerequisites():
        sys.exit(1)

    from gui.dashboard import PacketAnalyzerDashboard

    root = tk.Tk()
    app = PacketAnalyzerDashboard(root)
    root.mainloop()


if __name__ == "__main__":
    main()

