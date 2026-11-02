"""
Automated launch test for Tkinter GUI.
Initializes PacketAnalyzerDashboard, triggers basic events, processes queue, and exits cleanly.
"""

import sys
import tkinter as tk
import unittest

from gui.dashboard import PacketAnalyzerDashboard


class TestGUILaunch(unittest.TestCase):
    """Test desktop UI initialization and graceful shutdown."""

    def test_gui_instantiation(self):
        root = tk.Tk()
        root.withdraw()  # Hide window during automated test
        app = PacketAnalyzerDashboard(root)

        # Verify components initialized
        self.assertIsNotNone(app.packet_table)
        self.assertIsNotNone(app.packet_details)
        self.assertIsNotNone(app.charts_panel)
        self.assertIsNotNone(app.capture_engine)

        # Trigger simulated capture briefly
        app.var_simulate.set(True)
        app.start_capture()
        self.assertTrue(app.is_capturing)

        # Let Tkinter process events and packets
        for _ in range(15):
            root.update_idletasks()
            root.update()

        # Stop capture
        app.stop_capture()
        self.assertFalse(app.is_capturing)

        # Destroy window
        root.destroy()


if __name__ == "__main__":
    unittest.main()

