"""
Unit tests for core.packet_capture (Engine lifecycle, multithreading, and simulation).
"""

import queue
import time
import unittest

from core.packet_capture import PacketCaptureEngine


class TestCaptureEngine(unittest.TestCase):
    """Test PacketCaptureEngine behavior and queue management."""

    def test_engine_lifecycle(self):
        """Test starting and stopping simulation traffic without hanging or memory leaks."""
        pkt_queue = queue.Queue()
        engine = PacketCaptureEngine(packet_queue=pkt_queue)

        self.assertFalse(engine.is_capturing)

        # Start in simulation mode
        started = engine.start_capture(use_simulation=True)
        self.assertTrue(started)
        self.assertTrue(engine.is_capturing)

        # Wait briefly for packets to arrive in queue
        time.sleep(0.4)

        # Verify packets entered queue and engine archive
        self.assertGreater(engine.packet_counter, 0)
        packets = engine.get_packets()
        self.assertGreater(len(packets), 0)
        self.assertGreaterEqual(pkt_queue.qsize(), 1)

        # Stop capture
        engine.stop_capture()
        self.assertFalse(engine.is_capturing)

        # Check stats tracking
        stats = engine.stats
        self.assertEqual(stats["total"], engine.packet_counter)
        self.assertGreaterEqual(stats["total"], 1)

        # Test clear
        engine.clear()
        self.assertEqual(engine.packet_counter, 0)
        self.assertEqual(len(engine.get_packets()), 0)
        self.assertEqual(pkt_queue.qsize(), 0)


if __name__ == "__main__":
    unittest.main()

