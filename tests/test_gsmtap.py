"""Tests for GSMTAP receiver shutdown behavior."""

import unittest

from simtrace2_pysniff.gsmtap import GsmtapReceiver


class TestGsmtapReceiver(unittest.TestCase):
    def test_read_after_close_returns_none(self):
        r = GsmtapReceiver(bind_port=0)
        r.close()
        self.assertEqual(r.read_packet(), (None, None, 0))


if __name__ == '__main__':
    unittest.main()
