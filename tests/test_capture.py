"""Tests for CaptureManager session lifecycle (empty-session discard)."""

import os
import tempfile
import unittest

from simtrace2_pysniff.server.capture import CaptureManager
from simtrace2_pysniff.server.database import Database


class _FakeBackend:
    def __init__(self, messages=()):
        self._messages = list(messages)

    def start(self):
        pass

    def stop(self):
        pass

    def iter_messages(self):
        yield from self._messages


class _DisconnectingSession:
    def iter_messages(self):
        from simtrace2_pysniff.device import DeviceDisconnected
        raise DeviceDisconnected('disconnected')
        yield


class TestCaptureManager(unittest.TestCase):
    def _manager(self, backend):
        tmp = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        tmp.close()
        db = Database(tmp.name)
        self.addCleanup(lambda: (db._conn.close(), os.remove(tmp.name)))
        return CaptureManager(backend, db), db

    def test_empty_capture_discarded(self):
        mgr, db = self._manager(_FakeBackend())
        sid = mgr.start_session()
        self.assertIsNotNone(sid)
        self.assertIsNone(mgr.stop_session())
        self.assertIsNone(db.get_session(sid))

    def test_non_empty_capture_kept(self):
        mgr, db = self._manager(_FakeBackend([('tpdu', b'\x80\xf2\x00\x00\x00', 0)]))
        sid = mgr.start_session()
        self.assertEqual(mgr.stop_session(), sid)
        self.assertIsNotNone(db.get_session(sid))
        self.assertEqual(db.count_messages(sid), 1)

    def test_direct_sniffer_device_disconnect(self):
        from simtrace2_pysniff.server.capture import DirectSniffer
        sn = DirectSniffer()
        sn._session = _DisconnectingSession()
        self.assertEqual(list(sn.iter_messages()), [])


if __name__ == '__main__':
    unittest.main()
