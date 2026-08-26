"""Tests for CaptureManager session lifecycle (empty-session discard)."""

import contextlib
import io
import os
import tempfile
import time
import unittest

from simtrace2_pysniff.server.capture import CaptureManager, gsmtap_msg_type
from simtrace2_pysniff.server.database import Database


class TestGsmtapSubtypeMapping(unittest.TestCase):
    def test_custom_line_event_subtypes(self):
        self.assertEqual(gsmtap_msg_type(0x10), 'rst')
        self.assertEqual(gsmtap_msg_type(0x11), 'vcc')

    def test_standard_subtypes(self):
        self.assertEqual(gsmtap_msg_type(0x00), 'tpdu')
        self.assertEqual(gsmtap_msg_type(0x01), 'atr')
        self.assertEqual(gsmtap_msg_type(0x02), 'tpdu')  # PPS combined


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

    def test_capture_gap_message_inserted(self):
        # A 'gap' marker yielded by the backend is stored as a message.
        mgr, db = self._manager(_FakeBackend([
            ('gap', b'', 0),
            ('tpdu', b'\x80\xf2\x00\x00\x00', 0),
        ]))
        sid = mgr.start_session()
        self.assertEqual(mgr.stop_session(), sid)
        msgs = db.get_messages(sid)
        self.assertEqual([m['type'] for m in msgs], ['gap', 'tpdu'])

    def test_direct_sniffer_connected(self):
        from simtrace2_pysniff.server.capture import DirectSniffer

        class _FakeSession:
            connected = True

        sn = DirectSniffer()
        sn._session = _FakeSession()
        self.assertTrue(sn.connected)
        _FakeSession.connected = False
        self.assertFalse(sn.connected)

    def test_device_connected_gsmtap_none(self):
        from simtrace2_pysniff.server.capture import GsmtapListener
        listener = GsmtapListener(bind_port=0)
        self.addCleanup(listener.stop)
        mgr, _ = self._manager(listener)
        self.assertIsNone(mgr.device_connected)


class _FlakyReceiver:
    """Mimics GsmtapReceiver.read_packet, emitting scripted behaviors."""

    def __init__(self, listener, behaviors):
        self._listener = listener
        self._behaviors = list(behaviors)
        self._i = 0

    def read_packet(self):
        b = self._behaviors[self._i]
        self._i += 1
        if b == 'raise_non_sim':
            raise ValueError('Not a GSMTAP SIM packet (type=99)')
        if b == 'raise_short':
            raise ValueError('GSMTAP packet too short: 3 bytes')
        if b == 'none':
            return None, None, 0
        # 'good': return a valid APDU and terminate the loop.
        self._listener._running = False
        return 0x00, b'\x80\xf2\x00\x00\x00', 0

    def close(self):
        pass


class _NullDb:
    def create_session(self, mode):
        return 1

    def count_messages(self, sid):
        return 0

    def delete_session(self, sid):
        pass

    def close_session(self, sid):
        pass

    def insert_message(self, *a, **k):
        raise RuntimeError('db down')


class _OneShotBackend:
    def start(self):
        pass

    def stop(self):
        pass

    def iter_messages(self):
        yield ('tpdu', b'\x80\xf2\x00\x00\x00', 0)


class _RaisingBackend:
    def start(self):
        pass

    def stop(self):
        pass

    def iter_messages(self):
        raise RuntimeError('boom')
        yield  # unreachable


class TestGsmtapListenerRobustness(unittest.TestCase):
    def test_listener_survives_bad_packet(self):
        from simtrace2_pysniff.server.capture import GsmtapListener
        listener = GsmtapListener(bind_port=0)
        listener._receiver.close()  # drop the real socket before swapping
        listener._receiver = _FlakyReceiver(listener, ['raise_non_sim', 'good'])
        listener.start()
        out = list(listener.iter_messages())
        listener.stop()
        self.assertEqual(out, [('tpdu', b'\x80\xf2\x00\x00\x00', 0)])
        self.assertEqual(listener.dropped, 1)

    def test_listener_survives_short_packet(self):
        from simtrace2_pysniff.server.capture import GsmtapListener
        listener = GsmtapListener(bind_port=0)
        listener._receiver.close()  # drop the real socket before swapping
        listener._receiver = _FlakyReceiver(listener, ['raise_short', 'good'])
        listener.start()
        out = list(listener.iter_messages())
        listener.stop()
        self.assertEqual(out, [('tpdu', b'\x80\xf2\x00\x00\x00', 0)])
        self.assertEqual(listener.dropped, 1)


class TestCaptureLoopRobustness(unittest.TestCase):
    def test_capture_loop_survives_insert_error(self):
        mgr = CaptureManager(_OneShotBackend(), _NullDb())
        mgr._session_id = 1
        mgr._start_time = 0.0
        # Must not raise; counters stay untouched on a dropped insert.
        mgr._capture_loop()
        self.assertEqual(mgr._session_id, 1)
        self.assertEqual(mgr._msg_count, 0)

    def test_capture_loop_logs_stop_on_error(self):
        mgr = CaptureManager(_RaisingBackend(), _NullDb())
        mgr._session_id = 7
        mgr._start_time = 0.0
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            mgr._capture_loop()
        self.assertIn('stopped on error', buf.getvalue())
        self.assertIsNone(mgr._session_id)

    def test_capture_heartbeat_and_stop_log(self):
        tmp = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        tmp.close()
        db = Database(tmp.name)
        mgr = CaptureManager(_FakeBackend([('tpdu', b'\x80\xf2\x00\x00\x00', 0)]), db)
        mgr._log_interval = 0.05
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            mgr.start_session()
            time.sleep(0.25)
            mgr.stop_session()
        log = buf.getvalue()
        self.assertIn('Capture started', log)
        self.assertIn('Capture alive', log)
        self.assertIn('messages=1', log)
        self.assertIn('bytes=5', log)
        self.assertIn('Capture stopped', log)
        db._conn.close()
        os.remove(tmp.name)


if __name__ == '__main__':
    unittest.main()
