"""Capture backends: GSMTAP listener and direct SIMtrace2 sniffer."""

import struct
import sys
import threading
import time
import traceback

from ..gsmtap import (GsmtapReceiver, GSMTAP_SIM_ATR,
                      GSMTAP_SIM_RST_EVENT, GSMTAP_SIM_VCC_EVENT)


def _ts():
    """Local-time stamp for server-side capture log lines."""
    return time.strftime('%Y-%m-%d %H:%M:%S')


def _log(msg):
    print(f'[{_ts()}] {msg}', file=sys.stderr)


def gsmtap_msg_type(sub_type):
    """Map a GSMTAP-SIM sub_type to a stored message type.

    Custom sigrok-iso7816-stream line events (0x10/0x11) become 'rst'/'vcc';
    everything except ATR defaults to 'tpdu'.
    """
    return {
        GSMTAP_SIM_ATR: 'atr',
        GSMTAP_SIM_RST_EVENT: 'rst',
        GSMTAP_SIM_VCC_EVENT: 'vcc',
    }.get(sub_type, 'tpdu')


class GsmtapListener:
    def __init__(self, bind_port=4729):
        self._receiver = GsmtapReceiver(bind_port=bind_port)
        self._running = False
        self._dropped = 0

    def start(self):
        self._running = True
        self._dropped = 0

    def stop(self):
        self._running = False
        self._receiver.close()

    @property
    def dropped(self):
        return self._dropped

    def iter_messages(self):
        while self._running:
            try:
                sub_type, data, flags = self._receiver.read_packet()
            except (ValueError, struct.error) as e:
                # A malformed or non-SIM GSMTAP datagram (a different
                # GSMTAP packet type, a truncated frame, …) must not kill
                # the whole capture — drop it and keep listening.
                self._dropped += 1
                if self._dropped <= 1 or self._dropped % 100 == 0:
                    _log(f'GSMTAP: dropped packet ({self._dropped}): {e}')
                continue
            if sub_type is None:
                continue
            yield gsmtap_msg_type(sub_type), data, flags


class DirectSniffer:
    def __init__(self):
        from ..device import SniffSession
        self._session = SniffSession(
            reconnect=True,
            reconnect_delay_min=1.0,
            reconnect_delay_max=10.0,
            inactivity_timeout=0.0,
        )
        self._running = False

    @property
    def connected(self):
        """True while the USB sniffer device is open."""
        return self._session.connected

    def start(self):
        self._running = True

    def stop(self):
        self._running = False
        self._session.close()

    def iter_messages(self):
        from ..device import DeviceDisconnected
        try:
            for msg in self._session.iter_messages():
                if not self._running:
                    break
                yield msg.type, msg.data, msg.flags
        except DeviceDisconnected:
            return


class CaptureManager:
    def __init__(self, backend, db, log_interval=60.0):
        self._backend = backend
        self._db = db
        self._session_id = None
        self._thread = None
        self._log_thread = None
        self._stop_event = threading.Event()
        self._start_time = 0.0
        self._latest_msg_id = 0
        self._msg_count = 0
        self._byte_count = 0
        self._log_interval = log_interval

    @property
    def active(self):
        return self._session_id is not None

    @property
    def session_id(self):
        return self._session_id

    @property
    def start_time(self):
        return self._start_time

    @property
    def latest_msg_id(self):
        return self._latest_msg_id

    @property
    def device_connected(self):
        """True while the capture device is connected, or None when the
        backend has no device concept (gsmtap)."""
        if isinstance(self._backend, DirectSniffer):
            return self._backend.connected
        return None

    def start_session(self):
        if self._session_id is not None:
            self.stop_session()

        mode = 'gsmtap' if isinstance(self._backend, GsmtapListener) else 'direct'
        self._session_id = self._db.create_session(mode)
        self._start_time = time.monotonic()
        self._latest_msg_id = 0
        self._msg_count = 0
        self._byte_count = 0
        self._backend.start()

        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()

        self._stop_event.clear()
        _log(f'Capture started (mode={mode}, session={self._session_id})')
        self._log_thread = threading.Thread(target=self._log_loop, daemon=True)
        self._log_thread.start()

        return self._session_id

    def stop_session(self):
        if self._session_id is None:
            return None
        self._stop_event.set()
        self._backend.stop()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        if self._log_thread is not None:
            self._log_thread.join(timeout=2.0)
        sid = self._session_id
        self._session_id = None
        self._start_time = 0.0
        empty = self._db.count_messages(sid) == 0
        if empty:
            self._db.delete_session(sid)
            _log(f'Capture stopped: empty session discarded (session={sid})')
            return None
        self._db.close_session(sid)
        _log(f'Capture stopped: session={sid} messages={self._msg_count} '
             f'bytes={self._byte_count}')
        return sid

    def _capture_loop(self):
        try:
            for msg_type, data, flags in self._backend.iter_messages():
                if self._session_id is None:
                    break
                try:
                    elapsed = round(time.monotonic() - self._start_time, 3)
                    mid = self._db.insert_message(
                        self._session_id, elapsed, msg_type, data, flags)
                    self._msg_count += 1
                    self._byte_count += len(data)
                    self._latest_msg_id = mid
                except Exception as e:
                    _log(f'Capture: insert error, dropping msg: {e}')
                    continue
        except Exception:
            # The capture thread died unexpectedly (not a user stop).
            sid = self._session_id
            _log(f'ERROR: capture thread stopped on error (session={sid}):')
            traceback.print_exc()
            self._stop_event.set()
            if sid is not None:
                try:
                    self._db.close_session(sid)
                except Exception:
                    pass
                self._session_id = None
            return

    def _log_loop(self):
        while not self._stop_event.wait(self._log_interval):
            if self._session_id is None:
                break
            dropped = getattr(self._backend, 'dropped', 0)
            _log(f'Capture alive: session={self._session_id} '
                 f'messages={self._msg_count} bytes={self._byte_count} '
                 f'dropped={dropped}')
