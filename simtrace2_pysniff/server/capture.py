"""Capture backends: GSMTAP listener and direct SIMtrace2 sniffer."""

import time
import threading

from ..gsmtap import (GsmtapReceiver, GSMTAP_SIM_ATR,
                      GSMTAP_SIM_RST_EVENT, GSMTAP_SIM_VCC_EVENT)


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

    def start(self):
        self._running = True

    def stop(self):
        self._running = False
        self._receiver.close()

    def iter_messages(self):
        while self._running:
            sub_type, data, flags = self._receiver.read_packet()
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
    def __init__(self, backend, db):
        self._backend = backend
        self._db = db
        self._session_id = None
        self._thread = None
        self._start_time = 0.0
        self._latest_msg_id = 0

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
        self._backend.start()

        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()

        return self._session_id

    def stop_session(self):
        if self._session_id is None:
            return None
        self._backend.stop()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        sid = self._session_id
        self._session_id = None
        self._start_time = 0.0
        if self._db.count_messages(sid) == 0:
            self._db.delete_session(sid)
            return None
        self._db.close_session(sid)
        return sid

    def _capture_loop(self):
        for msg_type, data, flags in self._backend.iter_messages():
            if self._session_id is None:
                break
            elapsed = round(time.monotonic() - self._start_time, 3)
            mid = self._db.insert_message(self._session_id, elapsed, msg_type, data, flags)
            self._latest_msg_id = mid
