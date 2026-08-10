"""USB device discovery and sniffing session with auto-reconnect."""

import os
import sys
import time
import usb.core
import usb.util

USB_VENDOR_OPENMOKO = 0x1d50
USB_CLASS_PROPRIETARY = 0xff
SIMTRACE_SNIFFER_USB_SUBCLASS = 1

FATAL_USB_ERRNOS = {
    2,   # ENOENT
    5,   # EIO (some platforms)
    19,  # ENODEV (Linux)
    32,  # EPIPE / ESHUTDOWN (some platforms)
    108, # ESHUTDOWN (Linux)
}


class DeviceDisconnected(Exception):
    """Raised when the USB device disappears or becomes unresponsive."""
    pass


def _is_fatal_usb_error(err):
    if isinstance(err, usb.core.USBError):
        if hasattr(err, 'errno') and err.errno is not None:
            return err.errno in FATAL_USB_ERRNOS
        if err.strerror and ('device' in err.strerror.lower() or
                             'disconnect' in err.strerror.lower()):
            return True
    return False


def _usb_error_str(err):
    if isinstance(err, usb.core.USBError):
        return f'USBError(errno={getattr(err, "errno", "N/A")}, strerror={err.strerror})'
    return str(err)


def find_sniffer_device(vendor_id=USB_VENDOR_OPENMOKO):
    """Find a SIMtrace2 device running sniffer firmware.

    Returns a ``usb.core.Device`` on success, or ``None``.
    """
    devices = list(usb.core.find(
        find_all=True,
        idVendor=vendor_id,
        custom_match=lambda d: (
            True
        ),
    ))

    for dev in devices:
        for cfg in dev:
            for intf in cfg:
                cls = intf.bInterfaceClass
                sub = intf.bInterfaceSubClass
                if cls == USB_CLASS_PROPRIETARY and sub == SIMTRACE_SNIFFER_USB_SUBCLASS:
                    return dev
    return None


def _get_ep_addrs(dev):
    """Return (ep_out, ep_in, ep_irq) addresses from the active config."""
    cfg = dev.get_active_configuration()
    for intf in cfg:
        if (intf.bInterfaceClass == USB_CLASS_PROPRIETARY and
                intf.bInterfaceSubClass == SIMTRACE_SNIFFER_USB_SUBCLASS):
            for ep in intf:
                addr = ep.bEndpointAddress
                if addr & 0x80:  # IN endpoint
                    return addr
    return None


class SniffSession:
    """Manages a SIMtrace2 sniffer USB connection with auto-reconnect.

    Usage::

        session = SniffSession(
            inactivity_timeout=10.0,
            reconnect_delay_min=1.0,
            reconnect_delay_max=30.0,
        )
        try:
            for msg in session.iter_messages():
                print(f"{msg.type}: {msg.data.hex()}")
        except KeyboardInterrupt:
            pass
        finally:
            session.close()
    """

    def __init__(self, *,
                 reconnect=True,
                 reconnect_delay_min=1.0,
                 reconnect_delay_max=30.0,
                 backoff_factor=1.5,
                 inactivity_timeout=0.0):
        self._reconnect = reconnect
        self._reconnect_delay_min = reconnect_delay_min
        self._reconnect_delay_max = reconnect_delay_max
        self._backoff_factor = backoff_factor
        self._inactivity_timeout = inactivity_timeout

        self._dev = None
        self._devh = None
        self._ep_in = None
        self._last_msg_time = 0.0
        self._disconnect_count = 0

    def _ensure_connected(self):
        """Find, open, and claim the sniffer device.

        Raises DeviceDisconnected if no device found or open fails.
        """
        if self._devh is not None:
            return

        dev = find_sniffer_device()
        if dev is None:
            raise DeviceDisconnected('No SIMtrace2 sniffer device found')

        try:
            if dev.is_kernel_driver_active(0):
                dev.detach_kernel_driver(0)
        except (usb.core.USBError, NotImplementedError):
            pass

        try:
            devh = dev
            devh.set_configuration()
            usb.util.claim_interface(devh, 0)
        except usb.core.USBError as e:
            raise DeviceDisconnected(
                f'Failed to open/claim device: {_usb_error_str(e)}') from e

        ep_in = _get_ep_addrs(devh)
        if ep_in is None:
            usb.util.release_interface(devh, 0)
            raise DeviceDisconnected('No BULK IN endpoint found on sniffer interface')

        self._dev = dev
        self._devh = devh
        self._ep_in = ep_in
        self._last_msg_time = time.monotonic()
        self._disconnect_count = 0

        print(f'Connected to SIMtrace2 sniffer (EP IN 0x{ep_in:02x})',
              file=sys.stderr)

    def _close(self):
        """Release USB resources gracefully."""
        if self._devh is not None:
            try:
                usb.util.release_interface(self._devh, 0)
            except Exception:
                pass
            try:
                usb.util.dispose_resources(self._devh)
            except Exception:
                pass
        self._devh = None
        self._dev = None
        self._ep_in = None

    def _backoff_wait(self):
        """Sleep with exponential backoff before reconnecting."""
        delay = self._reconnect_delay_min * (self._backoff_factor ** self._disconnect_count)
        delay = min(delay, self._reconnect_delay_max)
        self._disconnect_count += 1

        print(f'Disconnected — retrying in {delay:.1f}s '
              f'(attempt {self._disconnect_count})',
              file=sys.stderr)
        time.sleep(delay)

    def _read_loop(self):
        """Inner read loop. Yields SniffMessages. Raises DeviceDisconnected on error."""
        from .protocol import parse_message

        buf = bytearray()
        max_buf = 1024 * 1024  # 1 MB

        while True:
            try:
                chunk = self._devh.read(
                    self._ep_in, 65536, timeout=1000)
                chunk = bytes(chunk)
            except usb.core.USBTimeoutError:
                self._check_inactivity()
                continue
            except usb.core.USBError as e:
                if _is_fatal_usb_error(e):
                    raise DeviceDisconnected(
                        f'USB read error: {_usb_error_str(e)}') from e
                print(f'Transient USB error: {_usb_error_str(e)}',
                      file=sys.stderr)
                time.sleep(0.1)
                continue
            except Exception as e:
                print(f'Unexpected read error: {e}', file=sys.stderr)
                time.sleep(0.1)
                continue

            if not chunk:
                self._check_inactivity()
                continue

            self._last_msg_time = time.monotonic()
            buf.extend(chunk)

            if len(buf) > max_buf:
                print(f'Buffer overflow ({len(buf)} > {max_buf}), '
                      f'discarding oldest data', file=sys.stderr)
                buf = buf[-max_buf // 2:]

            while True:
                msg, consumed = parse_message(buf, timestamp=time.time())
                if msg is not None:
                    yield msg
                if consumed <= 0 or consumed > len(buf):
                    break
                buf = buf[consumed:]

    def _check_inactivity(self):
        if self._inactivity_timeout <= 0:
            return
        elapsed = time.monotonic() - self._last_msg_time
        if elapsed > self._inactivity_timeout:
            raise DeviceDisconnected(
                f'Inactivity timeout ({elapsed:.1f}s > '
                f'{self._inactivity_timeout:.1f}s)')

    def iter_messages(self):
        """Generator of SniffMessage objects.

        Automatically reconnects on disconnect if ``reconnect=True``.
        Raises ``DeviceDisconnected`` if reconnect is disabled or exhausted.
        """
        while True:
            try:
                self._ensure_connected()
                yield from self._read_loop()
            except DeviceDisconnected:
                self._close()
                if not self._reconnect:
                    raise
                self._backoff_wait()

    def close(self):
        self._reconnect = False
        self._close()
