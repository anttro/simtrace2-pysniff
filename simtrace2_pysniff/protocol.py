"""Message parsing for SIMtrace2 USB sniffing protocol."""

import struct
from collections import namedtuple

MSG_HDR_FMT = '<BBBBHH'
MSG_HDR_SIZE = struct.calcsize(MSG_HDR_FMT)  # 8 bytes

SIMTRACE_MSGC_SNIFF = 3

# --- Message types within SIMTRACE_MSGC_SNIFF ---
SIMTRACE_MSGT_SNIFF_CHANGE = 0
SIMTRACE_MSGT_SNIFF_FIDI = 1
SIMTRACE_MSGT_SNIFF_ATR = 2
SIMTRACE_MSGT_SNIFF_PPS = 3
SIMTRACE_MSGT_SNIFF_TPDU = 4

_TYPE_NAMES = {
    SIMTRACE_MSGT_SNIFF_CHANGE: 'change',
    SIMTRACE_MSGT_SNIFF_FIDI:  'fidi',
    SIMTRACE_MSGT_SNIFF_ATR:   'atr',
    SIMTRACE_MSGT_SNIFF_PPS:   'pps',
    SIMTRACE_MSGT_SNIFF_TPDU:  'tpdu',
}

# --- Change flags ---
CHANGE_FLAG_CARD_INSERT     = 1 << 0
CHANGE_FLAG_CARD_EJECT      = 1 << 1
CHANGE_FLAG_RESET_ASSERT    = 1 << 2
CHANGE_FLAG_RESET_DEASSERT  = 1 << 3
CHANGE_FLAG_TIMEOUT_WT      = 1 << 4

_CHANGE_FLAG_NAMES = {
    CHANGE_FLAG_CARD_INSERT:    'card inserted',
    CHANGE_FLAG_CARD_EJECT:     'card ejected',
    CHANGE_FLAG_RESET_ASSERT:   'reset asserted',
    CHANGE_FLAG_RESET_DEASSERT: 'reset de-asserted',
    CHANGE_FLAG_TIMEOUT_WT:     'waiting time timeout',
}

# --- Data flags ---
DATA_FLAG_ERROR_INCOMPLETE  = 1 << 5
DATA_FLAG_ERROR_MALFORMED   = 1 << 6
DATA_FLAG_ERROR_CHECKSUM    = 1 << 7
DATA_FLAG_ERROR_OVERRUN     = 1 << 8
DATA_FLAG_ERROR_FRAMING     = 1 << 9
DATA_FLAG_ERROR_PARITY      = 1 << 10

_DATA_FLAG_NAMES = {
    DATA_FLAG_ERROR_INCOMPLETE: 'incomplete',
    DATA_FLAG_ERROR_MALFORMED:  'malformed',
    DATA_FLAG_ERROR_CHECKSUM:   'checksum error',
    DATA_FLAG_ERROR_OVERRUN:    'overrun',
    DATA_FLAG_ERROR_FRAMING:    'framing error',
    DATA_FLAG_ERROR_PARITY:     'parity error',
}

SniffMessage = namedtuple('SniffMessage', [
    'type',
    'type_hex',
    'data',
    'flags',
    'slot_nr',
    'seq_nr',
    'timestamp',
])


def flags_to_names(value, mapping):
    """Convert a uint32 bitmask to a list of human-readable flag names."""
    names = []
    for bit, name in sorted(mapping.items()):
        if value & bit:
            names.append(name)
            value &= ~bit
    if value:
        names.append(f'unknown(0x{value:08x})')
    return names


def _parse_change(payload):
    if len(payload) < 4:
        return None
    flags, = struct.unpack('<I', payload[:4])
    consumed = 4
    return consumed, flags, b''


def _parse_fidi(payload):
    if len(payload) < 1:
        return None
    return 1, 0, payload[:1]

_SNIFF_DATA_FMT = '<IH'
_SNIFF_DATA_HDR_SIZE = struct.calcsize(_SNIFF_DATA_FMT)  # 6 bytes


def _parse_data(payload):
    if len(payload) < _SNIFF_DATA_HDR_SIZE:
        return None
    flags, length = struct.unpack(_SNIFF_DATA_FMT, payload[:_SNIFF_DATA_HDR_SIZE])
    total = _SNIFF_DATA_HDR_SIZE + length
    if len(payload) < total:
        return None
    data = payload[_SNIFF_DATA_HDR_SIZE:total]
    return total, flags, data


_PAYLOAD_PARSERS = {
    SIMTRACE_MSGT_SNIFF_CHANGE: _parse_change,
    SIMTRACE_MSGT_SNIFF_FIDI:   _parse_fidi,
    SIMTRACE_MSGT_SNIFF_ATR:    _parse_data,
    SIMTRACE_MSGT_SNIFF_PPS:    _parse_data,
    SIMTRACE_MSGT_SNIFF_TPDU:   _parse_data,
}


def parse_message(buf, timestamp=None):
    """Try to extract one SniffMessage from the front of *buf*.

    Returns ``(SniffMessage, consumed)`` on success, or ``(None, 0)`` on failure.
    ``consumed`` is the number of bytes to remove from the buffer.
    """
    if len(buf) < MSG_HDR_SIZE:
        return None, 0

    msg_class, msg_type, seq_nr, slot_nr, _reserved, msg_len = \
        struct.unpack(MSG_HDR_FMT, buf[:MSG_HDR_SIZE])

    if msg_class != SIMTRACE_MSGC_SNIFF:
        if msg_len < MSG_HDR_SIZE or msg_len > 65535:
            consumed = MSG_HDR_SIZE
        else:
            consumed = msg_len
        return None, consumed

    payload_size = msg_len - MSG_HDR_SIZE
    if payload_size < 0:
        return None, MSG_HDR_SIZE

    if len(buf) < msg_len:
        return None, 0

    payload = buf[MSG_HDR_SIZE:msg_len]
    type_name = _TYPE_NAMES.get(msg_type, f'unknown(0x{msg_type:02x})')

    data = b''
    flags = 0

    parser = _PAYLOAD_PARSERS.get(msg_type)
    if parser is not None:
        result = parser(payload)
        if result is None:
            return None, msg_len
        consumed_payload, flags, data = result
    else:
        data = payload
        consumed_payload = payload_size
        if consumed_payload != payload_size:
            return None, msg_len

    return SniffMessage(
        type=type_name,
        type_hex=f'0x{msg_type:02x}',
        data=data,
        flags=flags,
        slot_nr=slot_nr,
        seq_nr=seq_nr,
        timestamp=timestamp,
    ), msg_len
