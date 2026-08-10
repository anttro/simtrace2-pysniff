"""Hex dump formatters for simtrace2 sniffing output."""

import sys


def hexdump(data, sep=' '):
    """Return hex string representation of bytes.

    >>> hexdump(b'\\x3b\\x9e\\x12\\x34')
    '3b 9e 12 34'
    """
    return data.hex(sep)


def _flag_str(flags, flag_names):
    if not flags:
        return ''
    names = []
    for bit, name in sorted(flag_names.items()):
        if flags & bit:
            names.append(name)
            flags &= ~bit
    if flags:
        names.append(f'unknown(0x{flags:08x})')
    return ', '.join(names)


def format_message(msg, *, show_flags=True):
    """Format a SniffMessage as a human-readable line.

    Returns a str suitable for stdout or file output.
    """
    from .protocol import (
        CHANGE_FLAG_CARD_INSERT, CHANGE_FLAG_CARD_EJECT,
        CHANGE_FLAG_RESET_ASSERT, CHANGE_FLAG_RESET_DEASSERT,
        CHANGE_FLAG_TIMEOUT_WT,
        DATA_FLAG_ERROR_INCOMPLETE, DATA_FLAG_ERROR_MALFORMED,
        DATA_FLAG_ERROR_CHECKSUM, DATA_FLAG_ERROR_OVERRUN,
        DATA_FLAG_ERROR_FRAMING, DATA_FLAG_ERROR_PARITY,
    )

    change_flag_names = {
        CHANGE_FLAG_CARD_INSERT:    'card inserted',
        CHANGE_FLAG_CARD_EJECT:     'card ejected',
        CHANGE_FLAG_RESET_ASSERT:   'reset asserted',
        CHANGE_FLAG_RESET_DEASSERT: 'reset de-asserted',
        CHANGE_FLAG_TIMEOUT_WT:     'waiting time timeout',
    }

    data_flag_names = {
        DATA_FLAG_ERROR_INCOMPLETE: 'incomplete',
        DATA_FLAG_ERROR_MALFORMED:  'malformed',
        DATA_FLAG_ERROR_CHECKSUM:   'checksum error',
        DATA_FLAG_ERROR_OVERRUN:    'overrun',
        DATA_FLAG_ERROR_FRAMING:    'framing error',
        DATA_FLAG_ERROR_PARITY:     'parity error',
    }

    type_label = msg.type.upper()

    if msg.type == 'change':
        flags_str = _flag_str(msg.flags, change_flag_names)
        line = f'Card state change: {flags_str}' if flags_str else 'Card state change: no changes'
    elif msg.type == 'fidi':
        fidi = msg.data[0] if len(msg.data) >= 1 else 0
        fi = fidi >> 4
        di = fidi & 0x0f
        line = f'Fi/Di switched to {_fi_table.get(fi, fi)}/{_di_table.get(di, di)}'
    else:
        flags_str = ''
        if show_flags and msg.flags:
            flags_str = f' ({_flag_str(msg.flags, data_flag_names)})'
        line = f'{type_label}{flags_str}: {hexdump(msg.data)}'

    return line


class FileDumper:
    """Write formatted sniff messages to a file."""

    def __init__(self, path):
        self._f = open(path, 'a', buffering=1)

    def write(self, msg):
        line = format_message(msg)
        self._f.write(line + '\n')

    def close(self):
        self._f.close()


# ISO 7816-3:2006 Table 7
_fi_table = {
    0: 372, 1: 372, 2: 558, 3: 744,
    4: 1116, 5: 1488, 6: 1860, 7: 0,
    8: 0, 9: 512, 10: 768, 11: 1024,
    12: 1536, 13: 2048, 14: 0, 15: 0,
}

# ISO 7816-3:2006 Table 8
_di_table = {
    0: 0, 1: 1, 2: 2, 3: 4,
    4: 8, 5: 16, 6: 32, 7: 64,
    8: 12, 9: 20, 10: 2, 11: 4,
    12: 8, 13: 16, 14: 32, 15: 64,
}
