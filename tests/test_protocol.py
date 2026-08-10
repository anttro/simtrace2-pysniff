"""Tests for protocol.py message parsing."""

import struct
import unittest

from simtrace2_pysniff.protocol import (
    parse_message,
    MSG_HDR_FMT,
    MSG_HDR_SIZE,
    MSG_HDR_SIZE,
    flags_to_names,
    CHANGE_FLAG_CARD_INSERT,
    CHANGE_FLAG_TIMEOUT_WT,
    DATA_FLAG_ERROR_CHECKSUM,
    DATA_FLAG_ERROR_MALFORMED,
    DATA_FLAG_ERROR_INCOMPLETE,
    SIMTRACE_MSGC_SNIFF,
    SIMTRACE_MSGT_SNIFF_CHANGE,
    SIMTRACE_MSGT_SNIFF_FIDI,
    SIMTRACE_MSGT_SNIFF_ATR,
    SIMTRACE_MSGT_SNIFF_PPS,
    SIMTRACE_MSGT_SNIFF_TPDU,
)


def _build_hdr(msg_class, msg_type, slot_nr=0, seq_nr=0, payload=b''):
    msg_len = MSG_HDR_SIZE + len(payload)
    return struct.pack(MSG_HDR_FMT, msg_class, msg_type, seq_nr, slot_nr, 0, msg_len) + payload


class TestParseMessage(unittest.TestCase):
    def test_empty_buffer(self):
        msg, consumed = parse_message(b'')
        self.assertIsNone(msg)
        self.assertEqual(consumed, 0)

    def test_too_short_for_header(self):
        msg, consumed = parse_message(b'\x00' * 5)
        self.assertIsNone(msg)
        self.assertEqual(consumed, 0)

    def test_non_sniff_class_skipped(self):
        payload = b'junk_data'
        buf = _build_hdr(0, 0, payload=payload)
        msg, consumed = parse_message(buf)
        self.assertIsNone(msg)
        self.assertEqual(consumed, len(buf))

    def test_msg_len_smaller_than_header_skip(self):
        buf = _build_hdr(SIMTRACE_MSGC_SNIFF, SIMTRACE_MSGT_SNIFF_CHANGE)
        buf = bytearray(buf)
        struct.pack_into('<H', buf, 6, 4)  # set msg_len to 4 (< MSG_HDR_SIZE)
        msg, consumed = parse_message(bytes(buf))
        self.assertIsNone(msg)
        self.assertEqual(consumed, MSG_HDR_SIZE)

    def test_incomplete_message_needs_more_data(self):
        buf = _build_hdr(SIMTRACE_MSGC_SNIFF, SIMTRACE_MSGT_SNIFF_ATR,
                         payload=b'\x01\x02\x03')
        msg, consumed = parse_message(buf[:-2])
        self.assertIsNone(msg)
        self.assertEqual(consumed, 0)

    def test_change_message_card_insert(self):
        payload = struct.pack('<I', CHANGE_FLAG_CARD_INSERT)
        buf = _build_hdr(SIMTRACE_MSGC_SNIFF, SIMTRACE_MSGT_SNIFF_CHANGE,
                         slot_nr=1, seq_nr=5, payload=payload)
        msg, consumed = parse_message(buf)
        self.assertEqual(consumed, len(buf))
        self.assertEqual(msg.type, 'change')
        self.assertEqual(msg.type_hex, '0x00')
        self.assertEqual(msg.slot_nr, 1)
        self.assertEqual(msg.seq_nr, 5)
        self.assertEqual(msg.flags, CHANGE_FLAG_CARD_INSERT)
        self.assertEqual(msg.data, b'')

    def test_change_message_timeout(self):
        payload = struct.pack('<I', CHANGE_FLAG_TIMEOUT_WT)
        buf = _build_hdr(SIMTRACE_MSGC_SNIFF, SIMTRACE_MSGT_SNIFF_CHANGE,
                         payload=payload)
        msg, consumed = parse_message(buf)
        self.assertEqual(msg.type, 'change')
        self.assertEqual(msg.flags, CHANGE_FLAG_TIMEOUT_WT)

    def test_fidi_message(self):
        payload = struct.pack('<I', 0x97)  # Fi=9, Di=7
        buf = _build_hdr(SIMTRACE_MSGC_SNIFF, SIMTRACE_MSGT_SNIFF_FIDI,
                         payload=payload)
        msg, consumed = parse_message(buf)
        self.assertEqual(msg.type, 'fidi')
        self.assertEqual(len(msg.data), 0)
        self.assertEqual(msg.flags, 0x97)

    def test_atr_message(self):
        atr = b'\x3b\x9e\x12\x34\x56\x78\x90'
        payload = struct.pack('<IH', 0, len(atr)) + atr
        buf = _build_hdr(SIMTRACE_MSGC_SNIFF, SIMTRACE_MSGT_SNIFF_ATR,
                         payload=payload)
        msg, consumed = parse_message(buf)
        self.assertEqual(consumed, len(buf))
        self.assertEqual(msg.type, 'atr')
        self.assertEqual(msg.data, atr)
        self.assertEqual(msg.flags, 0)

    def test_atr_message_with_flags(self):
        atr = b'\x3b\x00'
        flags = DATA_FLAG_ERROR_CHECKSUM | DATA_FLAG_ERROR_MALFORMED
        payload = struct.pack('<IH', flags, len(atr)) + atr
        buf = _build_hdr(SIMTRACE_MSGC_SNIFF, SIMTRACE_MSGT_SNIFF_ATR,
                         payload=payload)
        msg, _ = parse_message(buf)
        self.assertEqual(msg.flags, flags)

    def test_pps_message(self):
        pps = b'\xff\x10\x97\x7e'
        payload = struct.pack('<IH', 0, len(pps)) + pps
        buf = _build_hdr(SIMTRACE_MSGC_SNIFF, SIMTRACE_MSGT_SNIFF_PPS,
                         payload=payload)
        msg, consumed = parse_message(buf)
        self.assertEqual(msg.type, 'pps')
        self.assertEqual(msg.data, pps)

    def test_tpdu_message(self):
        tpdu = b'\xa0\xa4\x00\x00\x02\x3f\x00'
        payload = struct.pack('<IH', 0, len(tpdu)) + tpdu
        buf = _build_hdr(SIMTRACE_MSGC_SNIFF, SIMTRACE_MSGT_SNIFF_TPDU,
                         payload=payload)
        msg, _ = parse_message(buf)
        self.assertEqual(msg.type, 'tpdu')
        self.assertEqual(msg.data, tpdu)

    def test_tpdu_flags_incomplete(self):
        tpdu = b'\x00\xb0\x00\x00\x0a'
        flags = DATA_FLAG_ERROR_INCOMPLETE
        payload = struct.pack('<IH', flags, len(tpdu)) + tpdu
        buf = _build_hdr(SIMTRACE_MSGC_SNIFF, SIMTRACE_MSGT_SNIFF_TPDU,
                         payload=payload)
        msg, _ = parse_message(buf)
        self.assertEqual(msg.flags, flags)

    def test_timestamp_passed_through(self):
        buf = _build_hdr(SIMTRACE_MSGC_SNIFF, SIMTRACE_MSGT_SNIFF_CHANGE,
                         payload=struct.pack('<I', 0))
        msg, _ = parse_message(buf, timestamp=12345.678)
        self.assertEqual(msg.timestamp, 12345.678)

    def test_multiple_messages_in_buffer(self):
        buf1 = _build_hdr(SIMTRACE_MSGC_SNIFF, SIMTRACE_MSGT_SNIFF_CHANGE,
                          payload=struct.pack('<I', 1))
        atr_payload = struct.pack('<IH', 0, 2) + b'\x3b\x00'
        buf2 = _build_hdr(SIMTRACE_MSGC_SNIFF, SIMTRACE_MSGT_SNIFF_ATR,
                          payload=atr_payload)
        combined = buf1 + buf2

        msg1, consumed1 = parse_message(combined)
        self.assertIsNotNone(msg1)
        self.assertEqual(msg1.type, 'change')
        self.assertEqual(consumed1, len(buf1))

        remaining = combined[consumed1:]
        msg2, consumed2 = parse_message(remaining)
        self.assertIsNotNone(msg2)
        self.assertEqual(msg2.type, 'atr')
        self.assertEqual(consumed2, len(buf2))

    def test_trailing_garbage_before_valid_message(self):
        msg1 = _build_hdr(0, 1, slot_nr=3, payload=b'card_emu_data!!!')
        buf = msg1 + _build_hdr(SIMTRACE_MSGC_SNIFF, SIMTRACE_MSGT_SNIFF_CHANGE,
                                payload=struct.pack('<I', 1))

        msg, consumed = parse_message(buf)
        self.assertIsNone(msg)
        self.assertEqual(consumed, len(msg1))

        msg, consumed = parse_message(buf[len(msg1):])
        self.assertIsNotNone(msg)
        self.assertEqual(msg.type, 'change')

    def test_non_sniff_msg_class_with_short_msg_len(self):
        hdr = struct.pack(MSG_HDR_FMT, 0, 0, 0, 0, 0, 4)
        msg, consumed = parse_message(hdr + b'\x00')
        self.assertIsNone(msg)
        self.assertEqual(consumed, MSG_HDR_SIZE)

    def test_non_sniff_msg_class_known_len_skip(self):
        payload = b'test_data_for_cardem'
        buf = _build_hdr(1, 0, payload=payload)
        msg, consumed = parse_message(buf)
        self.assertIsNone(msg)
        self.assertEqual(consumed, len(buf))

    def test_zero_length_data(self):
        payload = struct.pack('<IH', 0, 0)
        buf = _build_hdr(SIMTRACE_MSGC_SNIFF, SIMTRACE_MSGT_SNIFF_ATR,
                         payload=payload)
        msg, consumed = parse_message(buf)
        self.assertEqual(msg.type, 'atr')
        self.assertEqual(msg.data, b'')
        self.assertEqual(msg.flags, 0)

    def test_truncated_data_hdr(self):
        buf = _build_hdr(SIMTRACE_MSGC_SNIFF, SIMTRACE_MSGT_SNIFF_TPDU,
                         payload=b'\x00\x00\x00\x00\x10')
        msg, consumed = parse_message(buf)
        self.assertIsNone(msg)
        self.assertEqual(consumed, len(buf))


class TestFlagsToNames(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(flags_to_names(0, {}), [])

    def test_single(self):
        names = flags_to_names(CHANGE_FLAG_CARD_INSERT, {
            CHANGE_FLAG_CARD_INSERT: 'card inserted',
        })
        self.assertEqual(names, ['card inserted'])

    def test_multiple(self):
        names = flags_to_names(
            CHANGE_FLAG_CARD_INSERT | CHANGE_FLAG_TIMEOUT_WT,
            {
                CHANGE_FLAG_CARD_INSERT: 'card inserted',
                CHANGE_FLAG_TIMEOUT_WT: 'timeout',
            }
        )
        self.assertEqual(names, ['card inserted', 'timeout'])

    def test_unknown_bit_preserved(self):
        names = flags_to_names(0xDEAD0000, {})
        self.assertIn('unknown(0xdead0000)', names)


if __name__ == '__main__':
    unittest.main()
