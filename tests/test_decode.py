"""Tests for server APDU/CAT decoding."""

import unittest

from simtrace2_pysniff.server.decode import (
    decode_message,
    decode_sniff_msg,
    CAT_COMMAND_TYPES,
    ENVELOPE_TYPES,
    parse_tlv,
)


class TestParseTlv(unittest.TestCase):
    def test_simple(self):
        data = bytes.fromhex('8103010500')
        self.assertEqual(parse_tlv(data), [(0x81, 3, bytes.fromhex('010500'))])

    def test_multiple(self):
        data = bytes.fromhex('810301050082028182')
        self.assertEqual(parse_tlv(data), [
            (0x81, 3, bytes.fromhex('010500')),
            (0x82, 2, bytes.fromhex('8182')),
        ])

    def test_empty(self):
        self.assertEqual(parse_tlv(b''), [])


class TestAuthenticateNaming(unittest.TestCase):
    def test_ins_88(self):
        r = decode_message(bytes.fromhex('0088008122' + '00' * 34 + '6135'))
        self.assertEqual(r['ins_name'], 'AUTHENTICATE')

    def test_ins_89(self):
        r = decode_message(bytes.fromhex('0089008122' + '00' * 34 + '6135'))
        self.assertEqual(r['ins_name'], 'AUTHENTICATE')


class TestCatDecoding(unittest.TestCase):
    def test_fetch_setup_menu(self):
        r = decode_message(bytes.fromhex(
            '8012000030D02E810301250082028182050B416C6661204D6F62696C65'
            '8F16808112089DB0C1C2C0BEB9BAB82F53657474696E67739000'))
        self.assertEqual(r['ins_name'], 'FETCH')
        self.assertEqual(r['cat_command'], 'SET UP MENU')

    def test_fetch_setup_event_list(self):
        r = decode_message(bytes.fromhex(
            '801200000FD00D810301050082028182990203129000'))
        self.assertEqual(r['cat_command'], 'SET UP EVENT LIST')

    def test_fetch_poll_interval(self):
        r = decode_message(bytes.fromhex(
            '801200000FD00D8103010300820281820402011E9000'))
        self.assertEqual(r['cat_command'], 'POLL INTERVAL')

    def test_fetch_provide_local_info(self):
        r = decode_message(bytes.fromhex(
            '801200000BD0098103012600820281829000'))
        self.assertEqual(r['cat_command'], 'PROVIDE LOCAL INFORMATION')

    def test_envelope_event_download(self):
        r = decode_message(bytes.fromhex(
            '80C200000CD60A190103020282811B01029000'))
        self.assertEqual(r['ins_name'], 'ENVELOPE')
        self.assertEqual(r['cat_command'], 'EVENT DOWNLOAD')

    def test_tr_no_cat(self):
        r = decode_message(bytes.fromhex(
            '801400000C8103010500020282810301009130'))
        self.assertEqual(r['ins_name'], 'TERMINAL RESPONSE')
        self.assertNotIn('cat_command', r)

    def test_select_no_cat(self):
        r = decode_message(bytes.fromhex('a0a40000023f009000'))
        self.assertEqual(r['ins_name'], 'SELECT')
        self.assertNotIn('cat_command', r)


class TestCommandTypeTables(unittest.TestCase):
    def test_known_values(self):
        self.assertEqual(CAT_COMMAND_TYPES[0x03], 'POLL INTERVAL')
        self.assertEqual(CAT_COMMAND_TYPES[0x05], 'SET UP EVENT LIST')
        self.assertEqual(CAT_COMMAND_TYPES[0x25], 'SET UP MENU')
        self.assertEqual(CAT_COMMAND_TYPES[0x21], 'DISPLAY TEXT')
        self.assertEqual(CAT_COMMAND_TYPES[0x24], 'SELECT ITEM')
        self.assertEqual(CAT_COMMAND_TYPES[0x26], 'PROVIDE LOCAL INFORMATION')

    def test_envelope_known_values(self):
        self.assertEqual(ENVELOPE_TYPES[0xD3], 'MENU SELECTION')
        self.assertEqual(ENVELOPE_TYPES[0xD6], 'EVENT DOWNLOAD')


class TestChangeAndFidiDecoding(unittest.TestCase):
    def test_change_reset_assert(self):
        r = decode_sniff_msg(b'', 'change', flags=1 << 2)
        self.assertEqual(r['type'], 'change')
        self.assertEqual(r['flags'], ['Reset asserted'])

    def test_change_card_insert(self):
        r = decode_sniff_msg(b'', 'change', flags=1 << 0)
        self.assertEqual(r['flags'], ['Card inserted'])

    def test_change_multiple_flags(self):
        r = decode_sniff_msg(b'', 'change', flags=(1 << 2) | (1 << 3))
        self.assertEqual(r['flags'], ['Reset asserted', 'Reset de-asserted'])

    def test_change_no_flags(self):
        r = decode_sniff_msg(b'', 'change', flags=0)
        self.assertEqual(r['flags'], ['no changes'])

    def test_fidi(self):
        r = decode_sniff_msg(b'\x97', 'fidi')
        self.assertEqual(r['type'], 'fidi')
        self.assertEqual(r['fi'], 9)
        self.assertEqual(r['di'], 7)
        self.assertEqual(r['fi_val'], 512)
        self.assertEqual(r['di_val'], 64)


if __name__ == '__main__':
    unittest.main()
