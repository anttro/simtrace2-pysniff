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
        self.assertEqual(r['cat_command'],
                         'PROVIDE LOCAL INFORMATION — Location Info (MCC, MNC, LAC/TAC, Cell ID)')

    def test_envelope_event_download(self):
        r = decode_message(bytes.fromhex(
            '80C200000CD60A190103020282811B01029000'))
        self.assertEqual(r['ins_name'], 'ENVELOPE')
        self.assertEqual(r['cat_command'], 'EVENT DOWNLOAD')

    def test_tr_has_response_to(self):
        r = decode_message(bytes.fromhex(
            '801400000C8103010500020282810301009130'))
        self.assertEqual(r['ins_name'], 'TERMINAL RESPONSE')
        self.assertNotIn('cat_command', r)
        self.assertEqual(r['response_to'], 'SET UP EVENT LIST')

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


class TestTerminalResponse(unittest.TestCase):
    def test_tr_setup_event_list(self):
        r = decode_message(bytes.fromhex(
            '801400000C8103010500020282810301009130'))
        self.assertEqual(r['ins_name'], 'TERMINAL RESPONSE')
        self.assertEqual(r['response_to'], 'SET UP EVENT LIST')

    def test_tr_setup_menu(self):
        r = decode_message(bytes.fromhex(
            '801400000C810301250002028281830100910F'))
        self.assertEqual(r['response_to'], 'SET UP MENU')

    def test_tr_poll_interval(self):
        r = decode_message(bytes.fromhex(
            '80140000108103010300020282810301000402011E9000'))
        self.assertEqual(r['response_to'], 'POLL INTERVAL')


class TestPliQualifier(unittest.TestCase):
    def test_tr_pli_imei(self):
        r = decode_message(bytes.fromhex(
            '8014000016810301260102028281030106130952F0991EC57A68009F'))
        self.assertEqual(r['response_to'], 'PROVIDE LOCAL INFORMATION — IMEI')

    def test_fetch_pli_location(self):
        r = decode_message(bytes.fromhex(
            '801200000BD0098103012600820281829000'))
        self.assertEqual(r['cat_command'],
                         'PROVIDE LOCAL INFORMATION — Location Info (MCC, MNC, LAC/TAC, Cell ID)')

    def test_fetch_pli_date_time(self):
        r = decode_message(bytes.fromhex(
            '801200000BD0098103012603820281829000'))
        self.assertEqual(r['cat_command'],
                         'PROVIDE LOCAL INFORMATION — Date, time and time zone')

    def test_non_pli_no_qualifier(self):
        r = decode_message(bytes.fromhex(
            '801400000C810301250002028281830100910F'))
        self.assertEqual(r['response_to'], 'SET UP MENU')


class TestGetResponseContext(unittest.TestCase):
    GET_RESPONSE = bytes.fromhex('00C000002962278202782183023F00A50A800171')

    def test_with_prev_select(self):
        r = decode_message(self.GET_RESPONSE, prev={'ins_name': 'SELECT', 'sw1': '61'})
        self.assertEqual(r['response_for'], 'SELECT')

    def test_with_prev_non_61(self):
        r = decode_message(self.GET_RESPONSE, prev={'ins_name': 'SELECT', 'sw1': '90'})
        self.assertIsNone(r['response_for'])

    def test_orphaned(self):
        r = decode_message(self.GET_RESPONSE, prev=None)
        self.assertIsNone(r['response_for'])


class TestFcpResponse(unittest.TestCase):
    GET_RESPONSE = bytes.fromhex(
        '00C000002962278202782183023F00A50A8001718302F9628701018A01058B032F0601C60990014083010183010A9000')

    def test_select_response_fcp(self):
        r = decode_message(self.GET_RESPONSE, prev={'ins': 0xA4, 'ins_name': 'SELECT', 'sw1': '61'})
        self.assertEqual(r['response_for'], 'SELECT')
        resp = r['response']
        self.assertEqual(resp['template'], 'FCP')
        self.assertEqual(resp['file_id'], '3F00')
        self.assertEqual(resp['file_id_name'], 'MF')
        self.assertEqual(resp['file_descriptor']['file_type'], 'DF or ADF')
        self.assertEqual(resp['file_descriptor']['shareable'], 'shareable')
        self.assertEqual(resp['life_cycle'], 'operational state (activated)')

    def test_ef_descriptor_transparent(self):
        from simtrace2_pysniff.server.decode import _decode_file_descriptor
        fd = _decode_file_descriptor(bytes.fromhex('0121'))
        self.assertEqual(fd['file_type'], 'Working EF')
        self.assertEqual(fd['structure'], 'transparent')

    def test_ef_descriptor_linear_fixed(self):
        from simtrace2_pysniff.server.decode import _decode_file_descriptor
        fd = _decode_file_descriptor(bytes.fromhex('0221'))
        self.assertEqual(fd['file_type'], 'Working EF')
        self.assertEqual(fd['structure'], 'linear fixed')


class TestAuthResponse(unittest.TestCase):
    def test_3g_success(self):
        from simtrace2_pysniff.server.decode import _decode_auth
        data = bytes.fromhex('DB084CFA9017FD0DD85A101A2622F60E8ABD2C2497B9A8EFAF55E510CAA393329FF97868B9537369D5266A4F084D417B05ABFAFAEE')
        r = _decode_auth(data)
        self.assertEqual(r['type'], '3G')
        self.assertEqual(r['status'], 'success')
        self.assertEqual(r['res'], '4CFA9017FD0DD85A')
        self.assertEqual(r['ck'], '1A2622F60E8ABD2C2497B9A8EFAF55E5')
        self.assertEqual(r['ik'], 'CAA393329FF97868B9537369D5266A4F')

    def test_3g_sync_fail(self):
        from simtrace2_pysniff.server.decode import _decode_auth
        data = bytes.fromhex('DC0E' + '00' * 14)
        r = _decode_auth(data)
        self.assertEqual(r['type'], '3G')
        self.assertEqual(r['status'], 'sync fail')
        self.assertEqual(r['auts'], '00' * 14)

    def test_gsm(self):
        from simtrace2_pysniff.server.decode import _decode_auth
        sres = bytes.fromhex('AABBCCDD')
        kc = bytes.fromhex('0011223344556677')
        r = _decode_auth(sres + kc)
        self.assertEqual(r['type'], 'GSM')
        self.assertEqual(r['sres'], 'AABBCCDD')
        self.assertEqual(r['kc'], '0011223344556677')


class TestTrResult(unittest.TestCase):
    def test_success(self):
        r = decode_message(bytes.fromhex('801400000C8103010500020282810301009130'))
        self.assertEqual(r['response']['code'], '0x00')
        self.assertEqual(r['response']['name'], 'Command performed successfully')

    def test_session_terminated(self):
        from simtrace2_pysniff.server.decode import _decode_tr_result
        r = _decode_tr_result(bytes.fromhex('81030105000202828103010A'))
        self.assertEqual(r['code'], '0x0A')
        self.assertEqual(r['name'], 'Proactive UICC session terminated by the user')


if __name__ == '__main__':
    unittest.main()
