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


class TestTrAdditionalInfo(unittest.TestCase):
    def test_poll_interval_duration(self):
        r = decode_message(bytes.fromhex(
            '80140000108103010300020282810301000402011E9000'))
        self.assertEqual(r['response_to'], 'POLL INTERVAL')
        self.assertEqual(r['response']['duration'], 286)

    def test_pli_location_info(self):
        r = decode_message(bytes.fromhex(
            '8014000017810301260002028281030106130952F0991EC57A43C09F9000'))
        self.assertEqual(
            r['response']['local_info']['Location'],
            'MCC 250 MNC 99 · LAC 0x1EC5 · Cell 0x7A43C09F')

    def test_pli_imei(self):
        r = decode_message(bytes.fromhex(
            '801400001681030126010202828103010014088A763201652428089000'))
        self.assertEqual(r['response']['local_info']['IMEI'],
                         '867231056428280')

    def test_pli_datetime(self):
        from simtrace2_pysniff.server.decode import _decode_datetime
        self.assertEqual(
            _decode_datetime(bytes.fromhex('26081214300021')),
            '2026-08-12 14:30:00 (UTC+03:00)')
        self.assertEqual(
            _decode_datetime(bytes.fromhex('260812143000FF')),
            '2026-08-12 14:30:00 (UTCunknown)')

    def test_pli_language(self):
        from simtrace2_pysniff.server.decode import _decode_local_info, PLI_LANGUAGE
        self.assertEqual(_decode_local_info(PLI_LANGUAGE, b'en'),
                         {'label': 'Language', 'value': 'en'})

    def test_pli_battery(self):
        from simtrace2_pysniff.server.decode import _decode_local_info, PLI_BATTERY
        self.assertEqual(_decode_local_info(PLI_BATTERY, b'\x05'),
                         {'label': 'Battery', 'value': 'full'})

    def test_pli_access_tech(self):
        from simtrace2_pysniff.server.decode import _decode_local_info, PLI_ACCESS_TECH
        self.assertEqual(_decode_local_info(PLI_ACCESS_TECH, bytes([0x03, 0x07])),
                         {'label': 'Access technology', 'value': 'UTRAN, E-UTRAN'})


class TestAuthCommand(unittest.TestCase):
    def test_3g_rand_autn(self):
        r = decode_message(bytes.fromhex(
            '0088008122104A75BA425D438C549EF35BA5E3DD53051065E04D80E4DC8000A5C7FD842F41395E6135'))
        cmd = r['cmd']
        self.assertEqual(cmd['context'], '3G (UMTS)')
        self.assertEqual(cmd['rand'], '4A75BA425D438C549EF35BA5E3DD5305')
        self.assertEqual(cmd['autn'], '65E04D80E4DC8000A5C7FD842F41395E')

    def test_gsm_rand_only(self):
        from simtrace2_pysniff.server.decode import _decode_auth_cmd
        r = _decode_auth_cmd(bytes.fromhex('10' + '00' * 16), 0x00)
        self.assertEqual(r['context'], 'GSM')
        self.assertEqual(r['rand'], '00' * 16)
        self.assertNotIn('autn', r)


class TestEventDownload(unittest.TestCase):
    def test_location_status(self):
        r = decode_message(bytes.fromhex(
            '80C2000017D615190103020282811B0100130952F0991EC57A43C09F9000'))
        cmd = r['cmd']
        self.assertEqual(cmd['type'], 'EVENT DOWNLOAD')
        self.assertEqual(cmd['events'], ['Location status'])
        self.assertEqual(cmd['location_status'], 'Normal service')

    def test_event_no_service(self):
        r = decode_message(bytes.fromhex(
            '80C200000CD60A190103020282811B01029000'))
        self.assertEqual(r['cmd']['events'], ['Location status'])
        self.assertEqual(r['cmd']['location_status'], 'No service')


class TestSmTpdu(unittest.TestCase):
    def _bcd(self, number):
        d = [int(c) for c in number]
        out = bytearray()
        for i in range(0, len(d), 2):
            lo = d[i]
            hi = d[i + 1] if i + 1 < len(d) else 0xF
            out.append((hi << 4) | lo)
        return bytes(out)

    def test_deliver_gsm7(self):
        from simtrace2_pysniff.server.decode import _decode_sm_tpdu
        oa = b'\x91' + self._bcd('79031234567')
        tpdu = (b'\x00' + bytes([11]) + oa + b'\x00\x00' + b'\x00' * 7 +
                b'\x05' + bytes.fromhex('E8329BFD06'))
        r = _decode_sm_tpdu(tpdu)
        self.assertEqual(r['mti'], 'SMS-DELIVER')
        self.assertEqual(r['oa'], '+79031234567')
        self.assertEqual(r['encoding'], 'GSM 7-bit')
        self.assertEqual(r['text'], 'hello')

    def test_deliver_ucs2(self):
        from simtrace2_pysniff.server.decode import _decode_sm_tpdu
        oa = b'\x91' + self._bcd('79031234567')
        ucs2 = '\u041f\u0440\u0438\u0432\u0435\u0442'.encode('utf-16-be')
        tpdu = (b'\x00' + bytes([11]) + oa + b'\x00\x08' + b'\x00' * 7 +
                bytes([len(ucs2)]) + ucs2)
        r = _decode_sm_tpdu(tpdu)
        self.assertEqual(r['encoding'], 'UCS2')
        self.assertEqual(r['text'], '\u041f\u0440\u0438\u0432\u0435\u0442')

    def test_8bit_no_text(self):
        from simtrace2_pysniff.server.decode import _decode_sm_tpdu
        oa = b'\x91' + self._bcd('79031234567')
        tpdu = (b'\x00' + bytes([11]) + oa + b'\x00\x04' + b'\x00' * 7 +
                b'\x10' + bytes(range(16)))
        r = _decode_sm_tpdu(tpdu)
        self.assertEqual(r['encoding'], '8-bit data')
        self.assertNotIn('text', r)
        self.assertEqual(r['payload'], '000102030405060708090A0B0C0D0E0F')

    def test_sim_data_download(self):
        from simtrace2_pysniff.server.decode import _decode_sm_tpdu
        oa = b'\x91' + self._bcd('79031234567')
        tpdu = (b'\x00' + bytes([11]) + oa + b'\x7f\x04' + b'\x00' * 7 +
                b'\x10' + bytes(range(16)))
        r = _decode_sm_tpdu(tpdu)
        self.assertEqual(r['pid_name'], 'SIM data download (secured packet)')
        self.assertEqual(r['payload'], '000102030405060708090A0B0C0D0E0F')


class TestBcdAddress(unittest.TestCase):
    def test_international(self):
        from simtrace2_pysniff.server.decode import _decode_bcd_address
        self.assertEqual(_decode_bcd_address(bytes.fromhex('912143658709')), '+1234567890')

    def test_national(self):
        from simtrace2_pysniff.server.decode import _decode_bcd_address
        self.assertEqual(_decode_bcd_address(bytes.fromhex('A12143658709')), '1234567890')

    def test_odd_digits(self):
        from simtrace2_pysniff.server.decode import _decode_bcd_address
        self.assertEqual(_decode_bcd_address(bytes.fromhex('9121436587F9')), '+123456789')


class TestProactiveDecode(unittest.TestCase):
    def test_setup_menu(self):
        r = decode_message(bytes.fromhex(
            '8012000030D02E810301250082028182050B416C6661204D6F62696C'
            '658F16808112089DB0C1C2C0BEB9BAB82F53657474696E67739000'))
        cmd = r['cmd']
        self.assertEqual(cmd['type'], 'SET UP MENU')
        self.assertEqual(cmd['title'], 'Alfa Mobile')
        self.assertEqual(cmd['items'], [{'id': 0x80, 'text': 'Настройки/Settings'}])

    def test_setup_event_list(self):
        r = decode_message(bytes.fromhex(
            '801200000FD00D810301050082028182990203129000'))
        self.assertEqual(r['cmd']['events'], ['Location status', 'Network Rejection'])

    def test_poll_interval_duration(self):
        r = decode_message(bytes.fromhex(
            '801200000FD00D8103010300820281820402011E9000'))
        self.assertEqual(r['cmd']['duration'], 286)

    def test_send_short_message_tpdu(self):
        r = decode_message(bytes.fromhex(
            '801200004AD04881030113008202818305000B3B11FF038199F90004A531'
            '494D45492038363732333130353634323832383020494D53492032353031'
            '3937373030313932373935204556454E5420319000'))
        self.assertEqual(r['cmd']['type'], 'SEND SHORT MESSAGE')
        self.assertEqual(r['cmd']['tpdu']['mti'], 'SMS-SUBMIT')
        self.assertEqual(r['cmd']['tpdu']['da'], '999')


class TestAnnexA(unittest.TestCase):
    def test_gsm_default(self):
        from simtrace2_pysniff.server.decode import _decode_annex_a
        self.assertEqual(_decode_annex_a(b'Alfa Mobile'), 'Alfa Mobile')

    def test_ucs2_variant1(self):
        from simtrace2_pysniff.server.decode import _decode_annex_a
        self.assertEqual(_decode_annex_a(b'\x80' + 'Привет'.encode('utf_16_be')), 'Привет')

    def test_ucs2_variant2_base_ptr(self):
        from simtrace2_pysniff.server.decode import _decode_annex_a
        # 'Н' = U+041D, base 0x08<<7 = 0x400, offset 0x1D
        self.assertEqual(_decode_annex_a(bytes.fromhex('8101089D')), 'Н')


class TestDcsText(unittest.TestCase):
    def test_gsm7(self):
        from simtrace2_pysniff.server.decode import _decode_dcs_text
        self.assertEqual(_decode_dcs_text(b'\x00Alfa'), 'Alfa')

    def test_ucs2(self):
        from simtrace2_pysniff.server.decode import _decode_dcs_text
        self.assertEqual(_decode_dcs_text(b'\x08' + 'OK'.encode('utf_16_be')), 'OK')

    def test_latin1(self):
        from simtrace2_pysniff.server.decode import _decode_dcs_text
        self.assertEqual(_decode_dcs_text(b'\x04caf\xe9'), 'café')


if __name__ == '__main__':
    unittest.main()
