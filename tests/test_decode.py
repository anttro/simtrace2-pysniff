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

    def test_long_form_length(self):
        # D0 81 BC … — a proactive command whose length is 0xBC (188),
        # encoded in BER-TLV long form.
        inner = bytes.fromhex('8103012500') + b'\x82\x02\x81\x82'
        data = b'\xd0' + b'\x81' + bytes([len(inner)]) + inner
        self.assertEqual(parse_tlv(data), [(0xD0, len(inner), inner)])

    def test_long_form_two_byte(self):
        # 0x82 followed by two length bytes.
        value = b'\x00' * 300
        data = b'\x70' + b'\x82\x01\x2c' + value
        self.assertEqual(parse_tlv(data), [(0x70, 300, value)])


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
        self.assertEqual(r['cmd']['qualifier'],
                         '0x00 Location Info (MCC, MNC, LAC/TAC, Cell ID)')

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

    def test_envelope_sms_pp_download(self):
        r = decode_message(bytes.fromhex(
            '80C2000022D120020283810607919740430900F40B1104038154F50004'
            '628021410300210248699000'))
        self.assertEqual(r['ins_name'], 'ENVELOPE')
        self.assertEqual(r['cat_command'], 'SMS-PP DOWNLOAD')
        cmd = r['cmd']
        self.assertEqual(cmd['smsc'], '+79043490004')
        self.assertEqual(cmd['device_ids'], {'src': 'Network', 'dst': 'UICC'})
        t = cmd['tpdu']
        self.assertEqual(t['mti'], 'SMS-DELIVER')
        self.assertEqual(t['oa'], '455')
        self.assertEqual(t['text'], 'Hi')
        self.assertEqual(t['scts'], '2026-08-12 14:30:00 (UTC+03:00)')


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

    def test_tpdu_error_flags_surfaced(self):
        r = decode_sniff_msg(bytes.fromhex('00a40000023f009000'), 'tpdu',
                             flags=(1 << 7) | (1 << 6))
        self.assertEqual(r['errors'], ['malformed', 'checksum error'])

    def test_tpdu_no_error_flags(self):
        r = decode_sniff_msg(bytes.fromhex('00a40000023f009000'), 'tpdu', flags=0)
        self.assertNotIn('errors', r)

    def test_atr_error_flags_surfaced(self):
        r = decode_sniff_msg(bytes.fromhex('3b00'), 'atr', flags=(1 << 5))
        self.assertEqual(r['errors'], ['incomplete'])


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
        self.assertEqual(r['response_to'], 'PROVIDE LOCAL INFORMATION')
        self.assertEqual(r['response']['qualifier'], '0x01 IMEI')

    def test_fetch_pli_location(self):
        r = decode_message(bytes.fromhex(
            '801200000BD0098103012600820281829000'))
        self.assertEqual(r['cat_command'], 'PROVIDE LOCAL INFORMATION')
        self.assertEqual(r['cmd']['qualifier'],
                         '0x00 Location Info (MCC, MNC, LAC/TAC, Cell ID)')

    def test_fetch_pli_date_time(self):
        r = decode_message(bytes.fromhex(
            '801200000BD0098103012603820281829000'))
        self.assertEqual(r['cat_command'], 'PROVIDE LOCAL INFORMATION')
        self.assertEqual(r['cmd']['qualifier'], '0x03 Date, time and time zone')

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

    def test_get_response_por(self):
        # GET RESPONSE after ENVELOPE SMS-PP DOWNLOAD → Response Packet (PoR).
        r = decode_message(
            bytes.fromhex('00C0000024') +
            bytes.fromhex('027100001F0AB0000100000000C100000290000080041C043004400438044FD83CDF37FF') +
            bytes.fromhex('9000'),
            prev={'ins': 0xC2, 'ins_name': 'ENVELOPE', 'sw1': '61'})
        self.assertEqual(r['response_for'], 'ENVELOPE')
        self.assertEqual(r['response']['rpl'], 31)
        self.assertEqual(r['response']['rhl'], 10)
        self.assertEqual(r['response']['tar'], 'B00001')
        self.assertEqual(r['response']['cntr'], '00000000C1')
        self.assertEqual(r['response']['status'], {'code': '00', 'name': 'PoR OK'})
        self.assertEqual(r['response']['data'], '0290000080041C043004400438044FD83CDF37FF')
        self.assertIn('PoR OK · TAR B00001', r['summary'])

    def test_get_response_non_por_not_parsed(self):
        # A GET RESPONSE after ENVELOPE that is not a PoR must stay undecoded.
        r = decode_message(bytes.fromhex('00C0000004') + bytes.fromhex('AABBCCDD') + bytes.fromhex('9000'),
                           prev={'ins': 0xC2, 'ins_name': 'ENVELOPE', 'sw1': '61'})
        self.assertEqual(r['response_for'], 'ENVELOPE')
        self.assertNotIn('response', r)


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

    def test_fcp_file_size(self):
        from simtrace2_pysniff.server.decode import _decode_fcp
        # FCP: file descriptor (transparent EF) + FID 6F07 + file size 9 + total 9
        fcp = _decode_fcp(bytes.fromhex('8202012183026f07800109810109'))
        self.assertEqual(fcp['file_descriptor']['file_type'], 'Working EF')
        self.assertEqual(fcp['file_descriptor']['structure'], 'transparent')
        self.assertEqual(fcp['file_id_name'], 'EF_IMSI')
        self.assertEqual(fcp['file_size'], 9)
        self.assertEqual(fcp['total_file_size'], 9)

    def test_fcp_sfi(self):
        # FCP SFI tag 0x88 carries the SFI in bits b8..b4 (value >> 3).
        from simtrace2_pysniff.server.decode import _decode_fcp
        fcp = _decode_fcp(bytes.fromhex('8202412183026f7e880158'))
        self.assertEqual(fcp['sfi'], 11)

    def test_fcp_sfi_empty(self):
        # FCP SFI tag 0x88 with length 0 → file does not support SFI.
        from simtrace2_pysniff.server.decode import _decode_fcp
        fcp = _decode_fcp(bytes.fromhex('82054221005a0d83026f068800'))
        self.assertIsNone(fcp['sfi'])

    def test_fcp_sfi_absent_uses_fid_lsbs(self):
        # No SFI tag → SFI = 5 LSBs of the FID (TS 102 221 §11.1.2).
        from simtrace2_pysniff.server.decode import _decode_fcp
        fcp = _decode_fcp(bytes.fromhex('8202412183022f06'))
        self.assertEqual(fcp['sfi'], 0x06)

    def test_fcp_summary_transparent(self):
        # GET RESPONSE (FCP) for a transparent EF of 9 bytes
        gr = bytes.fromhex('00c000000c') + bytes.fromhex('620c8202012183026f07800109810109') + bytes.fromhex('9000')
        r = decode_message(gr, prev={'ins': 0xA4, 'ins_name': 'SELECT', 'sw1': '61'})
        self.assertEqual(r['summary'], 'response for SELECT, Working EF, transparent, 9 B')

    def test_fcp_summary_linear_fixed(self):
        # linear fixed EF, 3 records x 64 bytes
        gr = bytes.fromhex('00c000000e') + bytes.fromhex('620e8205022100400383026f07800109') + bytes.fromhex('9000')
        r = decode_message(gr, prev={'ins': 0xA4, 'ins_name': 'SELECT', 'sw1': '61'})
        self.assertEqual(r['summary'], 'response for SELECT, Working EF, linear fixed, 3 rec × 64 B')

    def test_fcp_summary_df(self):
        r = decode_message(self.GET_RESPONSE, prev={'ins': 0xA4, 'ins_name': 'SELECT', 'sw1': '61'})
        self.assertEqual(r['summary'], 'response for SELECT, DF or ADF (MF)')


class TestAuthResponse(unittest.TestCase):
    def test_3g_success(self):
        from simtrace2_pysniff.server.decode import _decode_auth
        data = bytes.fromhex('DB084CFA9017FD0DD85A101A2622F60E8ABD2C2497B9A8EFAF55E510CAA393329FF97868B9537369D5266A4F084D417B05ABFAFAEE')
        r = _decode_auth(data)
        self.assertEqual(r['type'], '3G/EPS/5G')
        self.assertEqual(r['status'], 'success')
        self.assertEqual(r['res'], '4CFA9017FD0DD85A')
        self.assertEqual(r['ck'], '1A2622F60E8ABD2C2497B9A8EFAF55E5')
        self.assertEqual(r['ik'], 'CAA393329FF97868B9537369D5266A4F')

    def test_3g_sync_fail(self):
        from simtrace2_pysniff.server.decode import _decode_auth
        data = bytes.fromhex('DC0E' + '00' * 14)
        r = _decode_auth(data)
        self.assertEqual(r['type'], '3G/EPS/5G')
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
        r = _decode_tr_result(bytes.fromhex('810301050002028281030110'))
        self.assertEqual(r['code'], '0x10')
        self.assertEqual(r['name'], 'Proactive UICC session terminated by the user')


class TestTrAdditionalInfo(unittest.TestCase):
    def test_poll_interval_duration(self):
        r = decode_message(bytes.fromhex(
            '80140000108103010300020282810301000402011E9000'))
        self.assertEqual(r['response_to'], 'POLL INTERVAL')
        self.assertEqual(r['response']['duration'], {'value': 30, 'unit': 'seconds'})

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
            _decode_datetime(bytes.fromhex('62802141030021')),
            '2026-08-12 14:30:00 (UTC+03:00)')
        self.assertEqual(
            _decode_datetime(bytes.fromhex('628021410300FF')),
            '2026-08-12 14:30:00 (UTCunknown)')

    def test_datetime_invalid_bcd(self):
        from simtrace2_pysniff.server.decode import _decode_datetime
        self.assertIsNone(_decode_datetime(bytes.fromhex('A505326C333939')))

    def test_datetime_invalid_semantics(self):
        from simtrace2_pysniff.server.decode import _decode_datetime
        self.assertIsNone(_decode_datetime(bytes.fromhex('62310100000000')))

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
        self.assertNotIn('context', cmd)
        self.assertEqual(cmd['specific_key'], True)
        self.assertEqual(cmd['rand'], '4A75BA425D438C549EF35BA5E3DD5305')
        self.assertEqual(cmd['autn'], '65E04D80E4DC8000A5C7FD842F41395E')
        self.assertEqual(cmd['sqn_ak'], '65E04D80E4DC')
        self.assertEqual(cmd['amf'], '8000')
        self.assertEqual(cmd['mac'], 'A5C7FD842F41395E')

    def test_auth_p2_context(self):
        r = decode_message(bytes.fromhex(
            '0088008122104A75BA425D438C549EF35BA5E3DD53051065E04D80E4DC8000A5C7FD842F41395E6135'))
        p2 = r['p2']
        self.assertEqual(p2['raw'], '81')
        self.assertIn('3G/EPS/5G context', p2['bits'])
        self.assertIn('Specific reference data', p2['bits'])

    def test_gsm_rand_only(self):
        from simtrace2_pysniff.server.decode import _decode_auth_cmd
        r = _decode_auth_cmd(bytes.fromhex('10' + '00' * 16), 0x00)
        self.assertNotIn('context', r)
        self.assertNotIn('specific_key', r)
        self.assertEqual(r['rand'], '00' * 16)
        self.assertNotIn('autn', r)

    def test_sync_fail_auts(self):
        from simtrace2_pysniff.server.decode import _decode_auth
        auts = bytes.fromhex('010203040506' + '0a0b0c0d0e0f1011')
        r = _decode_auth(b'\xdc' + bytes([len(auts)]) + auts)
        self.assertEqual(r['status'], 'sync fail')
        self.assertEqual(r['auts'], auts.hex().upper())
        self.assertEqual(r['sqn_ak'], '010203040506')
        self.assertEqual(r['mac_s'], '0A0B0C0D0E0F1011')


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

    def test_location_status_with_info(self):
        r = decode_message(bytes.fromhex(
            '80C2000017D615190103020282811B0100130952F02026ADBC51A16F9000'))
        cmd = r['cmd']
        self.assertEqual(cmd['location_status'], 'Normal service')
        self.assertEqual(cmd['location_info'],
                         'MCC 250 MNC 02 · LAC 0x26AD · Cell 0xBC51A16F')

    def test_mt_call(self):
        r = decode_message(bytes.fromhex(
            '80C2000014D612190100020283811C010586069121436587099000'))
        cmd = r['cmd']
        self.assertEqual(cmd['events'], ['MT call'])
        self.assertEqual(cmd['transaction_id'], 5)
        self.assertEqual(cmd['caller'], '+1234567890')

    def test_cell_broadcast(self):
        cbp = ('4C511002F211' +
               '040000313A0103035E047FFB0F31303238322A333036343835363234' +
               '0D' * 54)
        r = decode_message(bytes.fromhex(
            '80C2000060D25E020283810C58' + cbp + '9000'))
        cmd = r['cmd']
        self.assertEqual(cmd['type'], 'CELL BROADCAST DOWNLOAD')
        self.assertEqual(cmd['cb_page']['serial'], '4C51')
        self.assertEqual(cmd['cb_page']['message_id'], '0x1002')
        self.assertEqual(cmd['cb_page']['page'], '1/1')
        self.assertEqual(cmd['cb_page']['content'],
                         '040000313A0103035E047FFB0F31303238322A333036343835363234' + '0D' * 54)


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
        # Mixed low/high bytes are treated as binary → no text decode.
        payload = bytes.fromhex('00018081A0FF07')
        tpdu = (b'\x00' + bytes([11]) + oa + b'\x00\x04' + b'\x00' * 7 +
                bytes([len(payload)]) + payload)
        r = _decode_sm_tpdu(tpdu)
        self.assertEqual(r['encoding'], '8-bit data')
        self.assertNotIn('text', r)
        self.assertEqual(r['payload'], '00018081A0FF07')

    def test_sim_data_download(self):
        from simtrace2_pysniff.server.decode import _decode_sm_tpdu
        oa = b'\x91' + self._bcd('79031234567')
        ud = bytes.fromhex('02700000200d000000000000020000000000000010100102a2090804420435044104420600')
        tpdu = (b'\x44' + bytes([11]) + oa + b'\x7f\x04' + b'\x00' * 7 +
                bytes([len(ud)]) + ud)
        r = _decode_sm_tpdu(tpdu)
        self.assertEqual(r['pid_name'], 'SIM data download (secured packet)')
        self.assertEqual(r['udh'][0]['name'], 'Command Packet Identifier (CPI)')
        self.assertEqual(r['secured']['cpl'], 32)
        self.assertEqual(r['secured']['chl'], 13)
        self.assertEqual(r['secured']['spi']['counter'], 'no counter')
        self.assertEqual(r['secured']['spi']['rc_cc_ds'], 'none')
        self.assertEqual(r['secured']['tar'], '000002')
        self.assertEqual(r['secured']['cntr'], '0000000000')
        self.assertEqual(r['secured']['data'], '0010100102A2090804420435044104420600')

    def test_response_packet(self):
        from simtrace2_pysniff.server.decode import _decode_response_packet
        body = bytes.fromhex('001f0a00000000000000500000ab12800101230d08a0000001510000000f9a9000')
        r = _decode_response_packet(body)
        self.assertEqual(r['rpl'], 31)
        self.assertEqual(r['rhl'], 10)
        self.assertEqual(r['tar'], '000000')
        self.assertEqual(r['cntr'], '0000000050')
        self.assertEqual(r['pcntr'], 0)
        self.assertEqual(r['status'], {'code': '00', 'name': 'PoR OK'})
        self.assertEqual(r['data'], 'AB12800101230D08A0000001510000000F9A9000')

    def test_secured_packet_fallback(self):
        from simtrace2_pysniff.server.decode import _decode_secured_packet
        self.assertEqual(_decode_secured_packet(bytes.fromhex('0001')), {'raw': '0001'})

    def test_send_sm_response_packet(self):
        from simtrace2_pysniff.server.decode import _decode_sm_tpdu
        tpdu = bytes.fromhex('41000481112200f624027100001f0a00000000000000500000ab12800101230d08a0000001510000000f9a9000')
        r = _decode_sm_tpdu(tpdu)
        self.assertEqual(r['mti'], 'SMS-SUBMIT')
        self.assertEqual(r['da'], '1122')
        self.assertEqual(r['udh'][0]['name'], 'Response Packet Identifier (RPI)')
        self.assertEqual(r['response_packet']['rpl'], 31)
        self.assertEqual(r['response_packet']['cntr'], '0000000050')
        self.assertEqual(r['response_packet']['status'], {'code': '00', 'name': 'PoR OK'})
        self.assertEqual(r['response_packet']['data'], 'AB12800101230D08A0000001510000000F9A9000')

    def test_deliver_scts(self):
        from simtrace2_pysniff.server.decode import _decode_sm_tpdu
        oa = b'\x91' + self._bcd('79031234567')
        scts = bytes.fromhex('62802141030021')
        tpdu = (b'\x00' + bytes([11]) + oa + b'\x00\x00' + scts + b'\x00')
        r = _decode_sm_tpdu(tpdu)
        self.assertEqual(r['scts'], '2026-08-12 14:30:00 (UTC+03:00)')

    def test_deliver_pid_name(self):
        from simtrace2_pysniff.server.decode import _decode_sm_tpdu
        oa = b'\x91' + self._bcd('79031234567')
        tpdu = (b'\x00' + bytes([11]) + oa + b'\x48\x00' + b'\x00' * 7 + b'\x00')
        r = _decode_sm_tpdu(tpdu)
        self.assertEqual(r['pid_name'], 'Device Triggering Short Message')

    def test_deliver_dcs_info(self):
        from simtrace2_pysniff.server.decode import _decode_sm_tpdu
        oa = b'\x91' + self._bcd('79031234567')
        tpdu = (b'\x00' + bytes([11]) + oa + b'\x00\x11' + b'\x00' * 7 + b'\x00')
        r = _decode_sm_tpdu(tpdu)
        self.assertEqual(r['dcs_info']['group'], 'Message Marked for Automatic Deletion')
        self.assertEqual(r['dcs_info']['has_class'], True)
        self.assertEqual(r['dcs_info']['msg_class'], 1)

    def test_dcs_mwi(self):
        from simtrace2_pysniff.server.decode import _decode_dcs_full
        d = _decode_dcs_full(0xD0)
        self.assertEqual(d['group'], 'Message Waiting Indication')
        self.assertEqual(d['action'], 'store')
        self.assertEqual(d['sense'], 'inactive')
        self.assertEqual(d['indication'], 'voicemail')

    def test_udh_concat_8bit(self):
        from simtrace2_pysniff.server.decode import _decode_udh
        el = _decode_udh(bytes.fromhex('0003A10201'))
        self.assertEqual(el[0]['name'], 'Concatenated short messages, 8-bit reference number')
        self.assertEqual(el[0]['data'], {'reference': 0xA1, 'max': 2, 'seq': 1})

    def test_udh_concat_16bit(self):
        from simtrace2_pysniff.server.decode import _decode_udh
        el = _decode_udh(bytes.fromhex('080403000201'))
        self.assertEqual(el[0]['name'], 'Concatenated short message, 16-bit reference number')
        self.assertEqual(el[0]['data'], {'reference': 0x0300, 'max': 2, 'seq': 1})

    def test_udh_app_port_8bit(self):
        from simtrace2_pysniff.server.decode import _decode_udh
        el = _decode_udh(bytes.fromhex('0402B5A5'))
        self.assertEqual(el[0]['data'], {'dest_port': 0xB5, 'orig_port': 0xA5})

    def test_udh_app_port_16bit(self):
        from simtrace2_pysniff.server.decode import _decode_udh
        el = _decode_udh(bytes.fromhex('05040B8423F0'))
        self.assertEqual(el[0]['data'], {'dest_port': 0x0B84, 'orig_port': 0x23F0})

    def test_udh_special_sms(self):
        from simtrace2_pysniff.server.decode import _decode_udh
        el = _decode_udh(bytes.fromhex('01028102'))
        self.assertEqual(el[0]['data'], {'store': True, 'indication': 'fax', 'count': 2})

    def test_deliver_udh_ucs2(self):
        from simtrace2_pysniff.server.decode import _decode_sm_tpdu
        oa = b'\x91' + self._bcd('79031234567')
        ud = bytes.fromhex('050003A10201') + 'Hi'.encode('utf-16-be')
        tpdu = (b'\x40' + bytes([11]) + oa + b'\x00\x08' + b'\x00' * 7 +
                bytes([len(ud)]) + ud)
        r = _decode_sm_tpdu(tpdu)
        self.assertEqual(r['udh'][0]['data'], {'reference': 0xA1, 'max': 2, 'seq': 1})
        self.assertEqual(r['text'], 'Hi')

    def test_submit_vp_relative(self):
        from simtrace2_pysniff.server.decode import _decode_sm_tpdu
        da = b'\x81' + self._bcd('999')
        tpdu = b'\x09' + b'\x2A' + bytes([len(da)]) + da + b'\x00\x00' + b'\x8F' + b'\x00'
        r = _decode_sm_tpdu(tpdu)
        self.assertEqual(r['mti'], 'SMS-SUBMIT')
        self.assertEqual(r['vp'], '720 min')

    def test_submit_vp_absolute(self):
        from simtrace2_pysniff.server.decode import _decode_sm_tpdu
        da = b'\x81' + self._bcd('999')
        scts = bytes.fromhex('62802141030021')
        tpdu = b'\x11' + b'\x2A' + bytes([len(da)]) + da + b'\x00\x00' + scts + b'\x00'
        r = _decode_sm_tpdu(tpdu)
        self.assertEqual(r['vp'], '2026-08-12 14:30:00 (UTC+03:00)')

    def test_submit_no_ud_encoding(self):
        # Real capture: absolute VP with non-BCD bytes, no TP-UD.
        from simtrace2_pysniff.server.decode import _decode_sm_tpdu
        tpdu = bytes.fromhex('11FF038154F50004A505326C333939')
        r = _decode_sm_tpdu(tpdu)
        self.assertEqual(r['da'], '455')
        self.assertEqual(r['encoding'], '8-bit data')
        self.assertEqual(r['msg_class'], 0)
        self.assertEqual(r['vp'], 'A505326C333939')

    def test_8bit_ascii_text(self):
        from simtrace2_pysniff.server.decode import _decode_sm_tpdu
        oa = b'\x91' + self._bcd('79031234567')
        payload = b'Hello World'
        tpdu = (b'\x00' + bytes([11]) + oa + b'\x00\x04' + b'\x00' * 7 +
                bytes([len(payload)]) + payload)
        r = _decode_sm_tpdu(tpdu)
        self.assertEqual(r['encoding'], '8-bit data')
        self.assertEqual(r['text'], 'Hello World')

    def test_8bit_ascii_ctrl_replaced(self):
        from simtrace2_pysniff.server.decode import _decode_sm_tpdu
        oa = b'\x91' + self._bcd('79031234567')
        payload = b'Hi\x00There'
        tpdu = (b'\x00' + bytes([11]) + oa + b'\x00\x04' + b'\x00' * 7 +
                bytes([len(payload)]) + payload)
        r = _decode_sm_tpdu(tpdu)
        self.assertEqual(r['text'], 'Hi\u00b7There')

    def test_8bit_high_text(self):
        from simtrace2_pysniff.server.decode import _decode_sm_tpdu
        oa = b'\x91' + self._bcd('79031234567')
        payload = '\u00e9\u00fc\u00f1'.encode('latin-1')
        tpdu = (b'\x00' + bytes([11]) + oa + b'\x00\x04' + b'\x00' * 7 +
                bytes([len(payload)]) + payload)
        r = _decode_sm_tpdu(tpdu)
        self.assertEqual(r['text'], '\u00e9\u00fc\u00f1')

    def test_8bit_mixed_no_text(self):
        from simtrace2_pysniff.server.decode import _decode_sm_tpdu
        oa = b'\x91' + self._bcd('79031234567')
        payload = b'\x00\x01\xff\xfe'
        tpdu = (b'\x00' + bytes([11]) + oa + b'\x00\x04' + b'\x00' * 7 +
                bytes([len(payload)]) + payload)
        r = _decode_sm_tpdu(tpdu)
        self.assertNotIn('text', r)
        self.assertEqual(r['payload'], '0001FFFE')


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
        self.assertEqual(r['cmd']['duration'], {'value': 30, 'unit': 'seconds'})

    def test_send_short_message_tpdu(self):
        r = decode_message(bytes.fromhex(
            '801200004AD04881030113008202818305000B3B11FF038199F90004A531'
            '494D45492038363732333130353634323832383020494D53492032353031'
            '3937373030313932373935204556454E5420319000'))
        self.assertEqual(r['cmd']['type'], 'SEND SHORT MESSAGE')
        self.assertEqual(r['cmd']['tpdu']['mti'], 'SMS-SUBMIT')
        self.assertEqual(r['cmd']['tpdu']['da'], '999')

    def test_send_short_message_rich_tpdu(self):
        r = decode_message(bytes.fromhex(
            '801200001AD01881030113008202818305000B0B0101038199F9000402'
            '48699000'))
        t = r['cmd']['tpdu']
        self.assertEqual(r['cmd']['type'], 'SEND SHORT MESSAGE')
        self.assertEqual(t['mti'], 'SMS-SUBMIT')
        self.assertEqual(t['da'], '999')
        self.assertEqual(t['pid_name'], 'SME-to-SME (implicit)')
        self.assertEqual(t['encoding'], '8-bit data')
        self.assertEqual(t['text'], 'Hi')

    def test_setup_menu_long_form_length(self):
        # Real Mi A1 startup trace: D0 length encoded as 0x81 0xBC (188 bytes).
        r = decode_message(bytes.fromhex(
            '80120000BFD081BC810301250082028182051580004D0065006700610046'
            '006F006E00500052004F8F100180041C0435043304300424043E043D8F18'
            '02800420043004370432043B043504470435043D0438044F8F0C03800421'
            '043F043E044004428F100480041D043E0432043E0441044204388F100580'
            '04240438043D0430043D0441044B8F1006800421043F044004300432043A'
            '04308F100780041E043104490435043D043804358F188080041A0430043B'
            '043504390434043E0441043A043E043F9000'))
        self.assertEqual(r['cat_command'], 'SET UP MENU')
        self.assertEqual(r['cmd']['title'], 'MegaFonPRO')
        self.assertEqual(r['cmd']['items'][0], {'id': 1, 'text': 'МегаФон'})


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

    def test_ucs2_variant_90(self):
        from simtrace2_pysniff.server.decode import _decode_annex_a
        self.assertEqual(_decode_annex_a(b'\x90' + 'Привет'.encode('utf_16_be')), 'Привет')

    def test_gsm7_packed(self):
        from simtrace2_pysniff.server.decode import _decode_annex_a
        self.assertEqual(_decode_annex_a(bytes.fromhex('41b6390c')), 'Alfa')


class TestPnnSpn(unittest.TestCase):
    def test_pnn_full_name(self):
        from simtrace2_pysniff.server.decode import _decode_pnn
        r = _decode_pnn(bytes.fromhex('43058441b6390c' + 'ff' * 13))
        self.assertEqual(r['full'], 'Alfa')

    def test_pnn_ucs2(self):
        from simtrace2_pysniff.server.decode import _decode_pnn
        v = b'\x90' + 'Привет'.encode('utf-16-be')
        r = _decode_pnn(b'\x43' + bytes([len(v)]) + v)
        self.assertEqual(r['full'], 'Привет')

    def test_spn_ucs2_90(self):
        from simtrace2_pysniff.server.decode import _decode_spn
        r = _decode_spn(b'\x00' + b'\x90' + 'Привет'.encode('utf-16-be'))
        self.assertEqual(r['name'], 'Привет')

    def test_spn_gsm7(self):
        from simtrace2_pysniff.server.decode import _decode_spn
        r = _decode_spn(b'\x00' + bytes.fromhex('41b6390c'))
        self.assertEqual(r['name'], 'Alfa')


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


class TestAtrPps(unittest.TestCase):
    def test_atr_simple_t0_only(self):
        from simtrace2_pysniff.server.decode import _decode_atr
        # 3B 00: direct, T0=00, no interface bytes, 0 historical bytes, only T=0 → no TCK
        r = _decode_atr(bytes.fromhex('3B00'))
        self.assertEqual(r['convention'], 'direct')
        self.assertEqual(r['t0'], '00')
        self.assertEqual(r['historical_len'], 0)
        self.assertNotIn('tck', r)

    def test_atr_ta1(self):
        from simtrace2_pysniff.server.decode import _decode_atr
        # 3B 12 11 00 00: TA1=11 (Fi=1,Di=1), 2 historical bytes, T=0 → no TCK
        r = _decode_atr(bytes.fromhex('3B12110000'))
        self.assertEqual(r['convention'], 'direct')
        self.assertEqual(r['interface'][0]['name'], 'TA1')
        self.assertEqual(r['interface'][0]['f'], 372)
        self.assertEqual(r['interface'][0]['d'], 1)
        self.assertEqual(r['historical_len'], 2)
        self.assertNotIn('tck', r)

    def test_atr_td1_t1_has_tck(self):
        from simtrace2_pysniff.server.decode import _decode_atr
        # 3B 80 01 80 31 80 66 ... : construct T=1 with TCK
        # T0=80 → TD1 present, 0 historical; TD1=01 (T=1, no more interface); then TCK
        # bytes: 3B 80 01 xx where xx = XOR(80,01) = 81
        r = _decode_atr(bytes.fromhex('3B800181'))
        self.assertEqual(r['protocols'], ['T=1'])
        self.assertIn('tck', r)
        self.assertTrue(r['tck_valid'])
        self.assertEqual(r['tck'], '81')

    def test_atr_inverse_convention(self):
        from simtrace2_pysniff.server.decode import _decode_atr
        # Inverse: TS=3F, then inverted bytes. Take direct ATR "3B 00" and invert body.
        # Inverted 0x00 is 0x00, so ATR = 3F 00 → convention inverse, T0=00.
        r = _decode_atr(bytes.fromhex('3F00'))
        self.assertEqual(r['convention'], 'inverse')
        self.assertEqual(r['t0'], '00')

    def test_atr_historical_life_cycle(self):
        from simtrace2_pysniff.server.decode import _decode_atr
        # T0 = 0x03 (3 historical bytes); historical = 80 00 05 (life cycle: operational)
        r = _decode_atr(bytes.fromhex('3B03800005'))
        self.assertEqual(r['historical_len'], 3)
        self.assertEqual(r['historical']['category'], 'status information (life cycle)')
        self.assertEqual(r['historical']['life_cycle'], 'operational state (activated)')

    def test_pps(self):
        from simtrace2_pysniff.server.decode import _decode_pps
        # FF 10 11 xx: PPS0=10 (T=0, PPS1 present), PPS1=11 (Fi=1,Di=1), PCK=XOR(FF,10,11)=FE
        r = _decode_pps(bytes.fromhex('FF1011FE'))
        self.assertEqual(r['protocol'], 'T=0')
        self.assertEqual(r['fi_di']['f'], 372)
        self.assertEqual(r['fi_di']['d'], 1)
        self.assertTrue(r['pck_valid'])
        self.assertEqual(r['pck'], 'FE')


class TestSummary(unittest.TestCase):
    def test_select_path_from_mf(self):
        r = decode_message(bytes.fromhex('a0a40804022fe29000'))
        self.assertEqual(r['summary'], 'Path from MF: 2FE2 (EF_ICCID), Return FCI template')

    def test_select_by_file_id(self):
        r = decode_message(bytes.fromhex('a0a40000023f009000'))
        self.assertEqual(r['summary'], 'DF/EF/MF by file ID: 3F00 (MF)')

    def test_read_record(self):
        r = decode_message(bytes.fromhex('a0b2010400'))
        self.assertEqual(r['summary'], 'Record number: 1, absolute mode (record number in P1)')

    def test_verify_pin_no_leak(self):
        # VERIFY PIN with P2 = 0x01 (PIN Appl 1): the PIN value must not leak.
        r = decode_message(bytes.fromhex('0020000108' + '12' * 8))
        self.assertEqual(r['summary'], 'PIN Appl 1')
        self.assertNotIn('12', r['summary'])

    def test_fetch_setup_menu(self):
        r = decode_message(bytes.fromhex(
            '8012000030D02E810301250082028182050B416C6661204D6F62696C'
            '658F16808112089DB0C1C2C0BEB9BAB82F53657474696E67739000'))
        self.assertEqual(r['summary'], 'Alfa Mobile, 1 item')

    def test_envelope_sms_pp(self):
        r = decode_message(bytes.fromhex(
            '80C2000022D120020283810607919740430900F40B1104038154F50004'
            '628021410300210248699000'))
        self.assertEqual(r['summary'], 'SMSC +79043490004, SMS-DELIVER from 455 «Hi»')

    def test_terminal_response(self):
        r = decode_message(bytes.fromhex(
            '80140000108103010300020282810301000402011E9000'))
        self.assertEqual(r['summary'], '→ POLL INTERVAL, Command performed successfully')

    def test_get_response_for(self):
        r = decode_message(bytes.fromhex('a0c000000f'),
                           prev={'ins_name': 'SELECT', 'sw1': '61'})
        self.assertEqual(r['summary'], 'response for SELECT')


class TestSelectPath(unittest.TestCase):
    def test_path_adf_alias(self):
        # 7FFF = current ADF; 6F05 after it → EF_LI (USIM).
        r = decode_message(bytes.fromhex('a0a40804047fff6f059000'))
        self.assertEqual(r['body']['note'], 'current ADF/EF_LI')
        self.assertEqual(r['summary'],
                         'Path from MF: 7FFF6F05 (current ADF/EF_LI), Return FCI template')

    def test_path_full(self):
        r = decode_message(bytes.fromhex('a0a40804067f107f206f079000'))
        self.assertEqual(r['body']['note'], 'DF_TELECOM/DF_GSM/EF_IMSI')

    def test_path_current_df(self):
        # P1 = 0x09 → 'Path from current DF' (no 7FFF/3F00 prefix).
        r = decode_message(bytes.fromhex('a0a40904046f076f049000'))
        self.assertEqual(r['p1']['name'], 'Path from current DF')
        self.assertEqual(r['body']['note'], 'EF_IMSI/EF_IMPU')

    def test_path_isim_adf_alias(self):
        # 7FFF 6F04 → EF_IMPU (ISIM).
        r = decode_message(bytes.fromhex('a0a40804047fff6f049000'))
        self.assertEqual(r['body']['note'], 'current ADF/EF_IMPU')

    def test_path_df_child(self):
        # 7FFF 5F3B 4F20 → current ADF / DF_GSM_ACCESS / EF_Kc.
        r = decode_message(bytes.fromhex('a0a40804067fff5f3b4f209000'))
        self.assertEqual(r['body']['note'], 'current ADF/DF_GSM_ACCESS/EF_Kc')

    def test_path_df_child_disambiguates_fid(self):
        # 7F10 5F3B 4F47 → DF_TELECOM / DF_MULTIMEDIA / EF_MML (5F3B is
        # DF_MULTIMEDIA here, not DF_GSM_ACCESS).
        r = decode_message(bytes.fromhex('a0a40804067f105f3b4f479000'))
        self.assertEqual(r['body']['note'], 'DF_TELECOM/DF_MULTIMEDIA/EF_MML')

    def test_path_phonebook(self):
        r = decode_message(bytes.fromhex('a0a40804067f105f3a4f229000'))
        self.assertEqual(r['body']['note'], 'DF_TELECOM/DF_PHONEBOOK/EF_PSC')

    def test_path_5gs(self):
        r = decode_message(bytes.fromhex('a0a40804067fff5fc04f019000'))
        self.assertEqual(r['body']['note'], 'current ADF/DF_5GS/EF_5GS3GPPLOCI')


class TestFileDecoders(unittest.TestCase):
    def test_imsi(self):
        from simtrace2_pysniff.server.decode import _decode_file_data
        f = _decode_file_data('6f07', bytes.fromhex('082905102143658709'))
        self.assertEqual(f['imsi'], '250011234567890')

    def test_imsi_real_card(self):
        # Real capture (Mi A1): 08 length byte + 8 bytes, first nibble is the
        # TS 24.008 type+parity indicator (9 = IMSI, odd).
        from simtrace2_pysniff.server.decode import _decode_file_data
        f = _decode_file_data('6f07', bytes.fromhex('082905917700917259'))
        self.assertEqual(f['imsi'], '250197700192795')

    def test_iccid(self):
        from simtrace2_pysniff.server.decode import _decode_file_data
        f = _decode_file_data('2fe2', bytes.fromhex('98891020000000460012'))
        self.assertEqual(f['iccid'], '89980102000000640021')

    def test_li(self):
        from simtrace2_pysniff.server.decode import _decode_file_data
        f = _decode_file_data('6f05', b'enru')
        self.assertEqual(f['languages'], ['en', 'ru'])

    def test_adn(self):
        from simtrace2_pysniff.server.decode import _decode_file_data
        f = _decode_file_data('6f3a', bytes.fromhex(
            '42204841203120536963FFFFFFFFFFFF06810628560810FFFFFFFFFFFFFF'))
        self.assertEqual(f['name'], 'B HA 1 Sic')
        self.assertEqual(f['number'], '6082658001')

    def test_adn_ber_tlv_fallback(self):
        # Non-ADN data (BER-TLV) must not be decoded as a name/number.
        from simtrace2_pysniff.server.decode import _decode_file_data
        raw = bytes.fromhex(
            'A0348001078120E823FF53C3E271754A644ED63DEFCF24A916387E3C585F'
            '0820CF3E27841852F7820400000000830400000000840102'
            'FFFFFFFFFFFFFFFFFFFFFFFFFFFF')
        f = _decode_file_data('6fc7', raw)
        self.assertNotIn('name', f)
        self.assertIn('raw', f)

    def test_ust(self):
        from simtrace2_pysniff.server.decode import _decode_file_data
        f = _decode_file_data('6f38', bytes.fromhex('07'))
        self.assertEqual([s['n'] for s in f['services']], [1, 2, 3])
        self.assertEqual(f['services'][0]['name'], 'Local Phone Book')

    def test_plmn_list(self):
        from simtrace2_pysniff.server.decode import _decode_file_data
        f = _decode_file_data('6f30', bytes.fromhex('42f095'))
        self.assertEqual(len(f['plmns']), 1)
        self.assertIn('mcc', f['plmns'][0])
        self.assertIn('mnc', f['plmns'][0])

    def test_dir(self):
        from simtrace2_pysniff.server.decode import _decode_file_data
        f = _decode_file_data('2f00', bytes.fromhex(
            '612b4f10a0000000871002fffff00189000001ff50074d656761466f6e'
            '730ea00c80011781025f408203454150ffffffffffffffffffffffffffffffffffffff'))
        self.assertEqual(f['applications'][0]['label'], 'MegaFon')
        self.assertEqual(f['applications'][0]['aid'], 'A0000000871002FFFFF00189000001FF')
        eap = f['applications'][0]['eap']
        self.assertEqual(eap['eap_types'], ['EAP-AKA'])
        self.assertEqual(eap['dfs'], ['5f40'])
        self.assertEqual(eap['label'], 'EAP')

    def test_nai_empty_record(self):
        from simtrace2_pysniff.server.decode import _decode_file_data
        # Unused ISIM record (all FF) must be 'empty', not garbage text.
        f = _decode_file_data('6f04', b'\xff' * 75)
        self.assertTrue(f['empty'])
        self.assertNotIn('text', f)

    def test_nai(self):
        from simtrace2_pysniff.server.decode import _decode_file_data
        f = _decode_file_data('6f04', bytes.fromhex(
            '80357369703a32353030323639333537373333363840696d732e6d6e63'
            '3030322e6d63633235302e336770706e6574776f726b2e6f7267'))
        self.assertEqual(f['text'], 'sip:250026935773368@ims.mnc002.mcc250.3gppnetwork.org')

    def test_plmn_wact(self):
        from simtrace2_pysniff.server.decode import _decode_file_data
        # TS 51.011 §10.3.35: 5-byte entries (3 PLMN + 2 access tech).
        f = _decode_file_data('6f60', bytes.fromhex('52f020400052f0208000'))
        self.assertEqual(f['plmns'][0]['mcc'], '250')
        self.assertEqual(f['plmns'][0]['mnc'], '02')
        self.assertEqual(f['plmns'][0]['access_tech'], 'E-UTRAN NB-S1, E-UTRAN WB-S1')
        self.assertEqual(f['plmns'][1]['access_tech'], 'UTRAN')

    def test_sms_record(self):
        from simtrace2_pysniff.server.decode import _decode_file_data
        # status 0x07 (MO, to be sent) + empty SMSC (len 0) + SMS-SUBMIT TPDU
        rec = bytes.fromhex('0700') + bytes.fromhex('01ff038199f90004024869')
        f = _decode_file_data('6f3c', rec)
        self.assertEqual(f['direction'], 'MO')
        self.assertEqual(f['status'], 'message to be sent')
        self.assertEqual(f['tpdu']['mti'], 'SMS-SUBMIT')
        self.assertEqual(f['tpdu']['da'], '999')
        self.assertEqual(f['tpdu']['text'], 'Hi')

    def test_loci(self):
        from simtrace2_pysniff.server.decode import _decode_file_data
        # EF_LOCI (11 bytes): TMSI 4 + LAI 5 + TMSI_TIME 1 + status 1.
        f = _decode_file_data('6f7e', bytes.fromhex('1e731e5752f09969c50000'))
        self.assertEqual(f['tmsi'], '1E731E57')
        self.assertEqual(f['mcc'], '250')
        self.assertEqual(f['mnc'], '99')
        self.assertEqual(f['lac'], '0x69C5')
        self.assertEqual(f['location_update_status'], '0x00')

    def test_epsloci(self):
        from simtrace2_pysniff.server.decode import _decode_file_data
        # EF_EPSLOCI (18 bytes): GUTI 12 + TAI 5 + status 1.
        f = _decode_file_data('6fe3', bytes.fromhex('0bf652f0998001b0fb91192652f0991d9900'))
        self.assertEqual(f['guti'], '0BF652F0998001B0FB911926')
        self.assertEqual(f['eps_update_status'], '0x00')

    def test_psloci(self):
        from simtrace2_pysniff.server.decode import _decode_file_data
        # EF_PSLOCI (14 bytes): P-TMSI 4 + sig 3 + RAI 6 + status 1.
        f = _decode_file_data('6f73', bytes.fromhex('1111111122222252f0991d990001'))
        self.assertEqual(f['p_tmsi'], '11111111')
        self.assertEqual(f['p_tmsi_signature'], '222222')
        self.assertEqual(f['mcc'], '250')
        self.assertEqual(f['mnc'], '99')
        self.assertEqual(f['lac'], '0x1D99')
        self.assertEqual(f['rac'], '0x00')
        self.assertEqual(f['update_status'], '0x01')

    def test_epsnsc(self):
        from simtrace2_pysniff.server.decode import _decode_file_data
        # EF_EPSNSC record: A0 { 80 KSI_ASME, 81 K_ASME, 82/83 NAS counts, 84 algos }.
        f = _decode_file_data('6fe4', bytes.fromhex(
            'a0188001018104aabbccdd820400000003830400000004840102'))
        self.assertEqual(f['ksi_asme'], '01')
        self.assertEqual(f['k_asme'], 'AABBCCDD')
        self.assertEqual(f['uplink_nas_count'], 3)
        self.assertEqual(f['downlink_nas_count'], 4)
        self.assertEqual(f['nas_algorithms'], '02')

    def test_read_binary_direct(self):
        # SELECT EF_IMSI then READ BINARY → file decoded in body.
        r = decode_message(bytes.fromhex('00b0000009') +
                           bytes.fromhex('082905102143658709') + bytes.fromhex('9000'),
                           prev={'sel': {'fid': '6f07', 'name': 'EF_IMSI'}})
        self.assertEqual(r['file']['imsi'], '250011234567890')
        self.assertIn('IMSI 250011234567890', r['summary'])

    def test_read_binary_offset_skip(self):
        r = decode_message(bytes.fromhex('00b00100') +
                           bytes.fromhex('082905102143658709') + bytes.fromhex('9000'),
                           prev={'sel': {'fid': '6f07'}})
        self.assertNotIn('file', r)

    def test_read_binary_offset_form(self):
        # b8 of P1 = 0 → offset = b7..b1 << 8 | P2.
        r = decode_message(bytes.fromhex('00b0010000'), prev=None)
        self.assertEqual(r['p1p2'], {'value': 0x0100, 'offset': 256})
        self.assertIn('Offset: 0x0100', r['summary'])

    def test_read_binary_sfi_form(self):
        # b8 of P1 = 1 → SFI referencing: SFI = b5..b1, P2 = offset.
        r = decode_message(bytes.fromhex('00d68b000b') +
                           bytes.fromhex('0000000000000000000000') + bytes.fromhex('9000'),
                           prev=None)
        self.assertEqual(r['p1p2'], {'value': 0x8B00, 'sfi': 11, 'offset': 0})
        self.assertIn('SFI 11', r['summary'])
        self.assertNotIn('offset 0', r['summary'])

    def test_read_binary_sfi_offset(self):
        # SFI referencing with a non-zero offset (P2 = 5).
        r = decode_message(bytes.fromhex('00b08b0500'), prev=None)
        self.assertEqual(r['p1p2'], {'value': 0x8B05, 'sfi': 11, 'offset': 5})
        self.assertIn('SFI 11, offset 5', r['summary'])

    def test_read_via_get_response(self):
        iccid = bytes.fromhex('98891020000000460012')
        gr = bytes.fromhex('00c00000') + bytes([len(iccid)]) + iccid + bytes.fromhex('9000')
        r = decode_message(gr, prev={'ins': 0xB0, 'ins_name': 'READ BINARY', 'sw1': '61',
                                     'sel': {'fid': '2fe2'}, 'file_ok': True})
        self.assertEqual(r['file']['iccid'], '89980102000000640021')

    def test_get_response_file_ok_false(self):
        iccid = bytes.fromhex('98891020000000460012')
        gr = bytes.fromhex('00c00000') + bytes([len(iccid)]) + iccid + bytes.fromhex('9000')
        r = decode_message(gr, prev={'ins': 0xB0, 'ins_name': 'READ BINARY', 'sw1': '61',
                                     'sel': {'fid': '2fe2'}, 'file_ok': False})
        self.assertNotIn('file', r)

    def test_search_record_numbers(self):
        # SEARCH RECORD returns 61xx; GET RESPONSE carries the record numbers.
        numbers = bytes(range(3, 21))  # 3..20
        gr = bytes.fromhex('00c00000') + bytes([len(numbers)]) + numbers + bytes.fromhex('9000')
        r = decode_message(gr, prev={'ins': 0xA2, 'ins_name': 'SEARCH RECORD', 'sw1': '61',
                                     'sel': {'fid': '6f3a'}, 'file_ok': True})
        self.assertEqual(r['file']['record_numbers'], list(range(3, 21)))
        self.assertIn('18 record(s)', r['summary'])

    def test_select_target_fid(self):
        from simtrace2_pysniff.server.decode import select_target_fid
        self.assertEqual(select_target_fid({'p1': {'raw': '00'}, 'body': {'hex': '6f07'}}), '6f07')
        self.assertEqual(select_target_fid({'p1': {'raw': '08'}, 'body': {'hex': '7fff6f05'}}), '6f05')
        self.assertIsNone(select_target_fid({'p1': {'raw': '04'}, 'body': {'hex': 'a0000000871002'}}))
        self.assertIsNone(select_target_fid({'p1': {'raw': '08'}, 'body': {'hex': '7fff'}}))


class TestSelectionTracking(unittest.TestCase):
    def test_select_then_read(self):
        import tempfile
        from simtrace2_pysniff.server.database import Database
        with tempfile.NamedTemporaryFile(suffix='.db') as tmp:
            db = Database(tmp.name)
            sid = db.create_session('capture')
            db.insert_message(sid, 0.0, 'atr', b'\x3b\x00')
            db.insert_message(sid, 0.1, 'tpdu', bytes.fromhex('a0a40804047fff6f079000'))
            db.insert_message(sid, 0.2, 'tpdu',
                              bytes.fromhex('00b0000009') + bytes.fromhex('082905102143658709') + bytes.fromhex('9000'))
            msgs = db.get_messages(sid)
            read = msgs[2]
            self.assertEqual(read['decoded']['file']['imsi'], '250011234567890')

    def test_atr_resets_selection(self):
        import tempfile
        from simtrace2_pysniff.server.database import Database
        with tempfile.NamedTemporaryFile(suffix='.db') as tmp:
            db = Database(tmp.name)
            sid = db.create_session('capture')
            db.insert_message(sid, 0.0, 'tpdu', bytes.fromhex('a0a40804047fff6f079000'))
            db.insert_message(sid, 0.1, 'atr', b'\x3b\x00')
            db.insert_message(sid, 0.2, 'tpdu',
                              bytes.fromhex('00b0000009') + bytes.fromhex('082905102143658709') + bytes.fromhex('9000'))
            msgs = db.get_messages(sid)
            self.assertNotIn('file', msgs[2]['decoded'])

    def test_timeout_wt_keeps_selection(self):
        # A waiting-time timeout interrupts one TPDU but the card stays
        # selected, so the selection must not be reset.
        import tempfile
        from simtrace2_pysniff.server.database import Database
        with tempfile.NamedTemporaryFile(suffix='.db') as tmp:
            db = Database(tmp.name)
            sid = db.create_session('capture')
            db.insert_message(sid, 0.0, 'tpdu', bytes.fromhex('a0a40804047fff6f079000'))
            db.insert_message(sid, 0.1, 'change', b'', 1 << 4)  # TIMEOUT_WT
            db.insert_message(sid, 0.2, 'tpdu',
                              bytes.fromhex('00b0000009') + bytes.fromhex('082905102143658709') + bytes.fromhex('9000'))
            msgs = db.get_messages(sid)
            self.assertEqual(msgs[2]['decoded']['file']['imsi'], '250011234567890')

    def test_reset_assert_resets_selection(self):
        import tempfile
        from simtrace2_pysniff.server.database import Database
        with tempfile.NamedTemporaryFile(suffix='.db') as tmp:
            db = Database(tmp.name)
            sid = db.create_session('capture')
            db.insert_message(sid, 0.0, 'tpdu', bytes.fromhex('a0a40804047fff6f079000'))
            db.insert_message(sid, 0.1, 'change', b'', 1 << 2)  # RESET_ASSERT
            db.insert_message(sid, 0.2, 'tpdu',
                              bytes.fromhex('00b0000009') + bytes.fromhex('082905102143658709') + bytes.fromhex('9000'))
            msgs = db.get_messages(sid)
            self.assertNotIn('file', msgs[2]['decoded'])

    def test_gap_resets_selection(self):
        # A capture gap (device disconnected/reconnected) means messages may
        # have been missed, so the selection must be reset.
        import tempfile
        from simtrace2_pysniff.server.database import Database
        with tempfile.NamedTemporaryFile(suffix='.db') as tmp:
            db = Database(tmp.name)
            sid = db.create_session('capture')
            db.insert_message(sid, 0.0, 'tpdu', bytes.fromhex('a0a40804047fff6f079000'))
            db.insert_message(sid, 0.1, 'gap', b'', 0)
            db.insert_message(sid, 0.2, 'tpdu',
                              bytes.fromhex('00b0000009') + bytes.fromhex('082905102143658709') + bytes.fromhex('9000'))
            msgs = db.get_messages(sid)
            self.assertNotIn('file', msgs[2]['decoded'])

    def test_failed_select_keeps_selection(self):
        # A SELECT that fails (6A82) must not change the current file.
        import tempfile
        from simtrace2_pysniff.server.database import Database
        with tempfile.NamedTemporaryFile(suffix='.db') as tmp:
            db = Database(tmp.name)
            sid = db.create_session('capture')
            db.insert_message(sid, 0.0, 'tpdu', bytes.fromhex('a0a40804047fff6f079000'))
            db.insert_message(sid, 0.1, 'tpdu', bytes.fromhex('a0a40804047fff6f136a82'))
            db.insert_message(sid, 0.2, 'tpdu',
                              bytes.fromhex('00b0000009') + bytes.fromhex('082905102143658709') + bytes.fromhex('9000'))
            msgs = db.get_messages(sid)
            read = msgs[2]
            self.assertEqual(read['decoded']['file']['imsi'], '250011234567890')

    def test_record_op_on_transparent_is_stale(self):
        # SELECT a transparent EF, then READ RECORD → selection is stale, so
        # we must not decode garbage.
        import tempfile
        from simtrace2_pysniff.server.database import Database
        with tempfile.NamedTemporaryFile(suffix='.db') as tmp:
            db = Database(tmp.name)
            sid = db.create_session('capture')
            db.insert_message(sid, 0.0, 'tpdu', bytes.fromhex('a0a40804047fff6f056123'))
            db.insert_message(sid, 0.1, 'tpdu',
                              bytes.fromhex('00c000000a') + bytes.fromhex('62088202012183026f05') + bytes.fromhex('9000'))
            db.insert_message(sid, 0.2, 'tpdu',
                              bytes.fromhex('00b2010408') + bytes.fromhex('800101a010a4068301019501') + bytes.fromhex('9000'))
            msgs = db.get_messages(sid)
            read = msgs[2]
            self.assertTrue(read['decoded']['file']['stale'])

    def test_sfi_update_resolves_eps_loci(self):
        # SFI referencing must resolve the target EF (EF_EPSLOCI), not the
        # last-selected file.
        import tempfile
        from simtrace2_pysniff.server.database import Database
        with tempfile.NamedTemporaryFile(suffix='.db') as tmp:
            db = Database(tmp.name)
            sid = db.create_session('capture')
            db.insert_message(sid, 0.0, 'atr', b'\x3b\x00')
            db.insert_message(sid, 0.1, 'tpdu', bytes.fromhex('00a40804027fff612a'))
            db.insert_message(sid, 0.2, 'tpdu',
                              bytes.fromhex('00d69e0012') +
                              bytes.fromhex('0bf652f0998001b0fb91192652f0991d9900') +
                              bytes.fromhex('9000'))
            msgs = db.get_messages(sid)
            up = msgs[2]
            self.assertEqual(up['decoded']['file']['ef'], 'EF_EPSLOCI')
            self.assertEqual(up['decoded']['file']['guti'], '0BF652F0998001B0FB911926')

    def test_sfi_unknown_not_misattributed(self):
        # An SFI not in the map must not fall back to the selected file.
        import tempfile
        from simtrace2_pysniff.server.database import Database
        with tempfile.NamedTemporaryFile(suffix='.db') as tmp:
            db = Database(tmp.name)
            sid = db.create_session('capture')
            db.insert_message(sid, 0.0, 'tpdu', bytes.fromhex('00a40804022fe2611e'))
            db.insert_message(sid, 0.1, 'tpdu', bytes.fromhex('00d6890001079000'))
            msgs = db.get_messages(sid)
            up = msgs[1]
            self.assertTrue(up['decoded']['file']['unknown'])
            self.assertEqual(up['decoded']['file']['sfi'], 9)

    def test_record_sfi_sets_current_ef(self):
        # A record command with a valid SFI sets that file as the current EF,
        # so a subsequent non-SFI record op targets it (TS 102 221 §11.1.2).
        import tempfile
        from simtrace2_pysniff.server.database import Database
        with tempfile.NamedTemporaryFile(suffix='.db') as tmp:
            db = Database(tmp.name)
            sid = db.create_session('capture')
            db.insert_message(sid, 0.0, 'atr', b'\x3b\x00')
            db.insert_message(sid, 0.1, 'tpdu', bytes.fromhex('00a40804047fff6f7e611e'))
            db.insert_message(sid, 0.2, 'tpdu', bytes.fromhex('00dc01c436') +
                              bytes.fromhex('a0348001018104aabbccdd820400000003830400000004840102') +
                              bytes.fromhex('9000'))
            db.insert_message(sid, 0.3, 'tpdu', bytes.fromhex('00dc010436') +
                              bytes.fromhex('a0348001078104aabbccdd820400000004830400000003840102') +
                              bytes.fromhex('9000'))
            msgs = db.get_messages(sid)
            self.assertEqual(msgs[2]['decoded']['file']['ef'], 'EF_EPSNSC')
            # 0.3 has P2=04 (no SFI) → must still target EF_EPSNSC.
            self.assertEqual(msgs[3]['decoded']['file']['ef'], 'EF_EPSNSC')

    def test_channel_selection_not_clobbered(self):
        # A SELECT on channel 1 (CLA 01) must not change channel 0's selection.
        import tempfile
        from simtrace2_pysniff.server.database import Database
        with tempfile.NamedTemporaryFile(suffix='.db') as tmp:
            db = Database(tmp.name)
            sid = db.create_session('capture')
            db.insert_message(sid, 0.0, 'tpdu', bytes.fromhex('00a40804047fff6f409000'))
            db.insert_message(sid, 0.1, 'tpdu', bytes.fromhex('01a40804047fff6f02611e'))
            db.insert_message(sid, 0.2, 'tpdu',
                              bytes.fromhex('00b2010427') +
                              bytes.fromhex('8109089cbeb920bdbebcb5c0ffffffffffffffffffffffffff07919752738981f7ffffffffffff') +
                              bytes.fromhex('9000'))
            msgs = db.get_messages(sid)
            up = msgs[2]
            # channel 0 still selects EF_MSISDN, not channel 1's EF_IMPI.
            self.assertEqual(up['decoded']['file']['ef'], 'EF_MSISDN')


class TestSfiResolution(unittest.TestCase):
    def test_sfi_resolved(self):
        r = decode_message(
            bytes.fromhex('00d69e00120bf652f0998001b0fb91192652f0991d99009000'),
            prev={'sfi_map': {30: '6fe3'}})
        self.assertEqual(r['file']['ef'], 'EF_EPSLOCI')
        self.assertEqual(r['file']['guti'], '0BF652F0998001B0FB911926')

    def test_sfi_unknown(self):
        r = decode_message(bytes.fromhex('00d6880001079000'), prev={'sfi_map': {}})
        self.assertTrue(r['file']['unknown'])
        self.assertEqual(r['file']['sfi'], 8)

    def test_sfi_read_resolves(self):
        # READ BINARY via SFI needs no prev['sel']; only the SFI map.
        r = decode_message(bytes.fromhex('00b08b000b') +
                           bytes.fromhex('1e731e5752f09969c50000') + bytes.fromhex('9000'),
                           prev={'sfi_map': {11: '6f7e'}})
        self.assertEqual(r['file']['ef'], 'EF_LOCI')
        self.assertEqual(r['file']['tmsi'], '1E731E57')

    def test_selected_df_fid(self):
        from simtrace2_pysniff.server.decode import selected_df_fid, sfi_table
        self.assertEqual(selected_df_fid({'ins_hex': 'a4', 'p1': {'raw': '08'},
                                          'body': {'hex': '3f007fff'}}), '7fff')
        self.assertEqual(selected_df_fid({'ins_hex': 'a4', 'p1': {'raw': '00'},
                                          'body': {'hex': '7f20'}}), '7f20')
        self.assertIsNone(selected_df_fid({'ins_hex': 'a4', 'p1': {'raw': '00'},
                                           'body': {'hex': '6f7e'}}))
        self.assertIsNone(selected_df_fid({'ins_hex': 'b0'}))
        self.assertEqual(sfi_table('7fff')[0x1e], '6fe3')
        self.assertEqual(sfi_table('3f00')[0x1e], '2f00')
        self.assertEqual(sfi_table('7fff')[0x17], '6f06')
        self.assertEqual(sfi_table('7fff')[0x1a], '6fc6')
        self.assertEqual(sfi_table('6f7e'), {})

    def test_record_p2_sfi(self):
        # READ RECORD P2 = 0xBC → SFI = 0xBC>>3 = 23, mode = 0x04.
        r = decode_message(bytes.fromhex('00b204bc00'), prev={})
        self.assertEqual(r['p2']['sfi'], 23)
        self.assertIn('absolute mode', r['p2']['bits'][0])

    def test_update_record_sfi_resolves(self):
        # UPDATE RECORD P2 = 0xC4 → SFI 24 = EF_EPSNSC (record 54 B).
        raw = bytes.fromhex('00dc01c436') + bytes.fromhex(
            'a0348001078120ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
            '8204ffffffff8304ffffffff840100') + bytes.fromhex('9000')
        r = decode_message(raw, prev={'sfi_map': {24: '6fe4'}})
        self.assertEqual(r['file']['ef'], 'EF_EPSNSC')
        self.assertEqual(r['file']['ksi_asme'], '07')


class TestP1P2(unittest.TestCase):
    def test_search_record_p2_modes(self):
        r = decode_message(bytes.fromhex('00a2010508ffffffffffffffff9000'))
        self.assertEqual(r['p2']['bits'], ['Simple search (backward)'])
        r = decode_message(bytes.fromhex('00a2010708ffffffffffffffff9000'))
        self.assertEqual(r['p2']['bits'], ['Proprietary search'])

    def test_pin_p2_reference(self):
        r = decode_message(bytes.fromhex('0020000108' + '12' * 8))
        self.assertEqual(r['p1']['name'], 'No indication')
        self.assertEqual(r['p2']['name'], 'PIN Appl 1')
        r = decode_message(bytes.fromhex('0020008108' + '12' * 8))
        self.assertEqual(r['p2']['name'], 'Second PIN Appl 1')

    def test_manage_channel_p2(self):
        r = decode_message(bytes.fromhex('0070000300'))
        self.assertEqual(r['p1']['name'], 'Open channel')
        self.assertEqual(r['p2']['name'], 'Channel 3')

    def test_retrieve_data_p2(self):
        r = decode_message(bytes.fromhex('80cb008004' + '4f' * 4))
        self.assertEqual(r['p2']['bits'], ['First block'])

    def test_get_data_tag(self):
        r = decode_message(bytes.fromhex('80ca005000'))
        self.assertEqual(r['p1p2'], {'label': 'Tag', 'value': 0x50})

    def test_commands_always_have_p1p2(self):
        # FETCH and GET RESPONSE have unused P1/P2 (always '00') — RFU.
        r = decode_message(bytes.fromhex('801200000fd00d8103010300820281820402011e9000'))
        self.assertEqual(r['p1p2'], {'unused': True, 'value': 0})
        r = decode_message(bytes.fromhex('00c0000000'), prev={'ins': 0xA4, 'ins_name': 'SELECT', 'sw1': '61'})
        self.assertEqual(r['p1p2'], {'unused': True, 'value': 0})

    def test_increase_p1p2_unused(self):
        r = decode_message(bytes.fromhex('80320000030100000000'))
        self.assertEqual(r['p1p2'], {'unused': True, 'value': 0})

    def test_deactivate_activate_file_p1(self):
        r = decode_message(bytes.fromhex('00040000126f0a'))
        self.assertEqual(r['p1']['name'], 'EF by file ID')
        self.assertEqual(r['p2']['name'], 'No indication')
        r = decode_message(bytes.fromhex('00040800123f002f00'))
        self.assertEqual(r['p1']['name'], 'Path from MF')
        r = decode_message(bytes.fromhex('00040900122f00'))
        self.assertEqual(r['p1']['name'], 'Path from current DF')


class TestSwWrongLength(unittest.TestCase):
    def test_6c(self):
        from simtrace2_pysniff.server.decode import decode_sw
        self.assertEqual(decode_sw(bytes.fromhex('6c38'))['name'],
                         'Wrong length (Le): correct length is 0x38 (56 bytes)')

    def test_62_unknown_is_unnamed(self):
        from simtrace2_pysniff.server.decode import decode_sw
        self.assertIsNone(decode_sw(bytes.fromhex('6205'))['name'])


class TestStatusFcp(unittest.TestCase):
    def test_status_body_is_fcp(self):
        raw = bytes.fromhex(
            '80f2000038'
            '62368202782183027ff08410a0000000871002ff45ff0189020111008a01058b032f0608c60c90016083010183018183010a81040000039f'
            '9000')
        r = decode_message(raw)
        self.assertEqual(r['ins_name'], 'STATUS')
        self.assertEqual(r['sw']['sw1'], '90')
        resp = r['response']
        self.assertEqual(resp['template'], 'FCP')
        self.assertEqual(resp['file_id'], '7FF0')
        self.assertEqual(resp['df_name'], 'A0000000871002FF45FF018902011100')
        self.assertEqual(resp['file_descriptor']['file_type'], 'DF or ADF')
        self.assertEqual(resp['life_cycle'], 'operational state (activated)')


class TestLengthMismatch(unittest.TestCase):
    def test_lc_truncated(self):
        # ENVELOPE with Lc=21, body missing (only SW captured).
        r = decode_message(bytes.fromhex('80c20000159000'))
        self.assertEqual(r['sw']['sw1'], '90')
        self.assertEqual(r['sw']['sw2'], '00')
        self.assertNotIn('body', r)
        self.assertEqual(r['length_mismatch'],
                         {'kind': 'truncated', 'expected': 21, 'actual': 0})

    def test_lc_excessive(self):
        # ENVELOPE with Lc=3 but 4 bytes of body + SW.
        r = decode_message(bytes.fromhex('80c2000003d10102039000'))
        self.assertEqual(r['length_mismatch'],
                         {'kind': 'excessive', 'expected': 3, 'actual': 4})

    def test_select_well_formed(self):
        r = decode_message(bytes.fromhex('a0a40000023f009000'))
        self.assertNotIn('length_mismatch', r)

    def test_le_short_response_not_flagged(self):
        # READ BINARY (Le) returning an error SW with no data is not "truncated".
        r = decode_message(bytes.fromhex('00b08f00066a82'))
        self.assertEqual(r['sw']['sw1'], '6a')
        self.assertNotIn('length_mismatch', r)


class TestRefresh(unittest.TestCase):
    def test_uicc_reset(self):
        r = decode_message(bytes.fromhex('801200000bd0098103010104820281829000'))
        self.assertEqual(r['cat_command'], 'REFRESH')
        self.assertEqual(r['cmd']['qualifier'], '0x04 UICC Reset')
        self.assertNotIn('file_list', r['cmd'])
        self.assertNotIn('aid', r['cmd'])

    def test_file_change_notification(self):
        r = decode_message(bytes.fromhex('8012000011d00f81030101018202818292046f076f209000'))
        self.assertEqual(r['cmd']['qualifier'], '0x01 File Change Notification')
        self.assertEqual(r['cmd']['file_list'], ['6F07', '6F20'])


class TestIdleModeText(unittest.TestCase):
    """SET UP IDLE MODE TEXT (TS 102 223 §6.6.13) proactive command."""

    def _fetch(self, inner_hex):
        # FETCH response body: D0 BER-TLV wrapping the proactive command
        inner = bytes.fromhex(inner_hex)
        body = b'\xd0' + bytes([len(inner)]) + inner
        return decode_message(
            bytes.fromhex('80120000%02x' % len(body)) + body + b'\x90\x00')

    def test_8bit_text_icon_qualifier(self):
        # "Hello" 8-bit + icon record 5 + qualifier bit 1 (self-explanatory)
        r = self._fetch(
            '810301280182028182'      # cmd details (qual 0x01) + device ids
            '8d060448656c6c6f'        # Text String: DCS 0x04 (8-bit), "Hello"
            '1e0105')                 # Icon Identifier: record 5
        self.assertEqual(r['cat_command'], 'SET UP IDLE MODE TEXT')
        self.assertEqual(r['cmd']['text'], 'Hello')
        self.assertEqual(r['cmd']['qualifier'], 'icon self-explanatory')
        self.assertEqual(r['cmd']['icon_id'], 5)

    def test_ucs2_text(self):
        # "Привет" UCS-2 (DCS 0x08)
        r = self._fetch(
            '810301280082028182'
            '8d0d08041f04400438043204350442')
        self.assertEqual(r['cat_command'], 'SET UP IDLE MODE TEXT')
        self.assertEqual(r['cmd']['text'], 'Привет')

    def test_qualifier_zero_hidden(self):
        r = self._fetch('8103012800820281828d060448656c6c6f')
        self.assertNotIn('qualifier', r['cmd'])

    def test_qualifier_rfu_bits_raw(self):
        r = self._fetch('8103012802820281828d060448656c6c6f')
        self.assertEqual(r['cmd']['qualifier'], '0x02')

    def test_empty_text_removes_idle_text(self):
        # Zero-length Text String instructs the ME to remove the idle text
        r = self._fetch('8103012800820281828d00')
        self.assertEqual(r['cmd']['text'], '')

    def test_no_icon_tlv(self):
        r = self._fetch('8103012800820281828d060448656c6c6f')
        self.assertNotIn('icon_id', r['cmd'])


class TestSatLegacyQuirks(unittest.TestCase):
    """Real-card SAT quirks and unknown-TLV transparency.

    Tag assignments verified against GSM 11.14 v5.1.0/v5.9.0 §12.3 and
    TS 102 223 V18.3.0: Text String = '0D'/'8D' in all generations;
    '10'/'90' = Item identifier.
    """

    def _fetch(self, inner_hex):
        inner = bytes.fromhex(inner_hex)
        body = b'\xd0' + bytes([len(inner)]) + inner
        return decode_message(
            bytes.fromhex('80120000%02x' % len(body)) + body + b'\x90\x00')

    def test_idle_mode_text_nonstandard_tag(self):
        # Real-card capture: SET UP IDLE MODE TEXT whose Text String ("037",
        # 8-bit data) is tagged '10' instead of '8D'.
        r = decode_message(bytes.fromhex(
            '8012000011d00f8103012800820281821004043033379000'))
        self.assertEqual(r['cat_command'], 'SET UP IDLE MODE TEXT')
        self.assertEqual(r['cmd']['text'], '037')
        self.assertIn('non-standard', r['cmd']['text_note'])
        self.assertNotIn('raw_tlv', r['cmd'])

    def test_item_identifier_single_byte(self):
        # Genuine 1-byte Item identifier (SELECT ITEM flow) must not be
        # mistaken for the quirk text fallback.
        r = self._fetch('810301240082028182900102')
        self.assertEqual(r['cat_command'], 'SELECT ITEM')
        self.assertEqual(r['cmd']['item_id'], 2)
        self.assertNotIn('text', r['cmd'])

    def test_unknown_tlv_preserved(self):
        r = self._fetch('8103012800820281827102aabb')
        self.assertEqual(r['cmd']['raw_tlv'],
                         [{'tag': '71', 'value': 'AABB'}])

    def test_device_ids_not_in_raw_tlv(self):
        # Structural Device Identities TLV must not surface as unknown.
        r = self._fetch('810301280082028182')
        self.assertNotIn('raw_tlv', r['cmd'])

    def test_compliant_text_still_wins_over_quirk(self):
        # If both a compliant 8D text and a '10'-tagged object exist,
        # the compliant one is used and the other lands in raw_tlv.
        r = self._fetch('8103012100820281828d0204411003010102')
        self.assertEqual(r['cmd']['text'], 'A')
        self.assertIn({'tag': '10', 'value': '010102'}, r['cmd']['raw_tlv'])


class TestSpecRegistry(unittest.TestCase):
    """Registries verified against TS 102 223 V18.3.0 / TS 31.111 V18.12.0."""

    def _fetch(self, inner_hex):
        inner = bytes.fromhex(inner_hex)
        body = b'\xd0' + bytes([len(inner)]) + inner
        return decode_message(
            bytes.fromhex('80120000%02x' % len(body)) + body + b'\x90\x00')

    def test_event_names_multi_rat_and_profile_container(self):
        # SET UP EVENT LIST with events '14', '19', '1E'
        from simtrace2_pysniff.server.decode import EVENT_TYPES
        self.assertEqual(EVENT_TYPES[0x14],
                         'Access Technology Change (multiple)')
        self.assertEqual(EVENT_TYPES[0x19], 'Profile Container')
        self.assertEqual(EVENT_TYPES[0x1E], 'CAG cell selection')
        self.assertEqual(EVENT_TYPES[0x1F], 'Slices Status Change')

    def test_event_list_fetch_decodes_new_events(self):
        # SET UP EVENT LIST with events '14', '19', '1E'
        r = self._fetch('810301050002028281190314191e')
        self.assertEqual(r['cat_command'], 'SET UP EVENT LIST')
        self.assertEqual(r['cmd']['events'],
                         ['Access Technology Change (multiple)',
                          'Profile Container', 'CAG cell selection'])

    def test_tr_result_me_unable_vs_network(self):
        from simtrace2_pysniff.server.decode import TR_RESULTS
        self.assertIn('ME currently unable', TR_RESULTS[0x20])
        self.assertIn('Network currently unable', TR_RESULTS[0x21])

    def test_tr_result_user_session_codes(self):
        from simtrace2_pysniff.server.decode import TR_RESULTS
        self.assertEqual(TR_RESULTS[0x14],
                         'USSD or SS transaction terminated by the user')
        self.assertNotIn(0x0A, TR_RESULTS)
        self.assertNotIn(0x0E, TR_RESULTS)

    def test_tr_result_permanent_problems(self):
        from simtrace2_pysniff.server.decode import TR_RESULTS
        self.assertEqual(TR_RESULTS[0x3A],
                         'Bearer Independent Protocol error')
        self.assertEqual(TR_RESULTS[0x3B],
                         'Access Technology unable to process command')
        self.assertEqual(TR_RESULTS[0x3C], 'Frames error')
        self.assertEqual(TR_RESULTS[0x3D], 'MMS error')

    def test_envelope_types_extended(self):
        from simtrace2_pysniff.server.decode import ENVELOPE_TYPES
        self.assertEqual(ENVELOPE_TYPES[0xD9], 'USSD DOWNLOAD')
        self.assertEqual(ENVELOPE_TYPES[0xDD],
                         'GEOGRAPHICAL LOCATION REPORTING')
        self.assertEqual(ENVELOPE_TYPES[0xDE], 'ENVELOPE CONTAINER')
        self.assertEqual(ENVELOPE_TYPES[0xE0], '5G PROSE REPORT')

    def test_lsi_command_type(self):
        from simtrace2_pysniff.server.decode import CAT_COMMAND_TYPES
        self.assertEqual(CAT_COMMAND_TYPES[0x79], 'LSI COMMAND')

    def test_proprietary_type_fallback(self):
        r = self._fetch('810301f20082028182')
        self.assertEqual(r['cat_command'], 'Proprietary (0xf2)')
        self.assertEqual(r['cmd']['type'], 'Proprietary (0xf2)')

    def test_pli_qualifiers_esn_and_supported_rat(self):
        from simtrace2_pysniff.server.decode import PLI_QUALIFIERS
        self.assertEqual(PLI_QUALIFIERS[0x07], 'ESN of the terminal')
        self.assertEqual(PLI_QUALIFIERS[0x1A],
                         'Supported Radio Access Technologies')


class TestEnvelopeDecoders(unittest.TestCase):
    """Phase 2: inner TLV decoding for the remaining ENVELOPE types."""

    def _envelope(self, hexstr):
        apdu = '80C20000%02x' % (len(hexstr) // 2) + hexstr + '9000'
        return decode_message(bytes.fromhex(apdu))

    def test_menu_selection_item_and_help(self):
        # D3 | device ids (UICC→Terminal) | item identifier 02 | help request
        r = self._envelope('D309820281821001029500')
        cmd = r['cmd']
        self.assertEqual(cmd['type'], 'MENU SELECTION')
        self.assertEqual(cmd['item_id'], 2)
        self.assertTrue(cmd['help'])
        self.assertEqual(cmd['device_ids'], {'src': 'UICC', 'dst': 'Terminal'})

    def test_timer_expiration(self):
        # D7 | device ids | timer id 01 | timer value semi-octet h/m/s
        r = self._envelope('D70C820282812401012503010203')
        cmd = r['cmd']
        self.assertEqual(cmd['type'], 'TIMER EXPIRATION')
        self.assertEqual(cmd['timer_id'], 1)
        self.assertEqual(cmd['timer_value'], '01:02:03')

    def test_ussd_download(self):
        # D9 | device ids | USSD string, DCS 0x04 (8-bit) "*100#"
        r = self._envelope('D90C820283810A06042A31303023')
        cmd = r['cmd']
        self.assertEqual(cmd['type'], 'USSD DOWNLOAD')
        self.assertEqual(cmd['ussd'], '*100#')
        self.assertEqual(cmd['device_ids'], {'src': 'Network', 'dst': 'UICC'})

    def test_call_control_address_and_ccp(self):
        # D4 | device ids | address (intl '+79') | CCP 0xAA
        r = self._envelope('D40C8202838106039179F10701AA')
        cmd = r['cmd']
        self.assertEqual(cmd['type'], 'CALL CONTROL')
        self.assertIn('+', cmd['address'])
        self.assertEqual(cmd['ccp'], 'AA')

    def test_envelope_container_recurses(self):
        # DE wrapping a complete MENU SELECTION envelope
        inner = bytes.fromhex('D309820281821001029500')
        body = b'\xDE' + bytes([len(inner)]) + inner
        lc = len(body)
        r = decode_message(
            bytes.fromhex('80C20000%02x' % lc) + body + b'\x90\x00')
        cmd = r['cmd']
        self.assertEqual(cmd['type'], 'ENVELOPE CONTAINER')
        self.assertEqual(cmd['encapsulated']['type'], 'MENU SELECTION')
        self.assertEqual(cmd['encapsulated']['item_id'], 2)

    def test_prose_report_keeps_raw_objects(self):
        # E0 | device ids | unknown data object → preserved in raw_tlv
        r = self._envelope('E008820282819902AABB')
        cmd = r['cmd']
        self.assertEqual(cmd['type'], '5G PROSE REPORT')
        self.assertEqual(cmd['raw_tlv'], [{'tag': '19', 'value': 'AABB'}])

    def test_proactive_device_ids_decoded(self):
        r = decode_message(bytes.fromhex(
            '801200000dd00b8103012800820283818d00'))
        self.assertEqual(r['cmd']['device_ids'],
                         {'src': 'Network', 'dst': 'UICC'})


class TestQualifiers(unittest.TestCase):
    """Phase 3: §8.6 qualifier decoding for the remaining commands."""

    def _fetch_qual(self, cmd_type, qual):
        inner_hex = '810301%02x%02x820281828d00' % (cmd_type, qual)
        inner = bytes.fromhex(inner_hex)
        body = b'\xd0' + bytes([len(inner)]) + inner
        r = decode_message(
            bytes.fromhex('80120000%02x' % len(body)) + body + b'\x90\x00')
        return r['cmd'].get('qualifier')

    def test_set_up_call_value_table(self):
        self.assertEqual(self._fetch_qual(0x10, 0x04),
                         '0x04 set up call, disconnecting all other calls (if any)')

    def test_display_text_bits(self):
        self.assertEqual(self._fetch_qual(0x21, 0x81),
                         'high priority, wait for user to clear message')
        self.assertIsNone(self._fetch_qual(0x21, 0x00))

    def test_get_inkey_bits(self):
        self.assertEqual(self._fetch_qual(0x22, 0x0B),
                         'alphabet set requested, UCS2 alphabet requested, '
                         'immediate digit response requested')

    def test_get_input_bits(self):
        self.assertEqual(self._fetch_qual(0x23, 0x04),
                         'input shall not be revealed')

    def test_select_item_presentation_and_help(self):
        self.assertEqual(self._fetch_qual(0x24, 0x05),
                         'data values presentation, '
                         'selection using soft key preferred')

    def test_timer_management_ops(self):
        self.assertEqual(self._fetch_qual(0x27, 0x02), 'deactivate timer')
        self.assertEqual(self._fetch_qual(0x27, 0x04),
                         'get current timer value')
        self.assertIsNone(self._fetch_qual(0x27, 0x00))  # start = default

    def test_send_sm_packing_bit(self):
        self.assertEqual(self._fetch_qual(0x13, 0x01),
                         'SMS packing by terminal required')

    def test_open_channel_bearer_dependent(self):
        self.assertIn('immediate link establishment',
                      self._fetch_qual(0x40, 0x01))
        self.assertIn('bearer-dependent', self._fetch_qual(0x40, 0x01))

    def test_launch_browser_value_table(self):
        self.assertEqual(self._fetch_qual(0x15, 0x03),
                         "0x03 close browser session and launch new")

    def test_lsi_command_values(self):
        self.assertEqual(self._fetch_qual(0x79, 0x01), '0x01 UICC Platform Reset')

    def test_rfu_byte_commands_stay_raw(self):
        self.assertEqual(self._fetch_qual(0x02, 0xFF), '0xFF')  # MORE TIME
        self.assertIsNone(self._fetch_qual(0x02, 0x00))


class TestSwUiccSpecific(unittest.TestCase):
    """TS 102 221 UICC-specific SWs (tables 10.7-10.15)."""

    def _sw(self, hexstr):
        from simtrace2_pysniff.server.decode import decode_sw
        return decode_sw(bytes.fromhex(hexstr))

    def test_91xx_proactive_pending(self):
        self.assertEqual(self._sw('9107')['name'],
                         'Proactive command pending (7 bytes)')
        self.assertEqual(self._sw('910b')['name'],
                         'Proactive command pending (11 bytes)')

    def test_62f_more_data(self):
        self.assertEqual(self._sw('62f1')['name'], 'More data available')
        self.assertEqual(self._sw('62f2')['name'],
                         'More data available and proactive command pending')
        self.assertEqual(self._sw('62f3')['name'], 'Response data available')

    def test_63f_not_pin_failure(self):
        # 63F1/F2 are "more data expected", NOT PIN retries
        self.assertEqual(self._sw('63f1')['name'], 'More data expected')
        self.assertEqual(self._sw('63f2')['name'],
                         'More data expected and proactive command pending')

    def test_63cx_still_pin_retries(self):
        self.assertIn('retries remaining', self._sw('63c3')['name'])
        self.assertIn('Verification failed', self._sw('63c3')['name'])

    def test_sat_busy_and_auth_errors(self):
        self.assertEqual(self._sw('9300')['name'], 'SIM Application Toolkit busy')
        self.assertEqual(self._sw('9850')['name'],
                         'INCREASE cannot be performed, max value reached')
        self.assertEqual(self._sw('9862')['name'],
                         'Authentication error, application specific')
        self.assertEqual(self._sw('9863')['name'],
                         'Security session or association expired')
        self.assertEqual(self._sw('9864')['name'],
                         'Minimum UICC suspension time too long')

    def test_6401_immediate_response(self):
        self.assertEqual(self._sw('6401')['name'],
                         'Execution error — immediate response required')

    def test_6500_nv_memory_changed(self):
        # TS 102 221 table 10.10: 6500 = no info given, NV memory CHANGED
        name = self._sw('6500')['name']
        self.assertIn('NV memory changed', name)
        self.assertNotEqual(name, 'Execution error — memory failure')

    def test_existing_patterns_intact(self):
        self.assertIn('GET RESPONSE', self._sw('6110')['name'])
        self.assertIn('correct length is 0x38', self._sw('6c38')['name'])
        self.assertIsNone(self._sw('6205')['name'])


class TestSpiBits(unittest.TestCase):
    """TS 102 225 §5.1.1: SPI1 b3 = ciphering, SPI2 b5 = PoR ciphering."""

    def _spi(self, spi_hex):
        from simtrace2_pysniff.server.decode import _decode_secured_packet
        # CPL(2) CHL(1)=0x0D SPI(2) KIc KID TAR(3) CNTR(5) PCNTR + 1 data byte
        body = bytes.fromhex('000d0d' + spi_hex + '1505000001000000000000aa')
        return _decode_secured_packet(body)['spi']

    def test_spi1_ciphering_b3(self):
        # 0x16 = 0001 0110: b3=1 → ciphering ON; old code checked b4 (0x08) → False
        self.assertTrue(self._spi('1605')['ciphering'])
        # 0x12 = 0001 0010: b3=0 → ciphering OFF
        self.assertFalse(self._spi('1205')['ciphering'])
        # 0x04 = 0000 0100: only b3 set → ciphering ON
        self.assertTrue(self._spi('0405')['ciphering'])

    def test_spi2_por_ciphered_b5(self):
        # 0x10 = 0001 0000: b5=1 → PoR ciphered; old code checked b6 (0x20) → False
        self.assertTrue(self._spi('0510')['por_ciphered'])
        # 0x20 = 0010 0000: b6=0... wait, b5=0 → NOT ciphered
        self.assertFalse(self._spi('0520')['por_ciphered'])

    def test_por_transport_field(self):
        # TS 31.115: SPI2 b6 (0x20) = PoR transport (0 = SMS-DELIVER-REPORT, 1 = SMS-SUBMIT)
        self.assertEqual(self._spi('0500')['por_transport'], 'SMS-DELIVER-REPORT')
        self.assertEqual(self._spi('0520')['por_transport'], 'SMS-SUBMIT')


class TestApduSpecCoverage(unittest.TestCase):
    """Newly added APDU_SPEC entries decode with names."""

    def _ins(self, cla, ins, p1p2='0000', body='', le=''):
        raw = bytes.fromhex(cla + ins + p1p2 + '%02x' % (len(body) // 2) + body + le)
        return decode_message(raw)['ins_name']

    def test_update_binary_odd_ins(self):
        r = self._ins('00', 'd7', '0010', 'aabb')
        self.assertEqual(r, 'UPDATE BINARY (odd INS)')

    def test_update_record_odd_ins(self):
        r = self._ins('00', 'dd', '0104', 'aabb')
        self.assertEqual(r, 'UPDATE RECORD (odd INS)')

    def test_write_record(self):
        r = self._ins('00', 'd2', '0104', 'aabb')
        self.assertEqual(r, 'WRITE RECORD')

    def test_external_authenticate(self):
        r = self._ins('00', '82', '0100', 'aabbccdd')
        self.assertEqual(r, 'EXTERNAL AUTHENTICATE')

    def test_general_authenticate(self):
        r = self._ins('00', '86', '0000', '7c0aa50401020304')
        self.assertEqual(r, 'GENERAL AUTHENTICATE')

    def test_manage_security_environment(self):
        r = self._ins('00', '22', '41a4', '')
        self.assertEqual(r, 'MANAGE SECURITY ENVIRONMENT')

    def test_erase_binary(self):
        r = self._ins('00', '0e', '0010', '0020')
        self.assertEqual(r, 'ERASE BINARY')

    def test_erase_records(self):
        r = self._ins('00', '0c', '0304', '')
        self.assertEqual(r, 'ERASE RECORDS')

    def test_manage_lsi(self):
        r = self._ins('80', '7c', '0000', '0201')
        self.assertEqual(r, 'MANAGE LSI')


class TestClaDecode(unittest.TestCase):
    """ISO 7816-4 §5.1.1 first/further interindustry CLA coding."""

    def _cla(self, value):
        from simtrace2_pysniff.server.decode import decode_cla
        return decode_cla(value)

    def test_basic_channel_iso(self):
        r = self._cla(0x00)
        self.assertEqual(r['channel'], 0)
        self.assertEqual(r['secure_messaging'], 'none')
        self.assertEqual(r['chain'], 'last or only')

    def test_sm_header_authenticated(self):
        # 0x1C = 0001 1100: SM bits b4-b3 = 11 → header authenticated
        r = self._cla(0x1c)
        self.assertEqual(r['secure_messaging'], 'SM header authenticated')

    def test_sm_proprietary(self):
        # 0x0C = 0000 1100: b4-b3 = 01 → proprietary secure messaging
        r = self._cla(0x0c)
        self.assertEqual(r['secure_messaging'], 'proprietary')

    def test_chain_bit_b5(self):
        # 0x20 = 0010 0000: b5=1 → first or continuing command of chain
        r = self._cla(0x20)
        self.assertEqual(r['chain'], 'first or continuing')

    def test_further_interindustry_channel_offset(self):
        # 0x40 = 0100 0000: further format, channel = b4-b1 + 4 = 4
        r = self._cla(0x40)
        self.assertEqual(r['interclass'], 'inter-industry (further format)')
        self.assertEqual(r['channel'], 4)

    def test_etsi_uicc(self):
        r = self._cla(0x80)
        self.assertEqual(r['interclass'], 'ETSI-defined (UICC/USIM)')

    def test_etsi_sim(self):
        r = self._cla(0xa0)
        self.assertEqual(r['interclass'], 'ETSI-defined (SIM/GSM)')


if __name__ == '__main__':
    unittest.main()
