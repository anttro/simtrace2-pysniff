"""APDU/TPDU decoding — CLA, INS, P1/P2, body, and status word.

Pure Python, no dependencies.  Decodes raw TPDU bytes captured by
the SIMtrace2 sniffer into structured dicts for the PWA to display.
"""

# ──────────────────── Status Word names ────────────────────

SW_NAMES = {
    (0x90, 0x00): 'Normal ending',
    (0x91, 0x00): 'Normal ending, proactive command pending',
    (0x92, 0x00): 'Normal ending after x bytes',
    (0x61, 0x00): 'Response data available',
    (0x62, 0x00): 'Warning — no information',
    (0x62, 0x81): 'Warning — part of data may be corrupted',
    (0x62, 0x82): 'Warning — EOF reached before reading Le bytes',
    (0x62, 0x83): 'Warning — selected file deactivated',
    (0x62, 0x84): 'Warning — FCI not formatted per ISO',
    (0x63, 0x00): 'Warning — no information',
    (0x63, 0xc1): 'Warning — 1 retry remaining',
    (0x63, 0xc2): 'Warning — 2 retries remaining',
    (0x63, 0xc3): 'Warning — 3 retries remaining',
    (0x64, 0x00): 'Execution error — no information',
    (0x65, 0x00): 'Execution error — memory failure',
    (0x65, 0x81): 'Execution error — memory failure',
    (0x66, 0x00): 'Security error — no information',
    (0x66, 0x81): 'Reserved for security-related issues',
    (0x67, 0x00): 'Checking error — wrong length',
    (0x68, 0x00): 'Checking error — no information',
    (0x68, 0x81): 'Logical channel not supported',
    (0x68, 0x82): 'Secure messaging not supported',
    (0x68, 0x83): 'Last command of chain expected',
    (0x68, 0x84): 'Command chaining not supported',
    (0x69, 0x00): 'Checking error — no information',
    (0x69, 0x81): 'Command incompatible with file structure',
    (0x69, 0x82): 'Security status not satisfied',
    (0x69, 0x83): 'Authentication method blocked',
    (0x69, 0x84): 'Referenced data invalidated',
    (0x69, 0x85): 'Conditions of use not satisfied',
    (0x69, 0x86): 'Command not allowed (no current EF)',
    (0x69, 0x87): 'Expected SM data objects missing',
    (0x69, 0x88): 'SM data objects incorrect',
    (0x6a, 0x00): 'Checking error — no information',
    (0x6a, 0x80): 'Incorrect data in command data',
    (0x6a, 0x81): 'Function not supported',
    (0x6a, 0x82): 'File not found',
    (0x6a, 0x83): 'Record not found',
    (0x6a, 0x84): 'Not enough memory space in file',
    (0x6a, 0x85): 'Nc inconsistent with TLV structure',
    (0x6a, 0x86): 'Incorrect P1-P2',
    (0x6a, 0x87): 'Nc inconsistent with P1-P2',
    (0x6a, 0x88): 'Referenced data not found',
    (0x6a, 0x89): 'File already exists',
    (0x6a, 0x8a): 'DF name already exists',
    (0x6b, 0x00): 'Wrong parameters P1-P2',
    (0x6d, 0x00): 'Instruction not supported or invalid',
    (0x6e, 0x00): 'Class not supported',
    (0x6f, 0x00): 'No precise diagnosis',
}


def _sw_name(sw1, sw2):
    key = (sw1, sw2)
    return SW_NAMES.get(key)

# pattern match: 63cx, 62xx, etc.
_SW_PATTERNS = {
    (0x63,): lambda s1, s2: ('PIN verification failed, %d retries remaining' % (s2 & 0x0f)
                              if s2 & 0xc0 == 0xc0 else None),
    (0x62, 0x00): lambda s1, s2: 'Response: %d more bytes available' % s2,
    (0x61,): lambda s1, s2: 'Response: %d bytes available (use GET RESPONSE)' % s2,
    (0x9e,): lambda s1, s2: 'Normal processing, %d bytes of response' % s2,
    (0x9f,): lambda s1, s2: 'Normal processing, %d bytes of response' % s2,
}


def decode_sw(raw_sw):
    if len(raw_sw) < 2:
        return None
    sw1, sw2 = raw_sw[-2], raw_sw[-1]
    name = _sw_name(sw1, sw2)
    if name is None:
        for keys, fn in _SW_PATTERNS.items():
            if len(keys) == 1:
                if sw1 == keys[0]:
                    name = fn(sw1, sw2)
                    if name:
                        break
            elif len(keys) == 2:
                if sw1 == keys[0]:
                    name = fn(sw1, sw2)
                    if name:
                        break
    return {
        'sw1': f'{sw1:02x}',
        'sw2': f'{sw2:02x}',
        'name': name,
    }


# ──────────────────── CLA byte ────────────────────

def decode_cla(cla):
    chain_bits = (cla >> 4) & 0x03
    chain_names = {0: 'last or only', 1: 'first in chain', 2: 'not last in chain', 3: 'not last'}
    interclass = 'inter-industry' if (cla & 0x80) == 0 else 'proprietary'
    note = None
    if cla in (0xa0, 0x80):
        note = 'standard UICC CLA'
    elif cla == 0x00:
        note = 'standard inter-industry CLA'
    result = {
        'hex': f'{cla:02x}',
        'interclass': interclass,
        'channel': cla & 0x03,
        'secure_messaging': 'none' if (cla & 0x0c) == 0 else 'SM present',
        'chain': chain_names.get(chain_bits, f'unknown ({chain_bits})'),
    }
    if note:
        result['note'] = note
    return result


# ──────────────────── Known FIDs ────────────────────

KNOWN_FIDS = {
    '3f00': 'MF',
    '2f00': 'EF_DIR',
    '2fe2': 'EF_ICCID',
    '2f05': 'EF_PL',
    '2f06': 'EF_ARR',
    '7f10': 'DF_TELECOM',
    '7f20': 'DF_GSM',
    '5f3a': 'DF_GSM_ACCESS',
    '2f07': 'EF_IMSI',
    '6f05': 'EF_LI',
    '6f07': 'EF_IMSI',
    '6f20': 'EF_Kc',
    '6f30': 'EF_PLMNsel',
    '6f31': 'EF_HPPLMN',
    '6f37': 'EF_ACMmax',
    '6f38': 'EF_SST',
    '6f39': 'EF_ACM',
    '6f3e': 'EF_GID1',
    '6f3f': 'EF_GID2',
    '6f46': 'EF_SPN',
    '6f74': 'EF_ARR',
    '6f78': 'EF_ACC',
    '6f7b': 'EF_FPLMN',
    '6fad': 'EF_ADN',
    '6fae': 'EF_Phase',
}


# ──────────────────── Per-INS specifications ────────────────────

APDU_SPEC = {
    0xA4: {
        'name': 'SELECT',
        'p1': {
            0x00: 'DF/EF/MF by file ID',
            0x01: 'Child DF',
            0x02: 'EF under current DF',
            0x03: 'Parent DF',
            0x04: 'Application DF by name',
            0x08: 'Path from MF',
            0x09: 'Application by AID',
        },
        'p2': {
            0x00: 'No indication',
            0x04: 'Return FCI template',
            0x08: 'Return FCP template',
            0x0c: 'No data returned',
        },
        'body': {'label': 'FID/AID', 'fids': KNOWN_FIDS},
    },
    0xB0: {
        'name': 'READ BINARY',
        'p1p2': {'fmt': 'uint16be', 'label': 'Offset'},
        'body': None,
    },
    0xB2: {
        'name': 'READ RECORD',
        'p1': {'fmt': 'uint8', 'label': 'Record number'},
        'p2': {
            'label': 'Mode',
            'bits': {
                0x07: 'currently selected EF',
                0x04: 'use record number from P1',
                0x02: 'previous record',
                0x03: 'next record',
                0x05: 'first record',
                0x06: 'last record',
            },
        },
        'body': None,
    },
    0xB1: {
        'name': 'READ RECORD (B1)',
        'p1': {'fmt': 'uint8', 'label': 'Record number'},
        'p2': {
            'label': 'Mode',
            'bits': {
                0x07: 'currently selected EF',
                0x04: 'use record number from P1',
                0x02: 'previous record',
                0x03: 'next record',
                0x05: 'first record',
                0x06: 'last record',
            },
        },
        'body': None,
    },
    0xD6: {
        'name': 'UPDATE BINARY',
        'p1p2': {'fmt': 'uint16be', 'label': 'Offset'},
        'body': {'label': 'Data'},
    },
    0xDC: {
        'name': 'UPDATE RECORD',
        'p1': {'fmt': 'uint8', 'label': 'Record number'},
        'p2': {
            'label': 'Mode',
            'bits': {
                0x07: 'currently selected EF',
                0x04: 'use record number from P1',
                0x02: 'previous record',
                0x03: 'next record',
                0x05: 'first record',
                0x06: 'last record',
            },
        },
        'body': {'label': 'Data'},
    },
    0x20: {
        'name': 'VERIFY PIN',
        'p1': {0x00: 'Verify PIN1', 0x01: 'Verify PIN2', 0x02: 'Verify ADM2',
               0x03: 'Verify ADM3', 0x04: 'Verify ADM4', 0x80: 'Verify PUK',
               0x81: 'Verify ADM5'},
        'p2': {0x00: 'No indication', 0x04: 'Reset PIN'},
        'body': {'label': 'PIN value'},
    },
    0x21: {
        'name': 'VERIFY',
        'body': {'label': 'Data'},
    },
    0x24: {
        'name': 'CHANGE PIN',
        'p1': {0x00: 'Change PIN1', 0x01: 'Change PIN2', 0x02: 'Change ADM2',
               0x03: 'Change ADM3', 0x04: 'Change ADM4', 0x80: 'Change PUK',
               0x81: 'Change ADM5'},
        'body': {'label': 'Old+new PIN'},
    },
    0x26: {
        'name': 'DISABLE PIN',
        'body': {'label': 'PIN value'},
    },
    0x28: {
        'name': 'ENABLE PIN',
        'body': {'label': 'PIN value'},
    },
    0x2C: {
        'name': 'UNBLOCK PIN',
        'p1': {0x00: 'Unblock PIN1', 0x01: 'Unblock PIN2', 0x02: 'Unblock ADM2',
               0x03: 'Unblock ADM3', 0x04: 'Unblock ADM4', 0x80: 'Unblock PUK',
               0x81: 'Unblock ADM5'},
        'body': {'label': 'PUK + new PIN'},
    },
    0x88: {
        'name': 'AUTHENTICATE',
        'p1': {0x00: 'Run GSM algorithm', 0x80: 'Run 3G algo (resynchronisation)'},
        'body': {'label': 'Challenge/session key'},
    },
    0x89: {
        'name': 'AUTHENTICATE',
        'body': {'label': 'Response/resynchronisation data'},
    },
    0x84: {
        'name': 'GET CHALLENGE',
        'body': None,
    },
    0x70: {
        'name': 'MANAGE CHANNEL',
        'p1': {0x00: 'Open channel', 0x80: 'Close channel'},
        'body': None,
    },
    0xC0: {
        'name': 'GET RESPONSE',
        'body': None,
    },
    0xC2: {
        'name': 'ENVELOPE',
        'body': {'label': 'TLV data'},
    },
    0x12: {
        'name': 'FETCH',
        'body': None,
    },
    0x14: {
        'name': 'TERMINAL RESPONSE',
        'body': {'label': 'TLV data'},
    },
    0x32: {
        'name': 'INCREASE',
        'p1p2': {'fmt': 'uint16be', 'label': 'Value'},
        'body': {'label': 'Data'},
    },
    0x04: {
        'name': 'DEACTIVATE FILE',
        'p1p2': {'fmt': 'uint16be', 'label': 'File ID'},
        'body': None,
    },
    0x44: {
        'name': 'ACTIVATE FILE',
        'p1p2': {'fmt': 'uint16be', 'label': 'File ID'},
        'body': None,
    },
    0xF2: {
        'name': 'STATUS',
        'p1': {0x00: 'No indication', 0x01: 'Current DF', 0x02: 'EF under current DF',
               0x04: 'DF name', 0x0d: 'Applet status'},
        'body': None,
    },
    0xE0: {
        'name': 'CREATE FILE',
        'body': {'label': 'TLV data'},
    },
    0xE4: {
        'name': 'DELETE FILE',
        'p1': {0x00: 'Delete EF/DF', 0x0c: 'Delete EF', 0x0d: 'Delete DF'},
        'body': None,
    },
    0xAA: {
        'name': 'TERMINAL CAPABILITY',
        'body': {'label': 'TLV data'},
    },
    0x73: {
        'name': 'MANAGE SECURE CHANNEL',
        'body': {'label': 'TLV data'},
    },
    0x75: {
        'name': 'TRANSACT DATA',
        'body': {'label': 'TLV data'},
    },
    0x78: {
        'name': 'GET IDENTITY',
        'body': {'label': 'TLV data'},
    },
    0xA2: {
        'name': 'SEARCH RECORD',
        'p1': {'fmt': 'uint8', 'label': 'Record number'},
        'p2': {
            'label': 'Mode',
            'bits': {
                0x04: 'Simple search (forward)',
                0x02: 'Backward search',
                0x01: 'Enhanced search',
            },
        },
        'body': {'label': 'Search pattern'},
    },
    0xCB: {
        'name': 'RETRIEVE DATA',
        'body': {'label': 'TLV data'},
    },
    0xDB: {
        'name': 'SET DATA',
        'body': {'label': 'TLV data'},
    },
    0x10: {
        'name': 'TERMINAL PROFILE',
        'body': {'label': 'TLV data'},
    },
    0x76: {
        'name': 'SUSPEND UICC',
        'body': None,
    },
    0xCA: {
        'name': 'GET DATA',
        'body': {'label': 'TLV data'},
    },
    0xDA: {
        'name': 'PUT DATA',
        'body': {'label': 'TLV data'},
    },
    0xE2: {
        'name': 'STORE DATA',
        'body': {'label': 'TLV data'},
    },
}


# ──────────────────── CAT (TS 102 223) command types ────────────────────

CAT_COMMAND_TYPES = {
    0x01: 'REFRESH',
    0x02: 'MORE TIME',
    0x03: 'POLL INTERVAL',
    0x04: 'POLLING OFF',
    0x05: 'SET UP EVENT LIST',
    0x10: 'SET UP CALL',
    0x11: 'SEND SS',
    0x12: 'SEND USSD',
    0x13: 'SEND SHORT MESSAGE',
    0x14: 'SEND DTMF',
    0x15: 'LAUNCH BROWSER',
    0x16: 'GEOGRAPHICAL LOCATION REQUEST',
    0x20: 'PLAY TONE',
    0x21: 'DISPLAY TEXT',
    0x22: 'GET INKEY',
    0x23: 'GET INPUT',
    0x24: 'SELECT ITEM',
    0x25: 'SET UP MENU',
    0x26: 'PROVIDE LOCAL INFORMATION',
    0x27: 'TIMER MANAGEMENT',
    0x28: 'SET UP IDLE MODE TEXT',
    0x30: 'PERFORM CARD APDU',
    0x31: 'POWER ON CARD',
    0x32: 'POWER OFF CARD',
    0x33: 'GET READER STATUS',
    0x34: 'RUN AT COMMAND',
    0x35: 'LANGUAGE NOTIFICATION',
    0x40: 'OPEN CHANNEL',
    0x41: 'CLOSE CHANNEL',
    0x42: 'RECEIVE DATA',
    0x43: 'SEND DATA',
    0x44: 'GET CHANNEL STATUS',
    0x45: 'SERVICE SEARCH',
    0x46: 'GET SERVICE INFORMATION',
    0x47: 'DECLARE SERVICE',
    0x50: 'SET FRAMES',
    0x51: 'GET FRAMES STATUS',
    0x60: 'RETRIEVE MULTIMEDIA MESSAGE',
    0x61: 'SUBMIT MULTIMEDIA MESSAGE',
    0x62: 'DISPLAY MULTIMEDIA MESSAGE',
    0x70: 'ACTIVATE',
    0x71: 'CONTACTLESS STATE CHANGED',
    0x72: 'COMMAND CONTAINER',
    0x73: 'ENCAPSULATED SESSION CONTROL',
    0x81: 'END OF PROACTIVE SESSION',
}

ENVELOPE_TYPES = {
    0xD1: 'SMS-PP DOWNLOAD',
    0xD2: 'CELL BROADCAST DOWNLOAD',
    0xD3: 'MENU SELECTION',
    0xD4: 'CALL CONTROL',
    0xD5: 'MO SHORT MESSAGE CONTROL',
    0xD6: 'EVENT DOWNLOAD',
    0xD7: 'TIMER EXPIRATION',
}


def parse_tlv(data):
    """Parse a BER-TLV structure into a list of (tag, length, value) tuples.

    Handles single-byte tags and single-byte lengths (< 128), which cover
    the CAT proactive command and ENVELOPE structures we decode.
    """
    tlvs = []
    i = 0
    n = len(data)
    while i < n:
        if i + 2 > n:
            break
        tag = data[i]
        i += 1
        length = data[i]
        i += 1
        if length & 0x80:
            # long form length — not needed for top-level CAT decode
            break
        if i + length > n:
            break
        value = data[i:i + length]
        i += length
        tlvs.append((tag, length, value))
    return tlvs


def decode_cat(ins, body):
    """Decode a CAT (TS 102 223) payload, returning the command/event name.

    For FETCH (0x12) the body is a proactive UICC command (D0 TLV) whose
    Command Details (tag 81) second byte is the Type of Command.
    For ENVELOPE (0xC2) the first TLV tag is the envelope type.
    Returns a string name or None.
    """
    if not body:
        return None
    if ins == 0x12:  # FETCH → proactive command
        for tag, _length, value in parse_tlv(body):
            if tag != 0xD0:
                continue
            for t2, _l2, v2 in parse_tlv(value):
                if t2 == 0x81 and len(v2) >= 2:
                    return CAT_COMMAND_TYPES.get(v2[1])
    elif ins == 0xC2:  # ENVELOPE → envelope type
        return ENVELOPE_TYPES.get(body[0])
    return None


# ──────────────────── Decode entry point ────────────────────

def decode_message(raw_data):
    """Decode a raw TPDU byte string into a structured dict.

    Returns None for non-TPDU messages (ATR, PPS, CHANGE, FIDI)
    or un-parseable data.  Returns a dict with ins_name, cla, p1, p2,
    p3, body, and sw keys for valid TPDU messages.
    """
    if not raw_data or len(raw_data) < 5:
        return None

    cla = raw_data[0]
    ins = raw_data[1]
    p1 = raw_data[2]
    p2 = raw_data[3]
    p3 = raw_data[4]

    spec = APDU_SPEC.get(ins)
    ins_name = spec['name'] if spec else f'Unknown (0x{ins:02x})'

    result = {
        'ins_hex': f'{ins:02x}',
        'ins_name': ins_name,
        'cla': decode_cla(cla),
        'p3': p3,
    }

    # P1 / P2 decode
    if spec:
        if 'p1p2' in spec:
            offset = (p1 << 8) | p2
            result['p1p2'] = {'label': spec['p1p2']['label'], 'value': offset}
        else:
            if 'p1' in spec:
                result['p1'] = _decode_field(spec['p1'], p1)
            if 'p2' in spec:
                result['p2'] = _decode_field(spec['p2'], p2)

    # Body: at least P3 bytes from byte 5; extra bytes may be SW
    remaining = raw_data[5:]
    extra_total = len(remaining) - p3
    sw_bytes = None

    if extra_total >= 2:
        sw_candidate = remaining[-2:]
        if sw_candidate[0] in (0x60, 0x61, 0x62, 0x63, 0x64, 0x65,
                               0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
                               0x6c, 0x6d, 0x6e, 0x6f, 0x90, 0x91,
                               0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                               0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
                               0x9e, 0x9f):
            sw_bytes = sw_candidate

    cmd_body_len = len(remaining) - 2 if sw_bytes else len(remaining)

    if cmd_body_len > 0:
        body = remaining[:cmd_body_len]
        result['body'] = {'hex': body.hex(), 'size': cmd_body_len}

        if spec and spec.get('body') and spec['body'].get('label'):
            result['body']['label'] = spec['body']['label']
        if spec and spec.get('body') and spec['body'].get('fids'):
            fids = spec['body']['fids']
            h = body.hex()
            if h in fids:
                result['body']['note'] = fids[h]

        cat_command = decode_cat(ins, body)
        if cat_command:
            result['cat_command'] = cat_command

    # SW
    if sw_bytes:
        result['sw'] = decode_sw(sw_bytes)

    return result


# ──────────────────── Sniff-level message types ────────────────────

CHANGE_FLAGS = {
    1 << 0: 'Card inserted',
    1 << 1: 'Card ejected',
    1 << 2: 'Reset asserted',
    1 << 3: 'Reset de-asserted',
    1 << 4: 'Waiting time timeout',
}


def decode_change(raw_data):
    """Decode a SIMtrace2 sniff_change payload (4-byte flags)."""
    if len(raw_data) < 4:
        return None
    import struct
    flags = struct.unpack('<I', raw_data[:4])[0]
    bits = []
    for mask, name in sorted(CHANGE_FLAGS.items()):
        if flags & mask:
            bits.append(name)
    return {
        'type': 'change',
        'flags_hex': f'{flags:08x}',
        'flags': bits if bits else ['no changes'],
    }


def decode_fidi(raw_data):
    """Decode a SIMtrace2 sniff_fidi payload (1-byte Fi/Di)."""
    if len(raw_data) < 1:
        return None
    fidi = raw_data[0]
    fi = fidi >> 4
    di = fidi & 0x0f
    fi_table = {0: 372, 1: 372, 2: 558, 3: 744, 4: 1116, 5: 1488, 6: 1860, 7: 0,
                8: 0, 9: 512, 10: 768, 11: 1024, 12: 1536, 13: 2048, 14: 0, 15: 0}
    di_table = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64,
                8: 12, 9: 20, 10: 2, 11: 4, 12: 8, 13: 16, 14: 32, 15: 64}
    return {
        'type': 'fidi',
        'fidi': f'{fidi:02x}',
        'fi': fi,
        'di': di,
        'fi_val': fi_table.get(fi, fi),
        'di_val': di_table.get(di, di),
    }


def decode_sniff_msg(raw_data, msg_type):
    """Decode a raw sniff message of the given type.

    Returns a structured dict with at least a 'type' key, or None if
    the message type has no structured decode.
    """
    if msg_type == 'tpdu' and raw_data:
        return decode_message(raw_data)
    if msg_type == 'change' and raw_data:
        return decode_change(raw_data)
    if msg_type == 'fidi' and raw_data:
        return decode_fidi(raw_data)
    if msg_type == 'atr':
        return {'type': 'atr', 'hex': raw_data.hex() if raw_data else ''}
    if msg_type == 'pps':
        return {'type': 'pps', 'hex': raw_data.hex() if raw_data else ''}
    return None


def _decode_field(spec, value):
    """Decode a single P1 or P2 field from its byte value."""
    result = {'raw': f'{value:02x}'}

    if isinstance(spec, dict):
        if value in spec and isinstance(spec[value], str):
            result['name'] = spec[value]
        elif 'label' in spec and 'bits' in spec:
            result['label'] = spec['label']
            matches = []
            for mask_val, desc in sorted(spec['bits'].items()):
                if (value & 0x07) == mask_val:
                    matches.append(desc)
                elif (value & mask_val) == mask_val and mask_val > 0x07:
                    matches.append(desc)
            result['bits'] = matches if matches else None
        elif 'fmt' in spec:
            result['label'] = spec.get('label', '')
            result['value'] = value

    return result
