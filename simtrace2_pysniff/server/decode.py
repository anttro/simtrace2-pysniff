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


# TS 102 223 — PROVIDE LOCAL INFORMATION command qualifier values
PLI_QUALIFIERS = {
    0x00: 'Location Info (MCC, MNC, LAC/TAC, Cell ID)',
    0x01: 'IMEI',
    0x02: 'Network Measurement results',
    0x03: 'Date, time and time zone',
    0x04: 'Language setting',
    0x05: 'Timing Advance',
    0x06: 'Access Technology (single)',
    0x08: 'IMEISV',
    0x09: 'Search Mode',
    0x0A: 'Battery charge state',
    0x0C: 'Current WSID',
    0x0D: 'Broadcast Network info',
    0x0E: 'Multiple Access Technologies',
    0x0F: 'Location Info (multi-RAT)',
    0x10: 'NMR (multi-RAT)',
    0x11: 'CSG ID list + HNB name',
    0x12: 'H(e)NB IP address',
    0x13: 'H(e)NB surrounding macrocells',
    0x14: 'Current WLAN identifier',
    0x15: 'Slices information',
    0x16: 'CAG information list',
    0x17: 'Rejected slices information',
}


def _command_details_name(value):
    """Decode a Command Details TLV value (number, type, qualifier).

    Returns the command type name, with the PLI qualifier description
    appended for PROVIDE LOCAL INFORMATION (type 0x26).
    """
    if len(value) < 2:
        return None
    name = CAT_COMMAND_TYPES.get(value[1])
    if not name:
        return None
    if value[1] == 0x26 and len(value) >= 3:  # PROVIDE LOCAL INFORMATION
        q = PLI_QUALIFIERS.get(value[2])
        if q:
            name = f'{name} — {q}'
    return name


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
                if t2 == 0x81:
                    return _command_details_name(v2)
    elif ins == 0xC2:  # ENVELOPE → envelope type
        return ENVELOPE_TYPES.get(body[0])
    return None


def decode_tr_command(body):
    """Extract the proactive command type echoed in a TERMINAL RESPONSE body.

    Returns the CAT command name (context the TR is responding to), or None.
    """
    if not body:
        return None
    for tag, _length, value in parse_tlv(body):
        if tag == 0x81:
            return _command_details_name(value)
    return None


# ──────────────────── Response decoders ────────────────────

# TS 102 223 Result (TERMINAL RESPONSE) — general result codes
TR_RESULTS = {
    0x00: 'Command performed successfully',
    0x01: 'Command performed with partial comprehension',
    0x02: 'Command performed, with missing information',
    0x03: 'REFRESH performed with additional EFs read',
    0x04: 'Command performed successfully, but requested icon could not be displayed',
    0x05: 'Command performed, but modified by call control by NAA',
    0x06: 'Command performed successfully, limited service',
    0x07: 'Command performed with modification',
    0x08: 'REFRESH performed but indicated NAA was not active',
    0x09: 'Command performed successfully, tone not played',
    0x0A: 'Proactive UICC session terminated by the user',
    0x0B: 'Backward move in the proactive UICC session requested by the user',
    0x0C: 'No response from user',
    0x0D: 'Help information required by the user',
    0x0E: 'USSD/SS transaction terminated by the user',
    0x10: 'Terminal currently unable to process command (screen busy)',
    0x11: 'Terminal currently unable to process command (busy on call)',
    0x12: 'Terminal currently unable to process command (USSD/SS ongoing)',
    0x13: 'Terminal currently unable to process command (no service)',
    0x14: 'Terminal currently unable to process command (access control class bar)',
    0x15: 'Terminal currently unable to process command (radio resource unavailable)',
    0x20: 'Network currently unable to process command',
    0x30: 'Beyond terminal capability',
    0x31: 'Command type not understood by terminal',
    0x32: 'Command data not understood by terminal',
    0x33: 'Command number not known by terminal',
    0x34: 'SS Return Error',
    0x35: 'SMS RP-ERROR',
    0x36: 'Error, required values are missing',
    0x37: 'USSD Return Error',
    0x38: 'MultipleCard commands error',
    0x39: 'Interaction with CC by NAA, wrong procedure',
    0x3C: 'Access Technology unable to process command',
    0x3D: 'Frames error',
    0x3E: 'MMS Error',
}


def _swap_nibbles(h):
    """Swap the nibbles of each hex byte in a hex string."""
    return ''.join(b[1] + b[0] for b in (h[i:i + 2] for i in range(0, len(h), 2)))


def _decode_plmn(b):
    """Decode a 3-byte PLMN (TS 24.008) into {'mcc', 'mnc'}."""
    if len(b) < 3:
        return None
    h = b.hex()
    mcc = (h[1] + h[0] + h[3]).upper().strip('F') or '0'
    mnc = (h[5] + h[4] + h[2]).upper().strip('F') or '0'
    return {'mcc': mcc, 'mnc': mnc}


def _decode_imei(val):
    """Decode an 8-byte BCD IMEI (TS 24.008 Mobile Identity) into a string."""
    swapped = _swap_nibbles(val.hex())
    if not swapped:
        return None
    # First nibble is the odd/even indicator (0x8|…) with digit 1 following;
    # drop it and any trailing 'F' padding.
    digits = swapped[1:].rstrip('fF')
    return digits or None


# TS 102 223 §6.8.7 Local information — COMPREHENSION-TLV tags (base form)
PLI_LOCATION_INFO = 0x13
PLI_IMEI = 0x14
PLI_NMR = 0x16
PLI_DATETIME = 0x26
PLI_LANGUAGE = 0x2D
PLI_ACCESS_TECH = 0x3F
PLI_TIMING_ADVANCE = 0x46
PLI_BATTERY = 0x63
PLI_SEARCH_MODE = 0x65

_ACCESS_TECH_NAMES = {
    0x00: 'GSM', 0x01: 'ANSI-136 (TIA/EIA-553)', 0x02: 'IS-136 (TIA/EIA-136)',
    0x03: 'UTRAN', 0x04: 'TETRA', 0x05: 'cdma2000 1xRTT',
    0x06: 'cdma2000 HRPD', 0x07: 'E-UTRAN', 0x08: 'eHRPD', 0x0A: 'NR',
}

_BATTERY_NAMES = {
    0x00: 'very low', 0x01: 'low', 0x02: 'average', 0x03: 'good', 0x05: 'full',
}

_ME_STATUS_NAMES = {0x00: 'idle', 0x01: 'not idle'}

_SEARCH_MODE_NAMES = {0x00: 'manual', 0x01: 'automatic'}


def _decode_datetime(val):
    """Decode TS 23.040 Service-Centre-Time-Stamp (7 bytes) into a string."""
    if len(val) < 7:
        return None
    b = val[:7]
    bcd = lambda x: (x >> 4) * 10 + (x & 0x0F)
    yy, mm, dd, hh, mi, ss = (bcd(x) for x in b[:6])
    tz_raw = b[6]
    if (tz_raw & 0x0F) == 0x0F:
        tz_str = 'unknown'
    else:
        tz_neg = bool(tz_raw & 0x08)
        tz_q = (tz_raw & 0x07) * 10 + (tz_raw >> 4)
        tz_str = f"{'-' if tz_neg else '+'}{tz_q // 4:02d}:{(tz_q % 4) * 15:02d}"
    return f'20{yy:02d}-{mm:02d}-{dd:02d} {hh:02d}:{mi:02d}:{ss:02d} (UTC{tz_str})'


def _decode_local_info(tag, value):
    """Decode a PLI local-information TLV value into a display dict."""
    if tag == PLI_LOCATION_INFO:
        if len(value) >= 7:
            plmn = _decode_plmn(value[:3]) or {}
            lac = value[3:5].hex().upper()
            cell = value[5:].hex().upper()
            loc = f"MCC {plmn.get('mcc', '?')} MNC {plmn.get('mnc', '?')} · LAC 0x{lac} · Cell 0x{cell}"
            return {'label': 'Location', 'value': loc}
    elif tag == PLI_IMEI:
        imei = _decode_imei(value)
        if imei:
            return {'label': 'IMEI', 'value': imei}
    elif tag == PLI_DATETIME:
        dt = _decode_datetime(value)
        if dt:
            return {'label': 'Date/time', 'value': dt}
    elif tag == PLI_LANGUAGE:
        lang = value.decode('ascii', 'replace').strip() or value.hex().upper()
        return {'label': 'Language', 'value': lang}
    elif tag == PLI_ACCESS_TECH:
        names = [_ACCESS_TECH_NAMES.get(b, f'0x{b:02X}') for b in value]
        return {'label': 'Access technology', 'value': ', '.join(names)}
    elif tag == PLI_TIMING_ADVANCE:
        if len(value) >= 2:
            status = _ME_STATUS_NAMES.get(value[0], f'0x{value[0]:02X}')
            return {'label': 'Timing advance', 'value': f'{status}, TA {value[1]}'}
    elif tag == PLI_BATTERY:
        if value:
            return {'label': 'Battery', 'value': _BATTERY_NAMES.get(value[0], f'0x{value[0]:02X}')}
    elif tag == PLI_SEARCH_MODE:
        if value:
            return {'label': 'Search mode', 'value': _SEARCH_MODE_NAMES.get(value[0], f'0x{value[0]:02X}')}
    elif tag == PLI_NMR:
        return {'label': 'Network measurement results', 'value': value.hex().upper()}
    return None


def _decode_tr_response(body):
    """Decode the TLVs of a TERMINAL RESPONSE body.

    Returns a dict with the Result (code/name), and any additional
    information: Duration (0x04), Item Identifier (0x05) and the
    PROVIDE LOCAL INFORMATION data objects.
    """
    result = {}
    local = {}
    for tag, _length, value in parse_tlv(body):
        if tag in (0x03, 0x83) and value:
            code = value[0]
            result['code'] = f'0x{code:02X}'
            result['name'] = TR_RESULTS.get(code)
            result['raw'] = value.hex().upper()
        elif tag == 0x04 and len(value) >= 2:  # Duration (POLL INTERVAL)
            result['duration'] = (value[0] << 8) | value[1]
        elif tag == 0x05 and value:  # Item Identifier (SELECT ITEM)
            result['item_identifier'] = value[0]
        else:
            info = _decode_local_info(tag, value)
            if info:
                local[info['label']] = info['value']
    if local:
        result['local_info'] = local
    return result or None


def _decode_tr_result(body):
    """Back-compat wrapper returning the Result TLV of a TERMINAL RESPONSE."""
    return _decode_tr_response(body)


# TS 102 221 Table 11.5 — file descriptor byte
_FILE_TYPES = {
    0b000: 'Working EF',
    0b001: 'Internal EF',
    0b111: 'DF or ADF',
}
_EF_STRUCTURES = {
    0b000: 'no information',
    0b001: 'transparent',
    0b010: 'linear fixed',
    0b110: 'cyclic',
}
_LIFE_CYCLE = {
    0x00: 'no information given',
    0x01: 'creation state',
    0x03: 'initialization state',
    0x05: 'operational state (activated)',
    0x07: 'operational state (deactivated)',
    0x0C: 'termination state',
    0x0D: 'termination state (permanently)',
}


def _decode_file_descriptor(value):
    """Decode a file descriptor byte string (TS 102 221 Table 11.5)."""
    if not value:
        return {}
    b = value[0]
    ft = (b >> 3) & 0x07
    result = {
        'shareable': 'shareable' if (b & 0x40) else 'not shareable',
        'file_type': _FILE_TYPES.get(ft, 'RFU'),
    }
    if ft in (0b000, 0b001):  # EF
        result['structure'] = _EF_STRUCTURES.get(b & 0x07, 'RFU')
        if len(value) >= 2:
            result['data_coding'] = f'0x{value[1]:02X}'
        if len(value) >= 4:
            result['record_length'] = int.from_bytes(value[2:4], 'big')
        if len(value) >= 5:
            result['num_records'] = value[4]
    elif len(value) >= 2:
        result['num_dfs_efs'] = value[1]
    return result


def _decode_fcp(data):
    """Decode an FCP/FCI/FMD template (TS 102 221 §11.1.1.3)."""
    result = {}
    for tag, _length, value in parse_tlv(data):
        if tag in (0x62, 0x64):  # outer template — recurse
            inner = _decode_fcp(value)
            inner['template'] = 'FCP' if tag == 0x62 else 'FMD'
            result.update(inner)
        elif tag == 0x82:
            result['file_descriptor'] = _decode_file_descriptor(value)
        elif tag == 0x83:
            fid = value.hex().upper()
            result['file_id'] = fid
            if fid.lower() in KNOWN_FIDS:
                result['file_id_name'] = KNOWN_FIDS[fid.lower()]
        elif tag == 0x84:
            result['df_name'] = value.hex().upper()
        elif tag == 0x88:
            result['sfi'] = f'0x{value[0]:02X}' if value else None
        elif tag == 0x8A:
            result['life_cycle'] = _LIFE_CYCLE.get(value[0] if value else 0, f'0x{(value[0] if value else 0):02X}')
        elif tag == 0xAB:
            result['short_ef_id'] = value.hex().upper()
    return result


def _decode_auth_3g(data):
    """Decode a 3G AUTHENTICATE response (tag DB success / DC sync-fail)."""
    tag = data[0]
    if tag == 0xDC:  # synchronisation failure → length byte + AUTS
        if len(data) >= 2:
            auts_len = data[1]
            return {'type': '3G', 'status': 'sync fail',
                    'auts': data[2:2 + auts_len].hex().upper()}
        return {'type': '3G', 'status': 'sync fail', 'auts': data[1:].hex().upper()}
    # tag 0xDB: success → length-prefixed RES, CK, IK, (KC)
    result = {'type': '3G', 'status': 'success'}
    i = 1
    for name in ('res', 'ck', 'ik', 'kc'):
        if i >= len(data):
            break
        ln = data[i]
        i += 1
        result[name] = data[i:i + ln].hex().upper()
        i += ln
    return result


def _decode_auth(data):
    """Decode an AUTHENTICATE response (GSM SRES+Kc, or 3G tag DB/DC)."""
    if not data:
        return {}
    if data[0] in (0xDB, 0xDC):
        return _decode_auth_3g(data)
    # GSM: SRES (4 bytes) + Kc (8 bytes)
    if len(data) >= 12:
        return {
            'type': 'GSM',
            'sres': data[:4].hex().upper(),
            'kc': data[4:12].hex().upper(),
        }
    return {'type': 'GSM', 'raw': data.hex().upper()}


def _decode_response_for(ins, data):
    """Decode response data using the command identified by INS."""
    if ins == 0xA4:  # SELECT → FCP/FCI template
        return _decode_fcp(data)
    if ins in (0x88, 0x89):  # AUTHENTICATE → SRES/Kc or RES/CK/IK
        return _decode_auth(data)
    return None


# ──────────────────── Command-body decoders ────────────────────

AUTH_CONTEXTS = {
    0: 'GSM',
    1: '3G (UMTS)',
    2: 'VGC/VBS',
    4: 'GBA',
}


def _decode_auth_cmd(data, p2):
    """Decode an AUTHENTICATE command body (RAND / RAND+AUTN)."""
    ctx = p2 & 0x07
    result = {'context': AUTH_CONTEXTS.get(ctx, f'unknown ({ctx})')}
    if ctx in (0, 1) and data:
        i = 0
        if i < len(data):
            rlen = data[i]
            i += 1
            result['rand'] = data[i:i + rlen].hex().upper()
            i += rlen
        if ctx == 1 and i < len(data):  # 3G → AUTN
            alen = data[i]
            i += 1
            result['autn'] = data[i:i + alen].hex().upper()
    return result


# TS 102 223 §8.25 — Event list values
EVENT_TYPES = {
    0x00: 'MT call', 0x01: 'Call connected', 0x02: 'Call disconnected',
    0x03: 'Location status', 0x04: 'User activity', 0x05: 'Idle screen available',
    0x06: 'Card reader status', 0x07: 'Language selection',
    0x08: 'Browser termination', 0x09: 'Data available',
    0x0A: 'Channel status', 0x0B: 'Access Technology Change',
    0x0C: 'Display parameters changed', 0x0D: 'Local connection',
    0x0E: 'Network Search Mode Change', 0x0F: 'Browsing status',
    0x10: 'Frames Information Change', 0x11: 'I-WLAN Access Status',
    0x12: 'Network Rejection', 0x13: 'HCI Connectivity',
    0x14: 'Change of UICC Access', 0x15: 'CSG Cell Change',
    0x16: 'Contactless state request', 0x17: 'Profile Container',
    0x18: 'LTE D2D Discovery Monitoring', 0x19: 'LTE D2D Communication Monitoring',
    0x1A: 'LTE D2D Announcement Response', 0x1B: 'LTE D2D Revocation',
    0x1C: 'LTE D2D Application Port', 0x1D: 'LTE D2D Security Recovery',
    0x1E: 'Off-net Emergency Call', 0x1F: 'ECall Over IMS',
    0x20: 'EARFCN Update', 0x21: 'SCEF Channel Status',
}

LOCATION_STATUS = {
    0x00: 'Normal service',
    0x01: 'Limited service',
    0x02: 'No service',
}


def _decode_bcd_address(data):
    """Decode a [TON/NPI + BCD digits] address into a string."""
    if not data:
        return ''
    ton = (data[0] >> 4) & 0x07  # bits 6-4 (bit 7 is the extension bit)
    digits = []
    for b in data[1:]:
        lo, hi = b & 0x0F, (b >> 4) & 0x0F
        if lo <= 9:
            digits.append(str(lo))
        elif lo == 0x0F:
            break
        if hi <= 9:
            digits.append(str(hi))
        elif hi == 0x0F:
            break
    num = ''.join(digits)
    if ton == 1:  # international
        num = '+' + num
    return num


# TS 23.038 — GSM 7-bit default alphabet
GSM7_ALPHABET = (
    '@\u00a3$\u00a5\u00e8\u00e9\u00f9\u00ec\u00f2\u00c7\n\u00d8\u00f8\r\u00c5\u00e5'
    '\u0394_\u03a6\u0393\u039b\u03a9\u03a0\u03a8\u03a3\u0398\u039e\u001b\u00c6\u00e6\u00df\u00c9'
    ' !"#\u00a4%&\'()*+,-./'
    '0123456789:;<=>?'
    '\u00a1ABCDEFGHIJKLMNO'
    'PQRSTUVWXYZ\u00c4\u00d6\u00d1\u00dc\u00a7'
    '\u00bfabcdefghijklmno'
    'pqrstuvwxyz\u00e4\u00f6\u00f1\u00fc\u00e0'
)

GSM7_EXTENSION = {
    0x0A: '\n', 0x14: '^', 0x28: '{', 0x29: '}', 0x2F: '\\',
    0x3C: '[', 0x3D: '~', 0x3E: ']', 0x40: '|', 0x65: '\u20ac',
}


def _decode_gsm7(data, num_chars):
    """Unpack GSM 7-bit packed septets and decode to text."""
    septets = []
    bitbuf = 0
    bitcount = 0
    for byte in data:
        bitbuf |= byte << bitcount
        bitcount += 8
        while bitcount >= 7:
            septets.append(bitbuf & 0x7F)
            bitbuf >>= 7
            bitcount -= 7
    if num_chars is not None:
        septets = septets[:num_chars]
    text = []
    i = 0
    while i < len(septets):
        s = septets[i]
        if s == 0x1B and i + 1 < len(septets):
            text.append(GSM7_EXTENSION.get(septets[i + 1], ' '))
            i += 2
        else:
            text.append(GSM7_ALPHABET[s] if s < len(GSM7_ALPHABET) else '?')
            i += 1
    return ''.join(text)


def _decode_dcs(dcs):
    """Decode TP-DCS into (encoding, message_class).

    Alphabet is selected by DCS bits 3-2: 0=GSM 7-bit, 1=8-bit data, 2=UCS2.
    """
    group = dcs & 0xC0
    if group in (0x00, 0xC0):
        alpha = (dcs >> 2) & 0x03
        encoding = {0: 'GSM 7-bit', 1: '8-bit data', 2: 'UCS2'}.get(alpha, 'reserved')
    else:
        encoding = '8-bit data'
    return encoding, (dcs & 0x03)


def _decode_gsm7_octets(data):
    """Decode 8-bit-per-octet GSM 7-bit default alphabet text (TS 102 221)."""
    out = []
    i = 0
    while i < len(data):
        b = data[i]
        if b == 0x1B and i + 1 < len(data):
            out.append(GSM7_EXTENSION.get(data[i + 1], ' '))
            i += 2
        else:
            out.append(GSM7_ALPHABET[b] if b < len(GSM7_ALPHABET) else '?')
            i += 1
    return ''.join(out)


def _decode_annex_a(raw):
    """Decode a TS 102 221 Annex A text string (GsmOrUcs2).

    Magic prefix 0x80/0x81/0x82 → UCS-2 variants; otherwise GSM 7-bit
    default alphabet coded one octet per character.
    """
    if not raw:
        return ''
    if raw == b'\xff' * len(raw):
        return ''
    if raw[0] == 0x80:
        return raw[1:].decode('utf_16_be', 'replace')
    if raw[0] == 0x81 and len(raw) >= 3:
        num_chars = raw[1]
        base_ptr = raw[2] << 7
        out = []
        for ch in raw[3:3 + num_chars]:
            if ch & 0x80:
                out.append(chr((ch & 0x7F) + base_ptr))
            else:
                out.append(GSM7_ALPHABET[ch] if ch < len(GSM7_ALPHABET) else '?')
        return ''.join(out)
    if raw[0] == 0x82 and len(raw) >= 4:
        num_chars = raw[1]
        base_ptr = (raw[2] << 8) | raw[3]
        out = []
        for ch in raw[4:4 + num_chars]:
            if ch & 0x80:
                out.append(chr((ch & 0x7F) + base_ptr))
            else:
                out.append(GSM7_ALPHABET[ch] if ch < len(GSM7_ALPHABET) else '?')
        return ''.join(out)
    return _decode_gsm7_octets(raw)


def _decode_dcs_text(raw):
    """Decode a Text String (TS 102 223 §8.15): DCS byte + text."""
    if not raw or len(raw) < 2:
        return raw.hex() if raw else ''
    dcs = raw[0]
    data = raw[1:]
    if (dcs & 0x0C) == 0x08:
        return data.decode('utf_16_be', 'replace')
    if (dcs & 0x0C) == 0x04:
        return data.decode('latin-1', 'replace')
    return _decode_gsm7_octets(data)


def _decode_sm_tpdu(data):
    """Decode a GSM 03.40 (TS 23.040) SM TPDU (SMS-DELIVER / SMS-SUBMIT)."""
    if not data:
        return {}
    mti = data[0] & 0x03
    mti_names = {0: 'SMS-DELIVER', 1: 'SMS-SUBMIT', 2: 'SMS-STATUS-REPORT', 3: 'SMS-COMMAND'}
    udhi = bool(data[0] & 0x40)
    result = {'mti': mti_names.get(mti, f'unknown ({mti})'), 'udhi': udhi}

    if mti == 0:  # SMS-DELIVER
        i = 1
        if i < len(data):
            oa_len = data[i]
            i += 1
            oa_bytes = 1 + (oa_len + 1) // 2  # TON/NPI + BCD digits
            result['oa'] = _decode_bcd_address(data[i:i + oa_bytes])
            i += oa_bytes
        if i + 1 < len(data):
            result['pid'] = data[i]
            result['dcs'] = data[i + 1]
            i += 2
        i += 7  # TP-SCTS (service centre time stamp)
        if i < len(data):
            udl = data[i]
            i += 1
            result = _decode_ud(data[i:], udl, result.get('dcs', 0), udhi, result)
    elif mti == 1:  # SMS-SUBMIT
        vpf = (data[0] >> 3) & 0x03
        i = 1
        if i < len(data):
            result['mr'] = data[i]  # TP-MR
            i += 1
        if i < len(data):
            da_len = data[i]
            i += 1
            da_bytes = 1 + (da_len + 1) // 2
            result['da'] = _decode_bcd_address(data[i:i + da_bytes])
            i += da_bytes
        if i + 1 < len(data):
            result['pid'] = data[i]
            result['dcs'] = data[i + 1]
            i += 2
        if vpf in (1, 3):  # 1-octet validity period
            i += 1
        elif vpf == 2:  # 7-octet relative validity period
            i += 7
        if i < len(data):
            udl = data[i]
            i += 1
            result = _decode_ud(data[i:], udl, result.get('dcs', 0), udhi, result)

    return result


def _decode_ud(ud, udl, dcs, udhi, result):
    encoding, msg_class = _decode_dcs(dcs)
    result['encoding'] = encoding
    result['msg_class'] = msg_class

    pid = result.get('pid')
    if pid == 0x7F:  # SIM data download → secured packet (show hex)
        result['pid_name'] = 'SIM data download (secured packet)'
        result['payload'] = ud[:udl].hex().upper()
        return result

    if udhi and ud:
        udhl = ud[0]
        result['udh'] = ud[1:1 + udhl].hex().upper()
        body = ud[1 + udhl:]
        if encoding == 'GSM 7-bit':
            fill_bits = (udhl + 1) * 8
            n = udl - ((fill_bits + 6) // 7)
            result['text'] = _decode_gsm7(body, n)
        elif encoding == 'UCS2':
            result['text'] = body[:udl].decode('utf-16-be', errors='replace')
        else:
            result['payload'] = body[:udl].hex().upper()
    else:
        if encoding == 'GSM 7-bit':
            result['text'] = _decode_gsm7(ud, udl)
        elif encoding == 'UCS2':
            result['text'] = ud[:udl].decode('utf-16-be', errors='replace')
        else:
            result['payload'] = ud[:udl].hex().upper()

    return result


def _decode_envelope(body):
    """Decode an ENVELOPE command body (TS 102 223 / TS 31.111)."""
    tlvs = parse_tlv(body)
    if not tlvs:
        return {}
    tag, _length, value = tlvs[0]
    result = {'type': ENVELOPE_TYPES.get(tag, f'0x{tag:02X}')}
    inner = parse_tlv(value)

    if tag == 0xD6:  # EVENT DOWNLOAD
        for t, _l, v in inner:
            if t == 0x19:  # Event list
                result['events'] = [EVENT_TYPES.get(e, f'0x{e:02X}') for e in v]
            elif t == 0x1B:  # Location status
                if v:
                    result['location_status'] = LOCATION_STATUS.get(v[0], f'0x{v[0]:02X}')
            elif t == 0x13:  # Location information
                result['location_info'] = v.hex().upper()
            elif t == 0x02:  # Device identities
                result['device_ids'] = v.hex().upper()
    elif tag == 0xD5:  # MO SHORT MESSAGE CONTROL
        for t, _l, v in inner:
            if t == 0x06:  # Address objects
                if 'smsc' not in result:
                    result['smsc'] = _decode_bcd_address(v)
                else:
                    result['tp_da'] = _decode_bcd_address(v)
            elif t == 0x13:
                result['location_info'] = v.hex().upper()
            elif t == 0x02:
                result['device_ids'] = v.hex().upper()
    elif tag == 0xD1:  # SMS-PP DOWNLOAD
        for t, _l, v in inner:
            if t == 0x06:
                result['smsc'] = _decode_bcd_address(v)
            elif t == 0x86:  # SMS TPDU (SMS-DELIVER)
                result['tpdu'] = _decode_sm_tpdu(v)
            elif t == 0x02:
                result['device_ids'] = v.hex().upper()
    elif tag == 0xD2:  # CELL BROADCAST DOWNLOAD (structure only)
        for t, _l, v in inner:
            if t == 0x02:
                result['device_ids'] = v.hex().upper()
            else:
                result[f'tag_{t:02X}'] = v.hex().upper()
    else:  # D3 / D4 / D7 — device identities only
        for t, _l, v in inner:
            if t == 0x02:
                result['device_ids'] = v.hex().upper()

    return result


# ──────────────────── Proactive command-body decoder ────────────────────

# TS 102 223 §6.6 data-object tags (base value; comprehension bit masked off)
_P_CMD_DETAILS = 0x01
_P_DEVICE_IDS = 0x02
_P_DURATION = 0x04
_P_ALPHA_ID = 0x05
_P_ADDRESS = 0x06
_P_SMS_TPDU = 0x0B
_P_TEXT_STRING = 0x0D
_P_ITEM = 0x0F
_P_RESPONSE_LEN = 0x11
_P_EVENT_LIST = 0x19


def _decode_proactive(body):
    """Decode a FETCH proactive command body (D0 TLV) into a dict.

    Unwraps the D0 BER-TLV and decodes the command's data objects,
    dispatching on the Type of Command from the Command Details (0x81).
    """
    if not body:
        return None
    inner = None
    for tag, _length, value in parse_tlv(body):
        if tag == 0xD0:
            inner = parse_tlv(value)
            break
    if inner is None:
        return None

    cmd_type = None
    result = {}
    items = []
    for tag, _length, value in inner:
        base = tag & 0x7F
        if base == _P_CMD_DETAILS and len(value) >= 2:
            cmd_type = value[1]
        elif base == _P_ALPHA_ID and value:
            result['title'] = _decode_annex_a(value)
        elif base == _P_TEXT_STRING and value:
            result['text'] = _decode_dcs_text(value)
        elif base == _P_ITEM and len(value) >= 2:
            items.append({'id': value[0], 'text': _decode_annex_a(value[1:])})
        elif base == _P_SMS_TPDU and value:
            result['tpdu'] = _decode_sm_tpdu(value)
        elif base == _P_DURATION and len(value) >= 2:
            result['duration'] = (value[0] << 8) | value[1]
        elif base == _P_RESPONSE_LEN and len(value) >= 2:
            result['response_length'] = {'min': value[0], 'max': value[1]}
        elif base == _P_EVENT_LIST and value:
            result['events'] = [EVENT_TYPES.get(e, f'0x{e:02X}') for e in value]
        elif base == _P_ADDRESS and value:
            result['address'] = _decode_bcd_address(value)

    if cmd_type is None:
        return None
    result['type'] = CAT_COMMAND_TYPES.get(cmd_type, f'0x{cmd_type:02X}')
    if items:
        result['items'] = items
    return result


# ──────────────────── Decode entry point ────────────────────

def decode_message(raw_data, prev=None):
    """Decode a raw TPDU byte string into a structured dict.

    Returns None for non-TPDU messages (ATR, PPS, CHANGE, FIDI)
    or un-parseable data.  Returns a dict with ins_name, cla, p1, p2,
    p3, body, and sw keys for valid TPDU messages.

    *prev* optionally carries the previous TPDU's decoded context
    (``{'ins_name': str, 'sw1': str}``) for resolving GET RESPONSE.
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

        if ins == 0x14:
            response_to = decode_tr_command(body)
            if response_to:
                result['response_to'] = response_to
            result['response'] = _decode_tr_result(body)
        else:
            cat_command = decode_cat(ins, body)
            if cat_command:
                result['cat_command'] = cat_command
            if ins in (0x88, 0x89):  # AUTHENTICATE command body
                result['cmd'] = _decode_auth_cmd(body, p2)
            elif ins == 0xC2:  # ENVELOPE command body
                result['cmd'] = _decode_envelope(body)
            elif ins == 0x12:  # FETCH → proactive command body
                result['cmd'] = _decode_proactive(body)

    # SW
    if sw_bytes:
        result['sw'] = decode_sw(sw_bytes)

    # GET RESPONSE context: the response belongs to the previous command
    # if that command ended with SW1 '61' (response data available).
    if ins == 0xC0:
        if prev and prev.get('sw1') == '61':
            result['response_for'] = prev.get('ins_name')
            prev_ins = prev.get('ins')
            if prev_ins is not None and cmd_body_len > 0:
                response = _decode_response_for(prev_ins, remaining[:cmd_body_len])
                if response:
                    result['response'] = response
        else:
            result['response_for'] = None

    return result


# ──────────────────── Sniff-level message types ────────────────────

CHANGE_FLAGS = {
    1 << 0: 'Card inserted',
    1 << 1: 'Card ejected',
    1 << 2: 'Reset asserted',
    1 << 3: 'Reset de-asserted',
    1 << 4: 'Waiting time timeout',
}


def decode_change(flags):
    """Decode SIMtrace2 sniff_change flags into a list of human-readable names."""
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


def decode_sniff_msg(raw_data, msg_type, flags=0, prev=None):
    """Decode a raw sniff message of the given type.

    Returns a structured dict with at least a 'type' key, or None if
    the message type has no structured decode.

    *prev* optionally carries the previous TPDU's decoded context for
    resolving GET RESPONSE.
    """
    if msg_type == 'tpdu' and raw_data:
        return decode_message(raw_data, prev=prev)
    if msg_type == 'change':
        return decode_change(flags)
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
