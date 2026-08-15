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
    if cla == 0x80:
        interclass = 'ETSI-defined (UICC/USIM)'
    elif cla == 0xa0:
        interclass = 'ETSI-defined (SIM/GSM)'
    elif cla == 0x00:
        interclass = 'inter-industry (ISO 7816-4)'
    else:
        interclass = 'inter-industry' if (cla & 0x80) == 0 else 'proprietary'
    result = {
        'hex': f'{cla:02x}',
        'interclass': interclass,
        'channel': cla & 0x03,
        'secure_messaging': 'none' if (cla & 0x0c) == 0 else 'SM present',
        'chain': chain_names.get(chain_bits, f'unknown ({chain_bits})'),
    }
    return result


# ──────────────────── Known FIDs ────────────────────
# Sourced from pySim (TS 102 221 common, TS 51.011 SIM, TS 31.102 USIM,
# TS 31.103 ISIM).  Note: some FIDs are reused across DFs/ADFs; the
# USIM/ISIM interpretation is preferred here because the '7FFF' (current
# ADF) SELECT-path resolution is the primary use case.

KNOWN_FIDS = {
    # Master File and common files (TS 102 221 / TS 51.011)
    '3f00': 'MF',
    '2f00': 'EF_DIR',
    '2f05': 'EF_PL',
    '2f06': 'EF_ARR',
    '2f08': 'EF_UMPC',
    '2fe2': 'EF_ICCID',

    # Dedicated files (MF/ADF level)
    '7f10': 'DF_TELECOM',
    '7f20': 'DF_GSM',
    '5f3b': 'DF_GSM_ACCESS',
    '5f40': 'DF_WLAN',
    '5f50': 'DF_HNB',
    '5f90': 'DF_ProSe',
    '5ff0': 'DF_5G_ProSe',
    '5fc0': 'DF_5GS',
    '5fe0': 'DF_SNPN',
    '5ff1': 'DF_5MBSUECONFIG',

    # SIM (TS 51.011) — DF_TELECOM / DF_GSM
    '6f05': 'EF_LI',
    '6f07': 'EF_IMSI',
    '6f20': 'EF_Kc',
    '6f2c': 'EF_DCK',
    '6f30': 'EF_PLMNsel',
    '6f31': 'EF_HPPLMN',
    '6f32': 'EF_CNL',
    '6f37': 'EF_ACMmax',
    '6f38': 'EF_UST',
    '6f39': 'EF_ACM',
    '6f3a': 'EF_ADN',
    '6f3b': 'EF_FDN',
    '6f3c': 'EF_SMS',
    '6f3d': 'EF_CCP',
    '6f3e': 'EF_GID1',
    '6f3f': 'EF_GID2',
    '6f40': 'EF_MSISDN',
    '6f41': 'EF_PUCT',
    '6f42': 'EF_SMSP',
    '6f43': 'EF_SMSS',
    '6f44': 'EF_LND',
    '6f45': 'EF_CBMI',
    '6f46': 'EF_SPN',
    '6f47': 'EF_SMSR',
    '6f48': 'EF_CBMID',
    '6f49': 'EF_SDN',
    '6f4a': 'EF_EXT1',
    '6f4b': 'EF_EXT2',
    '6f4c': 'EF_EXT3',
    '6f4d': 'EF_BDN',
    '6f4e': 'EF_EXT4',
    '6f4f': 'EF_ECCP',
    '6f50': 'EF_CBMIR',
    '6f51': 'EF_NIA',
    '6f52': 'EF_KcGPRS',
    '6f53': 'EF_LOCI_GPRS',
    '6f58': 'EF_CMI',
    '6f63': 'EF_CPBCCH',
    '6f64': 'EF_InvScan',
    '6f74': 'EF_BCCH',
    '6f78': 'EF_ACC',
    '6f7b': 'EF_FPLMN',
    '6f7e': 'EF_LOCI',
    '6fad': 'EF_AD',
    '6fae': 'EF_Phase',
    '6fb1': 'EF_VGCS',
    '6fb2': 'EF_VGCSS',
    '6fb3': 'EF_VBS',
    '6fb4': 'EF_VBSS',
    '6fb5': 'EF_eMLPP',
    '6fb6': 'EF_AAeM',
    '6fb7': 'EF_ECC',
    '6fc5': 'EF_PNN',
    '6fc6': 'EF_OPL',
    '6fc9': 'EF_MBI',
    '6fca': 'EF_MWIS',
    '6fcb': 'EF_CFIS',
    '6fcd': 'EF_SPDI',
    '6fce': 'EF_MMSN',
    '6fd0': 'EF_MMSICP',
    '6fd1': 'EF_MMSUP',
    '6fd2': 'EF_MMSUCP',

    # USIM (TS 31.102) — ADF_USIM
    '6f01': 'EF_eAKA',
    '6f02': 'EF_IMPI',   # ISIM EF_IMPI (USIM reuses 6F02 for EF_OCST)
    '6f06': 'EF_ARR',
    '6f08': 'EF_Keys',
    '6f09': 'EF_KeysPS',  # ISIM EF_P-CSCF also reuses 6F09
    '6f55': 'EF_EXT4',
    '6f56': 'EF_EST',
    '6f57': 'EF_ACL',
    '6f5b': 'EF_START-HFN',
    '6f5c': 'EF_THRESHOLD',
    '6f60': 'EF_PLMNwAcT',
    '6f61': 'EF_OPLMNwAcT',
    '6f62': 'EF_HPLMNwAcT',
    '6f65': 'EF_RPLMNAcT',
    '6f73': 'EF_PSLOCI',
    '6f80': 'EF_ICI',
    '6f81': 'EF_OCI',
    '6f82': 'EF_ICT',
    '6f83': 'EF_OCT',
    '6fc4': 'EF_NETPAR',
    '6fc7': 'EF_MBDN',
    '6fc8': 'EF_EXT6',
    '6fcc': 'EF_EXT7',
    '6fcf': 'EF_EXT8',
    '6fd3': 'EF_NIA',
    '6fd4': 'EF_VGCSCA',
    '6fd5': 'EF_VBSCA',
    '6fd6': 'EF_GBABP',
    '6fd7': 'EF_MSK',
    '6fd8': 'EF_MUK',
    '6fd9': 'EF_EHPLMN',
    '6fda': 'EF_GBANL',
    '6fdb': 'EF_EHPLMNPI',
    '6fdd': 'EF_NAFKCA',
    '6fde': 'EF_SPNI',
    '6fdf': 'EF_PNNI',
    '6fe2': 'EF_NCP-IP',
    '6fe3': 'EF_EPSLOCI',
    '6fe4': 'EF_EPSNSC',
    '6fe6': 'EF_UFC',
    '6fe8': 'EF_NASCONFIG',
    '6fec': 'EF_PWS',
    '6fed': 'EF_FDNURI',
    '6fee': 'EF_BDNURI',
    '6fef': 'EF_SDNURI',
    '6ff1': 'EF_IPS',
    '6ff3': 'EF_ePDGId',
    '6ff4': 'EF_ePDGSelection',
    '6ff5': 'EF_ePDGIdEm',
    '6ff6': 'EF_ePDGSelectionEm',
    '6ff7': 'EF_FromPreferred',
    '6ff8': 'EF_IMSConfigData',
    '6ffa': 'EF_WebRTCURI',
    '6ffc': 'EF_XCAPConfigData',
    '6ffd': 'EF_EARFCNList',
    '6ffe': 'EF_MuDMiDConfigData',

    # ISIM (TS 31.103) — ADF_ISIM
    '6f03': 'EF_DOMAIN',
    '6f04': 'EF_IMPU',
    '6f0a': 'EF_GBAUAPI',
    '6f0b': 'EF_IMSDCI',
     '6fe7': 'EF_UICCIARI',
}


# DF/ADF children (child FID → name), for context-aware SELECT-path
# resolution.  The '4Fxx' files are only meaningful within their parent
# DF, and many FIDs collide across DFs (e.g. '4F01' differs between
# DF_ProSe, DF_5GS, DF_MCS, DF_V2X, DF_SNPN), so they cannot live in the
# flat KNOWN_FIDS table.  Sourced from pySim (TS 31.102 / TS 31.102 telecom).
DF_CHILDREN = {
    '7f10': {  # DF_TELECOM
        '5f3a': 'DF_PHONEBOOK',
        '5f3b': 'DF_MULTIMEDIA',
        '5f3d': 'DF_MCS',
        '5f3e': 'DF_V2X',
    },
    '5f3a': {  # DF_PHONEBOOK
        '4f22': 'EF_PSC',
        '4f23': 'EF_CC',
        '4f24': 'EF_PUID',
        '4f30': 'EF_PBR',
    },
    '5f3b': {  # DF_GSM_ACCESS (ADF) + DF_MULTIMEDIA (DF_TELECOM) share 5F3B
        '4f20': 'EF_Kc',
        '4f52': 'EF_KcGPRS',
        '4f63': 'EF_CPBCCH',
        '4f64': 'EF_InvScan',
        '4f47': 'EF_MML',
        '4f48': 'EF_MMDF',
    },
    '5f3d': {  # DF_MCS
        '4f01': 'EF_MST',
        '4f02': 'EF_MCS_CONFIG',
    },
    '5f3e': {  # DF_V2X
        '4f01': 'EF_VST',
        '4f02': 'EF_V2X_CONFIG',
    },
    '5f40': {  # DF_WLAN
        '4f41': 'EF_Pseudo',
        '4f42': 'EF_UPLMNWLAN',
        '4f43': 'EF_OPLMNWLAN',
        '4f44': 'EF_UWSIDL',
        '4f45': 'EF_OWSIDL',
        '4f46': 'EF_WRI',
        '4f47': 'EF_HWSIDL',
        '4f48': 'EF_WEHPLMNPI',
        '4f49': 'EF_WHPI',
        '4f4a': 'EF_WLRPLMN',
        '4f4b': 'EF_HPLMNDAI',
    },
    '5f50': {  # DF_HNB
        '4f81': 'EF_ACSGL',
        '4f82': 'EF_CSGT',
        '4f83': 'EF_HNBN',
        '4f84': 'EF_OCSGL',
        '4f85': 'EF_OCSGT',
        '4f86': 'EF_OHNBN',
    },
    '5f90': {  # DF_ProSe
        '4f01': 'EF_PROSE_MON',
        '4f02': 'EF_PROSE_ANN',
        '4f03': 'EF_PROSEFUNC',
        '4f04': 'EF_PROSE_RADIO_COM',
        '4f05': 'EF_PROSE_RADIO_MON',
        '4f06': 'EF_PROSE_RADIO_ANN',
        '4f07': 'EF_PROSE_POLICY',
        '4f08': 'EF_PROSE_PLMN',
        '4f09': 'EF_PROSE_GC',
        '4f10': 'EF_PST',
        '4f11': 'EF_UIRC',
        '4f12': 'EF_PROSE_GM_DISCOVERY',
        '4f13': 'EF_PROSE_RELAY',
        '4f14': 'EF_PROSE_RELAY_DISCOVERY',
    },
    '5fc0': {  # DF_5GS
        '4f01': 'EF_5GS3GPPLOCI',
        '4f02': 'EF_5GSN3GPPLOCI',
        '4f03': 'EF_5GS3GPPNSC',
        '4f04': 'EF_5GSN3GPPNSC',
        '4f05': 'EF_5GAUTHKEYS',
        '4f06': 'EF_UAC_AIC',
        '4f07': 'EF_SUCI_Calc_Info',
        '4f08': 'EF_OPL5G',
        '4f09': 'EF_SUPI_NAI',
        '4f0a': 'EF_Routing_Indicator',
        '4f0b': 'EF_URSP',
        '4f0c': 'EF_TN3GPPSNN',
        '4f0d': 'EF_CAG',
        '4f0e': 'EF_SOR-CMCI',
        '4f0f': 'EF_DRI',
        '4f10': 'EF_5GSEDRX',
        '4f11': 'EF_5GNSWO_CONF',
        '4f15': 'EF_MCHPPLMN',
        '4f16': 'EF_KAUSF_DERIVATION',
    },
    '5fd0': {  # DF_SAIP
        '4f01': 'EF_SUCI_Calc_Info',
    },
    '5fe0': {  # DF_SNPN
        '4f01': 'EF_PWS_SNPN',
        '4f02': 'EF_NID',
    },
    '5ff0': {  # DF_5G_ProSe
        '4f02': 'EF_5G_PROSE_DD',
        '4f03': 'EF_5G_PROSE_DC',
        '4f04': 'EF_5G_PROSE_U2NRU',
        '4f05': 'EF_5G_PROSE_RU',
        '4f06': 'EF_5G_PROSE_UIR',
        '4f07': 'EF_5G_PROSE_U2URU',
        '4f08': 'EF_5G_PROSE_EU',
    },
    '5ff1': {  # DF_5MBSUECONFIG
        '4f01': 'EF_5MBSUECONFIG',
    },
}


def _decode_select_path(body_hex):
    """Decode a SELECT path body into a human-readable path.

    Splits the body into 2-byte FIDs and names each component, tracking
    the parent DF so DF-specific children (e.g. '4Fxx') resolve against
    the correct DF.  '7fff' is the implicit FID for the current
    application's ADF, whose children are the flat KNOWN_FIDS files.
    """
    pairs = [body_hex[i:i + 4] for i in range(0, len(body_hex), 4)]
    parts = []
    parent = None
    for p in pairs:
        if p == '7fff':
            parts.append('current ADF')
            parent = None
            continue
        name = None
        if parent and parent in DF_CHILDREN:
            name = DF_CHILDREN[parent].get(p)
        if name is None:
            name = KNOWN_FIDS.get(p)
        parts.append(name if name else p.upper())
        parent = p if p in DF_CHILDREN else None
    return '/'.join(parts)


def select_target_fid(d):
    """Return the FID targeted by a decoded SELECT message, or None.

    Used by the server's selection tracking to know which file is
    currently selected (so READ/UPDATE bodies can be decoded).
    """
    p1 = (d.get('p1') or {}).get('raw')
    h = (d.get('body') or {}).get('hex') or ''
    if p1 in ('00', '01'):  # select by FID / child DF
        return h if len(h) == 4 else None
    if p1 in ('08', '09'):  # select by path
        if len(h) >= 4:
            last = h[-4:]
            return None if last == '7fff' else last
        return None
    return None


# ──────────────────── Per-INS specifications ────────────────────

APDU_SPEC = {
    0xA4: {
        'name': 'SELECT',
        'p1': {
            0x00: 'DF/EF/MF by file ID',
            0x01: 'Child DF',
            0x03: 'Parent DF',
            0x04: 'Application DF by name',
            0x08: 'Path from MF',
            0x09: 'Path from current DF',
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

    Handles single-byte tags and both short-form (< 128) and long-form
    BER-TLV lengths (0x81 NN, 0x82 NN NN).  Indefinite lengths (0x80)
    and truncated data cause parsing to stop at that point.
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
            num_len = length & 0x7F
            if num_len == 0:  # indefinite length — not supported
                break
            if i + num_len > n:
                break
            length = int.from_bytes(data[i:i + num_len], 'big')
            i += num_len
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
    if any((x >> 4) > 9 or (x & 0x0F) > 9 for x in b[:6]):
        return None
    bcd = lambda x: (x >> 4) * 10 + (x & 0x0F)
    yy, mm, dd, hh, mi, ss = (bcd(x) for x in b[:6])
    if not (1 <= mm <= 12 and 1 <= dd <= 31 and hh <= 23 and mi <= 59 and ss <= 59):
        return None
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


# TS 102 223 §8.8 — Duration data object: [time unit][time interval]
_TIME_UNITS = {0x00: 'minutes', 0x01: 'seconds', 0x02: 'tenths of seconds'}


def _decode_duration(value):
    """Decode a Duration data object value (time unit + time interval)."""
    if len(value) < 2:
        return None
    return {'value': value[1], 'unit': _TIME_UNITS.get(value[0], f'unit 0x{value[0]:02X}')}


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
        elif tag == 0x04:  # Duration (POLL INTERVAL)
            result['duration'] = _decode_duration(value)
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
        elif tag == 0x80:
            result['file_size'] = int.from_bytes(value, 'big')
        elif tag == 0x81:
            result['total_file_size'] = int.from_bytes(value, 'big')
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


def _decode_dcs_full(dcs):
    """Decode TP-DCS into a rich dict (TS 23.038 §4).

    Returns encoding/msg_class (same as _decode_dcs) plus the coding
    group name and group-specific flags: compression, message class
    presence, and Message Waiting Indication details.
    """
    encoding, msg_class = _decode_dcs(dcs)
    result = {'hex': f'{dcs:02x}', 'encoding': encoding, 'msg_class': msg_class}
    group = dcs >> 4
    if group in (0x0, 0x1):
        result['group'] = ('General Data Coding indication'
                           if group == 0 else 'Message Marked for Automatic Deletion')
        result['compressed'] = bool(dcs & 0x20)
        result['has_class'] = bool(dcs & 0x10)
    elif group in (0xC, 0xD, 0xE):
        result['group'] = 'Message Waiting Indication'
        result['action'] = 'discard' if group == 0xC else 'store'
        result['sense'] = 'active' if (dcs & 0x08) else 'inactive'
        result['indication'] = {0: 'voicemail', 1: 'fax', 2: 'email', 3: 'other'}.get(dcs & 0x03)
    elif group == 0xF:
        result['group'] = 'Data coding / message class'
    else:  # 0x8..0xB reserved
        result['group'] = 'reserved'
    return result


# TS 23.040 §9.2.3.9 — TP-Protocol-Identifier values (SMS-DELIVER / SMS-SUBMIT)
PID_NAMES = {
    0x00: 'SME-to-SME (implicit)',
    0x20: 'Telematic: implicit',
    0x21: 'Telematic: telex',
    0x22: 'Telematic: group 3 telefax',
    0x23: 'Telematic: group 4 telefax',
    0x24: 'Telematic: voice telephone',
    0x25: 'Telematic: ERMES',
    0x26: 'Telematic: national paging',
    0x27: 'Telematic: videotex',
    0x28: 'Telematic: teletex (unspecified)',
    0x2A: 'Telematic: teletex (CSPDN)',
    0x2D: 'Telematic: teletex (ISDN)',
    0x30: 'Message handling facility',
    0x31: 'X.400-based MHS',
    0x32: 'Internet Electronic Mail',
    0x3F: 'GSM/UMTS mobile station',
    0x40: 'Short Message Type 0',
    0x41: 'Replace Short Message Type 1',
    0x42: 'Replace Short Message Type 2',
    0x43: 'Replace Short Message Type 3',
    0x44: 'Replace Short Message Type 4',
    0x45: 'Replace Short Message Type 5',
    0x46: 'Replace Short Message Type 6',
    0x47: 'Replace Short Message Type 7',
    0x48: 'Device Triggering Short Message',
    0x5F: 'Return Call Message',
    0x7C: 'ANSI-136 R-DATA',
    0x7D: 'ME Data download',
    0x7E: 'ME De-personalization Short Message',
    0x7F: '(U)SIM Data download',
}


def _decode_pid(pid):
    return PID_NAMES.get(pid)


# TS 23.040 §9.2.3.24 — User Data Header Information Element Identifiers
IEI_NAMES = {
    0x00: 'Concatenated short messages, 8-bit reference number',
    0x01: 'Special SMS Message Indication',
    0x04: 'Application port addressing scheme, 8 bit address',
    0x05: 'Application port addressing scheme, 16 bit address',
    0x06: 'SMSC Control Parameters',
    0x07: 'UDH Source Indicator',
    0x08: 'Concatenated short message, 16-bit reference number',
    0x09: 'Wireless Control Message Protocol',
    0x0A: 'Text Formatting',
    0x0B: 'Predefined Sound',
    0x0C: 'User Defined Sound',
    0x0D: 'Predefined Animation',
    0x0E: 'Large Animation',
    0x0F: 'Small Animation',
    0x10: 'Large Picture',
    0x11: 'Small Picture',
    0x12: 'Variable Picture',
    0x13: 'User prompt indicator',
    0x14: 'Extended Object',
    0x15: 'Reused Extended Object',
    0x16: 'Compression Control',
    0x17: 'Object Distribution Indicator',
    0x18: 'Standard WVG object',
    0x19: 'Character Size WVG object',
    0x1A: 'Extended Object Data Request Command',
    0x20: 'RFC 5322 E-Mail Header',
    0x21: 'Hyperlink format element',
    0x22: 'Reply Address Element',
    0x23: 'Enhanced Voice Mail Information',
    0x24: 'National Language Single Shift',
    0x25: 'National Language Locking Shift',
    0x26: 'Filler',
}

_SPECIAL_SMS_TYPES = {0: 'voice', 1: 'fax', 2: 'email', 3: 'other'}


def _decode_udh(udh):
    """Parse a TP-User-Data-Header byte string into a list of IEI dicts.

    Each element is ``{'iei', 'name', 'length', 'hex'}`` plus an IE-specific
    ``'data'`` dict for the common cases (concatenation, application port,
    special SMS indication).
    """
    elements = []
    i = 0
    while i + 2 <= len(udh):
        iei = udh[i]
        length = udh[i + 1]
        data = udh[i + 2:i + 2 + length]
        i += 2 + length
        el = {'iei': f'0x{iei:02X}', 'name': IEI_NAMES.get(iei),
              'length': length, 'hex': data.hex().upper()}
        if iei == 0x00 and length >= 3:  # concatenated, 8-bit reference
            el['data'] = {'reference': data[0], 'max': data[1], 'seq': data[2]}
        elif iei == 0x08 and length >= 4:  # concatenated, 16-bit reference
            el['data'] = {'reference': int.from_bytes(data[:2], 'big'),
                          'max': data[2], 'seq': data[3]}
        elif iei == 0x01 and length >= 2:  # special SMS message indication
            el['data'] = {'store': bool(data[0] & 0x80),
                          'indication': _SPECIAL_SMS_TYPES.get(data[0] & 0x03),
                          'count': data[1]}
        elif iei == 0x04 and length >= 2:  # application port, 8-bit
            el['data'] = {'dest_port': data[0], 'orig_port': data[1]}
        elif iei == 0x05 and length >= 4:  # application port, 16-bit
            el['data'] = {'dest_port': int.from_bytes(data[:2], 'big'),
                          'orig_port': int.from_bytes(data[2:4], 'big')}
        elements.append(el)
    return elements


def _decode_vp_relative(v):
    """Decode a 1-octet TP-Validity-Period (relative format, TS 23.040 §9.2.3.12.1)."""
    if 0 <= v <= 143:
        return f'{(v + 1) * 5} min'
    if 144 <= v <= 167:
        hours = 12 + (v - 143) // 2
        mins = ((v - 143) % 2) * 30
        return f'{hours}h{mins:02d}m'
    if 168 <= v <= 196:
        return f'{v - 166} d'
    if 197 <= v <= 255:
        return f'{v - 192} wk'
    return None


def _decode_8bit_text(data):
    """Best-effort printable text for 8-bit TP-UD data.

    If every byte is ASCII (<= 0x7F) or every byte has the high bit set
    (>= 0x80, latin-1), decode to a printable string with non-printable
    characters replaced by '·'.  Mixed ranges are treated as binary and
    return None.
    """
    if not data:
        return None
    if all(b <= 0x7F for b in data):
        return ''.join(chr(b) if 0x20 <= b < 0x7F else '\u00b7' for b in data)
    if all(b >= 0x80 for b in data):
        return ''.join(chr(b) if b >= 0xA0 else '\u00b7' for b in data)
    return None


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
            pid_name = _decode_pid(result['pid'])
            if pid_name:
                result['pid_name'] = pid_name
            result['dcs_info'] = _decode_dcs_full(result['dcs'])
            result['encoding'] = result['dcs_info']['encoding']
            result['msg_class'] = result['dcs_info']['msg_class']
        scts = _decode_datetime(data[i:i + 7])  # TP-SCTS (service centre time stamp)
        if scts:
            result['scts'] = scts
        i += 7
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
            pid_name = _decode_pid(result['pid'])
            if pid_name:
                result['pid_name'] = pid_name
            result['dcs_info'] = _decode_dcs_full(result['dcs'])
            result['encoding'] = result['dcs_info']['encoding']
            result['msg_class'] = result['dcs_info']['msg_class']
        if vpf == 1:  # relative: 1-octet validity period
            if i < len(data):
                vp = _decode_vp_relative(data[i])
                if vp:
                    result['vp'] = vp
            i += 1
        elif vpf == 2:  # absolute: 7-octet validity period (semi-octet time)
            vp = _decode_datetime(data[i:i + 7])
            result['vp'] = vp if vp else data[i:i + 7].hex().upper()
            i += 7
        elif vpf == 3:  # enhanced: 7-octet validity period
            result['vp'] = data[i:i + 7].hex().upper()
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
        result['udhl'] = udhl
        result['udh'] = _decode_udh(ud[1:1 + udhl])
        body = ud[1 + udhl:]
        if encoding == 'GSM 7-bit':
            fill_bits = (udhl + 1) * 8
            n = udl - ((fill_bits + 6) // 7)
            result['text'] = _decode_gsm7(body, n)
        elif encoding == 'UCS2':
            result['text'] = body[:udl].decode('utf-16-be', errors='replace')
        else:
            result['payload'] = body[:udl].hex().upper()
            text = _decode_8bit_text(body[:udl])
            if text is not None:
                result['text'] = text
    else:
        if encoding == 'GSM 7-bit':
            result['text'] = _decode_gsm7(ud, udl)
        elif encoding == 'UCS2':
            result['text'] = ud[:udl].decode('utf-16-be', errors='replace')
        else:
            result['payload'] = ud[:udl].hex().upper()
            text = _decode_8bit_text(ud[:udl])
            if text is not None:
                result['text'] = text

    return result


def _decode_cb_page(value):
    """Decode a CELL BROADCAST DOWNLOAD CB page (TS 31.111 §8.5 / TS 23.041).

    Layout: serial number (2), message identifier (2), DCS (1), page
    parameter (1), content (up to 82 octets).  Content is returned as raw
    hex (no text decode).
    """
    if len(value) < 6:
        return {'content': value.hex().upper()}
    serial = value[0:2].hex().upper()
    message_id = value[2:4].hex().upper()
    dcs = value[4]
    page_byte = value[5]
    total_pages = (page_byte >> 4) & 0x0F
    page_num = page_byte & 0x0F
    encoding, msg_class = _decode_dcs(dcs)
    dcs_str = f'0x{dcs:02X} — {encoding}' + (f' (class {msg_class})' if msg_class else '')
    return {
        'serial': serial,
        'message_id': '0x' + message_id,
        'dcs': dcs_str,
        'page': f'{page_num}/{total_pages}',
        'content': value[6:].hex().upper(),
    }


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
                li = _decode_local_info(PLI_LOCATION_INFO, v)
                result['location_info'] = li['value'] if li else v.hex().upper()
            elif t in (0x06, 0x86):  # Address (caller's number, MT call)
                result['caller'] = _decode_bcd_address(v)
            elif t == 0x1C:  # Transaction identifier (MT call)
                if v:
                    result['transaction_id'] = v[0]
            elif t in (0x08, 0x88):  # Subaddress
                result['subaddress'] = v.hex().upper()
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
            elif t in (0x0B, 0x8B):  # SMS TPDU (SMS-DELIVER)
                result['tpdu'] = _decode_sm_tpdu(v)
            elif t == 0x02:
                result['device_ids'] = v.hex().upper()
    elif tag == 0xD2:  # CELL BROADCAST DOWNLOAD
        for t, _l, v in inner:
            if t == 0x02:
                result['device_ids'] = v.hex().upper()
            elif t in (0x0C, 0x8C):  # CB page
                result['cb_page'] = _decode_cb_page(v)
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
        elif base == _P_DURATION:
            result['duration'] = _decode_duration(value)
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

# ──────────────────── File data decoders (READ/UPDATE) ────────────────────
# These decode the *body* of READ BINARY/RECORD and UPDATE BINARY/RECORD
# commands using the currently selected file (see select_target_fid and the
# server's selection tracking).  Sourced from pySim (TS 51.011 SIM, TS 31.102
# USIM, TS 31.103 ISIM).

# USIM Service Table (TS 31.102) — service n ↔ bit (n-1)
UST_SERVICES = {
    1: 'Local Phone Book', 2: 'Fixed Dialling Numbers (FDN)', 3: 'Extension 2',
    4: 'Service Dialling Numbers (SDN)', 5: 'Extension3', 6: 'Barred Dialling Numbers (BDN)',
    7: 'Extension4', 8: 'Outgoing Call Information (OCI and OCT)',
    9: 'Incoming Call Information (ICI and ICT)', 10: 'Short Message Storage (SMS)',
    11: 'Short Message Status Reports (SMSR)', 12: 'Short Message Service Parameters (SMSP)',
    13: 'Advice of Charge (AoC)', 14: 'Capability Configuration Parameters 2 (CCP2)',
    15: 'Cell Broadcast Message Identifier', 16: 'Cell Broadcast Message Identifier Ranges',
    17: 'Group Identifier Level 1', 18: 'Group Identifier Level 2', 19: 'Service Provider Name',
    20: 'User controlled PLMN selector with Access Technology', 21: 'MSISDN', 22: 'Image (IMG)',
    23: 'Support of Localised Service Areas (SoLSA)', 24: 'Enhanced Multi-Level Precedence and Pre-emption Service',
    25: 'Automatic Answer for eMLPP', 26: 'RFU', 27: 'GSM Access', 28: 'Data download via SMS-PP',
    29: 'Data download via SMS-CB', 30: 'Call Control by USIM', 31: 'MO-SMS Control by USIM',
    32: 'RUN AT COMMAND command', 33: 'shall be set to 1', 34: 'Enabled Services Table',
    35: 'APN Control List (ACL)', 36: 'Depersonalisation Control Keys', 37: 'Co-operative Network List',
    38: 'GSM security context', 39: 'CPBCCH Information', 40: 'Investigation Scan', 41: 'MexE',
    42: 'Operator controlled PLMN selector with Access Technology', 43: 'HPLMN selector with Access Technology',
    44: 'Extension 5', 45: 'PLMN Network Name', 46: 'Operator PLMN List', 47: 'Mailbox Dialling Numbers',
    48: 'Message Waiting Indication Status', 49: 'Call Forwarding Indication Status', 50: 'Reserved and shall be ignored',
    51: 'Service Provider Display Information', 52: 'Multimedia Messaging Service (MMS)', 53: 'Extension 8',
    54: 'Call control on GPRS by USIM', 55: 'MMS User Connectivity Parameters',
    56: "Network's indication of alerting in the MS (NIA)", 57: 'VGCS Group Identifier List (EFVGCS and EFVGCSS)',
    58: 'VBS Group Identifier List (EFVBS and EFVBSS)', 59: 'Pseudonym',
    60: 'User Controlled PLMN selector for I-WLAN access', 61: 'Operator Controlled PLMN selector for I-WLAN access',
    62: 'User controlled WSID list', 63: 'Operator controlled WSID list', 64: 'VGCS security', 65: 'VBS security',
    66: 'WLAN Reauthentication Identity', 67: 'Multimedia Messages Storage',
    68: 'Generic Bootstrapping Architecture (GBA)', 69: 'MBMS security',
    70: 'Data download via USSD and USSD application mode', 71: 'Equivalent HPLMN',
    72: 'Additional TERMINAL PROFILE after UICC activation', 73: 'Equivalent HPLMN Presentation Indication',
    74: 'Last RPLMN Selection Indication', 75: 'OMA BCAST Smart Card Profile',
    76: 'GBA-based Local Key Establishment Mechanism', 77: 'Terminal Applications', 78: 'Service Provider Name Icon',
    79: 'PLMN Network Name Icon', 80: 'Connectivity Parameters for USIM IP connections',
    81: 'Home I-WLAN Specific Identifier List', 82: 'I-WLAN Equivalent HPLMN Presentation Indication',
    83: 'I-WLAN HPLMN Priority Indication', 84: 'I-WLAN Last Registered PLMN', 85: 'EPS Mobility Management Information',
    86: 'Allowed CSG Lists and corresponding indications', 87: 'Call control on EPS PDN connection by USIM',
    88: 'HPLMN Direct Access', 89: 'eCall Data', 90: 'Operator CSG Lists and corresponding indications',
    91: 'Support for SM-over-IP', 92: 'Support of CSG Display Control', 93: 'Communication Control for IMS by USIM',
    94: 'Extended Terminal Applications', 95: 'Support of UICC access to IMS',
    96: 'Non-Access Stratum configuration by USIM', 97: 'PWS configuration by USIM', 98: 'RFU',
    99: 'URI support by UICC', 100: 'Extended EARFCN support', 101: 'ProSe', 102: 'USAT Application Pairing',
    103: 'Media Type support', 104: 'IMS call disconnection cause', 105: 'URI support for MO SHORT MESSAGE CONTROL',
    106: 'ePDG configuration Information support', 107: 'ePDG configuration Information configured', 108: 'ACDC support',
    109: 'MCPTT', 110: 'ePDG configuration Information for Emergency Service support',
    111: 'ePDG configuration Information for Emergency Service configured', 112: 'eCall Data over IMS',
    113: 'URI support for SMS-PP DOWNLOAD as defined in 3GPP TS 31.111 [12]', 114: 'From Preferred',
    115: 'IMS configuration data', 116: 'TV configuration', 117: '3GPP PS Data Off',
    118: '3GPP PS Data Off Service List', 119: 'V2X', 120: 'XCAP Configuration Data',
    121: 'EARFCN list for MTC/NB-IOT UEs', 122: '5GS Mobility Management Information', 123: '5G Security Parameters',
    124: 'Subscription identifier privacy support', 125: 'SUCI calculation by the USIM',
    126: 'UAC Access Identities support',
    127: 'Expect control plane-based Steering of Roaming information during initial registration in VPLMN',
    128: 'Call control on PDU Session by USIM', 129: '5GS Operator PLMN List',
    130: 'Support for SUPI of type NSI or GLI or GCI', 131: '3GPP PS Data Off separate Home and Roaming lists',
    132: 'Support for URSP by USIM', 133: '5G Security Parameters extended', 134: 'MuD and MiD configuration data',
    135: 'Support for Trusted non-3GPP access networks by USIM',
    136: 'Support for multiple records of NAS security context storage for multiple registration',
    137: 'Pre-configured CAG information list', 138: 'SOR-CMCI storage in USIM', 139: '5G ProSe',
    140: 'Storage of disaster roaming information in USIM', 141: 'Pre-configured eDRX parameters',
    142: '5G NSWO support', 143: 'PWS configuration for SNPN in USIM',
    144: 'Multiplier Coefficient for Higher Priority PLMN search via NG-RAN satellite access',
    145: 'K_AUSF derivation configuration', 146: 'Network Identifier for SNPN (NID)',
}

# SIM Service Table (TS 51.011)
SST_SERVICES = {
    1: 'CHV1 disable function', 2: 'Abbreviated Dialling Numbers (ADN)', 3: 'Fixed Dialling Numbers (FDN)',
    4: 'Short Message Storage (SMS)', 5: 'Advice of Charge (AoC)', 6: 'Capability Configuration Parameters (CCP)',
    7: 'PLMN selector', 8: 'RFU', 9: 'MSISDN', 10: 'Extension1', 11: 'Extension2', 12: 'SMS Parameters',
    13: 'Last Number Dialled (LND)', 14: 'Cell Broadcast Message Identifier', 15: 'Group Identifier Level 1',
    16: 'Group Identifier Level 2', 17: 'Service Provider Name', 18: 'Service Dialling Numbers (SDN)',
    19: 'Extension3', 20: 'RFU', 21: 'VGCS Group Identifier List (EFVGCS and EFVGCSS)',
    22: 'VBS Group Identifier List (EFVBS and EFVBSS)', 23: 'enhanced Multi-Level Precedence and Pre-emption Service',
    24: 'Automatic Answer for eMLPP', 25: 'Data download via SMS-CB', 26: 'Data download via SMS-PP',
    27: 'Menu selection', 28: 'Call control', 29: 'Proactive SIM', 30: 'Cell Broadcast Message Identifier Ranges',
    31: 'Barred Dialling Numbers (BDN)', 32: 'Extension4', 33: 'De-personalization Control Keys',
    34: 'Co-operative Network List', 35: 'Short Message Status Reports', 36: "Network's indication of alerting in the MS",
    37: 'Mobile Originated Short Message control by SIM', 38: 'GPRS', 39: 'Image (IMG)',
    40: 'SoLSA (Support of Local Service Area)', 41: 'USSD string data object supported in Call Control',
    42: 'RUN AT COMMAND command', 43: 'User controlled PLMN Selector with Access Technology',
    44: 'Operator controlled PLMN Selector with Access Technology', 45: 'HPLMN Selector with Access Technology',
    46: 'CPBCCH Information', 47: 'Investigation Scan', 48: 'Extended Capability Configuration Parameters',
    49: 'MExE', 50: 'Reserved and shall be ignored', 51: 'PLMN Network Name', 52: 'Operator PLMN List',
    53: 'Mailbox Dialling Numbers', 54: 'Message Waiting Indication Status', 55: 'Call Forwarding Indication Status',
    56: 'Service Provider Display Information', 57: 'Multimedia Messaging Service (MMS)', 58: 'Extension 8',
    59: 'MMS User Connectivity Parameters',
}

# ISIM Service Table (TS 31.103)
IST_SERVICES = {
    1: 'P-CSCF address', 2: 'Generic Bootstrapping Architecture (GBA)', 3: 'HTTP Digest',
    4: 'GBA-based Local Key Establishment Mechanism', 5: 'Support of P-CSCF discovery for IMS Local Break Out',
    6: 'Short Message Storage (SMS)', 7: 'Short Message Status Reports (SMSR)',
    8: 'Support for SM-over-IP including data download via SMS-PP as defined in TS 31.111 [31]',
    9: 'Communication Control for IMS by ISIM', 10: 'Support of UICC access to IMS', 11: 'URI support by UICC',
    12: 'Media Type support', 13: 'IMS call disconnection cause', 14: 'URI support for MO SHORT MESSAGE CONTROL',
    15: 'MCPTT', 16: 'URI support for SMS-PP DOWNLOAD as defined in 3GPP TS 31.111 [31]', 17: 'From Preferred',
    18: 'IMS configuration data', 19: 'XCAP Configuration Data', 20: 'WebRTC URI',
    21: 'MuD and MiD configuration data', 22: 'IMS Data Channel indication',
}

_PHASE_NAMES = {0x00: 'phase 1', 0x02: 'phase 2', 0x03: 'phase 2 and higher'}


def _decode_service_table(raw, table):
    flags = []
    for i, b in enumerate(raw):
        for bit in range(8):
            if b & (1 << bit):
                n = i * 8 + bit + 1
                flags.append({'n': n, 'name': table.get(n)})
    return {'services': flags}


def _decode_imsi(raw, p1=None):
    if not raw or all(b == 0xff for b in raw):
        return {'empty': True}
    if len(raw) <= 2:  # 6F07 is also the ISIM Service Table (IST)
        return _decode_service_table(raw, IST_SERVICES)
    digits = _swap_nibbles(raw[1:].hex()).rstrip('fF')
    return {'imsi': digits or None}


def _decode_iccid(raw, p1=None):
    if not raw or all(b == 0xff for b in raw):
        return {'empty': True}
    digits = _swap_nibbles(raw.hex()).rstrip('fF')
    return {'iccid': digits or None}


def _decode_li(raw, p1=None):
    """EF_LI / EF_PL — 2-letter ISO 639 language codes."""
    codes = []
    for i in range(0, len(raw) - 1, 2):
        pair = raw[i:i + 2]
        if pair == b'\xff\xff':
            continue
        try:
            c = pair.decode('ascii')
        except UnicodeDecodeError:
            continue
        if c.isalpha():
            codes.append(c)
    return {'languages': codes}


def _decode_adn(raw, p1=None):
    """ADN-format record: alpha + len_bcd + TON/NPI + number + CCP + ext1."""
    if not raw or all(b == 0xff for b in raw):
        return {'empty': True}
    if len(raw) < 14:
        return {'raw': raw.hex().upper()}
    alpha = raw[:-14].rstrip(b'\xff')
    name = _decode_annex_a(alpha) if alpha else ''
    number = _decode_bcd_address(raw[-13:-2])
    ccp = raw[-2]
    ext1 = raw[-1]
    out = {'name': name, 'number': number}
    if ccp != 0xff:
        out['ccp'] = ccp
    if ext1 != 0xff:
        out['ext1'] = ext1
    return out


def _decode_sms_rec(raw, p1=None):
    """EF_SMS record (TS 51.011 §10.5.3): status byte + SMSC address + TPDU."""
    if not raw or all(b == 0xff for b in raw):
        return {'empty': True}
    s = raw[0]
    if s & 0x01 == 0x00:
        direction, status = None, 'free space'
    elif s & 0x07 == 0x01:
        direction, status = 'MT', 'message read'
    elif s & 0x07 == 0x03:
        direction, status = 'MT', 'message to be read'
    elif s & 0x07 == 0x07:
        direction, status = 'MO', 'message to be sent'
    elif s & 0x1f == 0x05:
        direction, status = 'MO', 'sent (status not requested)'
    elif s & 0x1f == 0x0d:
        direction, status = 'MO', 'sent (status requested, not received)'
    elif s & 0x1f == 0x15:
        direction, status = 'MO', 'sent (status received, not stored)'
    elif s & 0x1f == 0x1d:
        direction, status = 'MO', 'sent (status received, stored)'
    else:
        direction, status = None, 'RFU'
    out = {'direction': direction, 'status': status}
    remainder = raw[1:]
    # Skip the TS-Service-Centre-Address: 1 length octet + that many octets.
    if remainder:
        sc_len = remainder[0]
        i = 1 + sc_len
        tpdu_bytes = remainder[i:].rstrip(b'\xff')
        if tpdu_bytes:
            out['tpdu'] = _decode_sm_tpdu(tpdu_bytes)
    return out


def _decode_plmn_list(raw, p1=None):
    entries = []
    for i in range(0, len(raw), 3):
        chunk = raw[i:i + 3]
        if len(chunk) < 3 or all(b == 0xff for b in chunk):
            break
        plmn = _decode_plmn(chunk)
        if plmn:
            entries.append(plmn)
    return {'plmns': entries}


def _decode_plmn_wact(raw, p1=None):
    """PLMN selector with Access Technology (TS 51.011 §10.3.35): 5-byte entries.

    Each entry: 3-byte PLMN + 2-byte access technology bitmask.
    """
    entries = []
    for i in range(0, len(raw) - 4, 5):
        chunk = raw[i:i + 5]
        if len(chunk) < 5:
            break
        plmn_bytes = chunk[:3]
        if all(b == 0xff for b in plmn_bytes):
            break
        plmn = _decode_plmn(plmn_bytes)
        if not plmn:
            continue
        act = (chunk[3] << 8) | chunk[4]
        techs = _decode_plmn_act(act)
        plmn['access_tech'] = ', '.join(techs) if techs else f'0x{act:04X}'
        entries.append(plmn)
    return {'plmns': entries}


def _decode_plmn_act(u16):
    """Decode the 2-byte access-technology field (TS 31.102 §4.2.5)."""
    techs = set()
    if u16 & 0x8000:
        techs.add('UTRAN')
    if u16 & 0x0800:
        techs.add('NG-RAN')
    if u16 & 0x0040:
        techs.add('GSM COMPACT')
    if u16 & 0x0020:
        techs.add('cdma2000 HRPD')
    if u16 & 0x0010:
        techs.add('cdma2000 1xRTT')
    e = u16 & 0x7000
    if e in (0x4000, 0x7000):
        techs.add('E-UTRAN WB-S1')
        techs.add('E-UTRAN NB-S1')
    elif e == 0x5000:
        techs.add('E-UTRAN NB-S1')
    elif e == 0x6000:
        techs.add('E-UTRAN WB-S1')
    g = u16 & 0x008C
    if g in (0x0080, 0x008C):
        techs.add('GSM')
        techs.add('EC-GSM-IoT')
    elif g == 0x0084:
        techs.add('GSM')
    elif g == 0x0086:
        techs.add('EC-GSM-IoT')
    return sorted(techs)


def _decode_dir(raw, p1=None):
    """EF_DIR record: application template(s) — AID (4F) + label (50)."""
    apps = []
    for tag, _length, value in parse_tlv(raw):
        if tag != 0x61:
            continue
        app = {}
        for t2, _l2, v2 in parse_tlv(value):
            if t2 == 0x4F:
                app['aid'] = v2.hex().upper()
            elif t2 == 0x50:
                label = _decode_annex_a(v2)
                if label:
                    app['label'] = label
        if app:
            apps.append(app)
    return {'applications': apps} if apps else {'raw': raw.hex().upper()}


def _decode_arr(raw, p1=None):
    entries = []
    for tag, _length, value in parse_tlv(raw):
        entries.append({'tag': f'0x{tag:02X}', 'hex': value.hex().upper()})
    return {'rules': entries} if entries else {'raw': raw.hex().upper()}


def _decode_pnn(raw, p1=None):
    names = {}
    for tag, _length, value in parse_tlv(raw):
        if tag == 0x43:
            names['full'] = _decode_annex_a(value)
        elif tag == 0x45:
            names['short'] = _decode_annex_a(value)
    if not names:
        txt = _decode_annex_a(raw.rstrip(b'\xff'))
        if txt:
            names['full'] = txt
    return names or {'raw': raw.hex().upper()}


def _decode_cbmi(raw, p1=None):
    ids = []
    for i in range(0, len(raw) - 1, 2):
        v = (raw[i] << 8) | raw[i + 1]
        if v == 0xffff:
            continue
        ids.append(v)
    return {'message_ids': ids}


def _decode_cbmir(raw, p1=None):
    if len(raw) >= 4:
        low = (raw[0] << 8) | raw[1]
        high = (raw[2] << 8) | raw[3]
        return {'range': [low, high]}
    return {'raw': raw.hex().upper()}


def _decode_ecc(raw, p1=None):
    txt = _decode_annex_a(raw.rstrip(b'\xff'))
    return {'number': txt} if txt else {'raw': raw.hex().upper()}


def _decode_spn(raw, p1=None):
    if len(raw) < 2:
        return {'raw': raw.hex().upper()}
    cond = raw[0]
    text = _decode_annex_a(raw[1:].rstrip(b'\xff'))
    out = {'display_condition': f'0x{cond:02X}'}
    if text:
        out['name'] = text
    return out


def _decode_loci(raw, p1=None):
    if len(raw) < 13:
        return {'raw': raw.hex().upper()}
    tmsi = raw[0:4]
    lai = raw[4:9]
    plmn = _decode_plmn(lai[:3]) or {}
    return {
        'tmsi': None if all(b == 0xff for b in tmsi) else tmsi.hex().upper(),
        'mcc': plmn.get('mcc'), 'mnc': plmn.get('mnc'),
        'lac': '0x' + lai[3:5].hex().upper(),
        'location_update_status': f'0x{raw[12]:02X}',
    }


def _decode_acc(raw, p1=None):
    if len(raw) < 2:
        return {'raw': raw.hex().upper()}
    val = (raw[0] << 8) | raw[1]
    classes = [i for i in range(16) if val & (0x8000 >> i)]
    return {'access_classes': classes}


def _decode_phase(raw, p1=None):
    v = raw[0] if raw else 0
    return {'phase': _PHASE_NAMES.get(v, f'0x{v:02X}')}


def _decode_nai(raw, p1=None):
    """ISIM identity files (EF_IMPI/DOMAIN/IMPU): BER-TLV tag 0x80 + ASCII value."""
    texts = []
    for tag, _length, value in parse_tlv(raw):
        if tag == 0x80:
            txt = value.decode('utf-8', 'replace').rstrip('\xff')
            if txt:
                texts.append(txt)
    if texts:
        return {'text': texts[0] if len(texts) == 1 else ', '.join(texts)}
    txt = raw.decode('ascii', 'replace').replace('\xff', '').strip()
    return {'text': txt} if txt else {'raw': raw.hex().upper()}


def _decode_hex(raw, p1=None):
    if not raw or all(b == 0xff for b in raw):
        return {'empty': True}
    return {'raw': raw.hex().upper()}


FILE_DECODERS = {
    '2fe2': _decode_iccid,
    '6f07': _decode_imsi,
    '6f05': _decode_li,
    '2f05': _decode_li,
    '6f3c': _decode_sms_rec,
    '6f38': lambda raw, p1=None: _decode_service_table(raw, UST_SERVICES),
    '6f30': _decode_plmn_list,
    '6f7b': _decode_plmn_list,
    '6f31': _decode_plmn_list,
    '6fd9': _decode_plmn_list,
    '6f60': _decode_plmn_wact,
    '6f61': _decode_plmn_wact,
    '6f62': _decode_plmn_wact,
    '2f00': _decode_dir,
    '6f40': _decode_adn,
    '6f49': _decode_adn,
    '6f3b': _decode_adn,
    '6f3a': _decode_adn,
    '6f4d': _decode_adn,
    '6fc7': _decode_adn,
    '6f80': _decode_adn,
    '6f81': _decode_adn,
    '6f45': _decode_cbmi,
    '6f50': _decode_cbmir,
    '2f06': _decode_arr,
    '6f06': _decode_arr,
    '6fc5': _decode_pnn,
    '6fb7': _decode_ecc,
    '6f46': _decode_spn,
    '6f7e': _decode_loci,
    '6f08': _decode_hex,
    '6f09': _decode_hex,
    '6f3e': _decode_hex,
    '6f3f': _decode_hex,
    '6fae': _decode_phase,
    '6f78': _decode_acc,
    '6fad': _decode_hex,
    '6f02': _decode_nai,
    '6f03': _decode_nai,
    '6f04': _decode_nai,
    '6fcb': _decode_hex,
    '6fc4': _decode_hex,
    '6fca': _decode_hex,
    '6fc9': _decode_hex,
}


def _decode_file_data(fid, raw, p1=None):
    """Decode file data using the FID's registered decoder."""
    if not raw:
        return None
    fn = FILE_DECODERS.get(fid)
    if not fn:
        return None
    try:
        out = fn(raw, p1=p1)
    except Exception:
        return None
    if not out:
        return None
    out['fid'] = fid
    out['ef'] = KNOWN_FIDS.get(fid, fid.upper())
    return out


def _file_summary(f):
    """Compact one-line summary of a decoded file body."""
    if f.get('empty'):
        return 'empty'
    if f.get('imsi'):
        return f"IMSI {f['imsi']}"
    if f.get('iccid'):
        return f"ICCID {f['iccid']}"
    if f.get('languages'):
        return 'languages ' + ' '.join(f['languages'])
    if 'number' in f and 'name' in f:
        return (f['name'] + ' ' + f['number']).strip()
    if f.get('number'):
        return f['number']
    if f.get('text'):
        return f['text']
    if f.get('name'):
        return f['name']
    if f.get('plmns'):
        return ', '.join(f"{p['mcc']}/{p['mnc']}" + (f" ({p['access_tech']})" if p.get('access_tech') else '')
                         for p in f['plmns'])
    if f.get('services'):
        return f"{len(f['services'])} services allocated"
    if f.get('applications'):
        return '; '.join((a.get('label') or a.get('aid') or '') for a in f['applications'])
    if f.get('tpdu'):
        t = f['tpdu']
        s = t.get('mti', '')
        if t.get('text'):
            s += f" \u00ab{t['text']}\u00bb"
        return f"SMS {s}".strip()
    if f.get('direction'):
        return f"SMS {f['direction']} — {f['status']}"
    if f.get('mcc'):
        return f"MCC {f['mcc']} MNC {f['mnc']} · LAC {f.get('lac', '')}"
    if f.get('access_classes') is not None:
        return 'classes ' + ', '.join(str(c) for c in f['access_classes'])
    if f.get('phase'):
        return f['phase']
    if f.get('range'):
        return f"range {f['range'][0]}-{f['range'][1]}"
    if f.get('message_ids') is not None:
        return f"{len(f['message_ids'])} message IDs"
    if f.get('record_numbers') is not None:
        nums = f['record_numbers']
        shown = ', '.join(str(n) for n in nums[:10])
        if len(nums) > 10:
            shown += ', \u2026'
        return f"{len(nums)} record(s): {shown}"
    return None


def _fcp_summary(response_for, fd, response):
    """Build a summary for a GET RESPONSE (FCP) following SELECT."""
    ft = fd.get('file_type') or ''
    label = f"response for {response_for}, {ft}"
    if ft == 'DF or ADF':
        name = response.get('file_id_name')
        if name:
            label += f" ({name})"
    else:
        struct = fd.get('structure') or ''
        if struct:
            label += f", {struct}"
        nrec = fd.get('num_records')
        rlen = fd.get('record_length')
        fsize = response.get('file_size') or response.get('total_file_size')
        if nrec and rlen:
            label += f", {nrec} rec \u00d7 {rlen} B"
        elif fsize:
            label += f", {fsize} B"
    return label


def _build_summary(result):
    """Build a concise human-readable description of a decoded command.

    Used to replace raw hex in the APDU list view.  Returns None when
    nothing meaningful is extractable (caller falls back to raw hex).
    Sensitive bodies (PIN, AUTH) are never included.
    """
    parts = []
    ins = result.get('ins_hex')

    p1 = result.get('p1')
    p2 = result.get('p2')
    p1txt = p2txt = None
    if 'p1p2' in result:
        p1txt = f"{result['p1p2']['label']}: 0x{result['p1p2']['value']:04X}"
    else:
        if p1:
            p1txt = p1.get('name')
            if not p1txt and p1.get('label') is not None and p1.get('value') is not None:
                p1txt = f"{p1['label']}: {p1['value']}"
            if not p1txt and p1.get('bits'):
                p1txt = ', '.join(p1['bits'])
        if p2:
            p2txt = p2.get('name')
            if not p2txt and p2.get('bits'):
                p2txt = ', '.join(p2['bits'])

    body = result.get('body')
    bodytxt = None
    if body and ins == 'a4':  # SELECT → FID/AID is the object of the command
        bodytxt = body['hex'].upper()
        if body.get('note'):
            bodytxt = f"{bodytxt} ({body['note']})"

    if ins == 'a4' and p1txt and bodytxt:
        parts.append(f"{p1txt}: {bodytxt}")
        if p2txt and p2txt != 'No indication':
            parts.append(p2txt)
    else:
        if p1txt and p1txt != 'No indication':
            parts.append(p1txt)
        if p2txt and p2txt != 'No indication':
            parts.append(p2txt)
        if bodytxt:
            parts.append(bodytxt)

    cmd = result.get('cmd')
    if cmd:
        if cmd.get('context'):
            parts.append(cmd['context'])
        if cmd.get('title'):
            parts.append(cmd['title'])
        items = cmd.get('items')
        if items:
            n = len(items)
            parts.append(f"{n} item{'s' if n != 1 else ''}")
        if cmd.get('text'):
            parts.append(cmd['text'])
        if cmd.get('smsc'):
            parts.append(f"SMSC {cmd['smsc']}")
        if cmd.get('events'):
            parts.append(', '.join(cmd['events']))
        if cmd.get('address'):
            parts.append(f"to {cmd['address']}")
        duration = cmd.get('duration')
        if isinstance(duration, dict) and duration.get('value') is not None:
            parts.append(f"{duration['value']} {duration['unit']}")
        tpdu = cmd.get('tpdu')
        if tpdu:
            s = tpdu.get('mti', '')
            if tpdu.get('oa'):
                s += f" from {tpdu['oa']}"
            if tpdu.get('da'):
                s += f" to {tpdu['da']}"
            if tpdu.get('text'):
                s += f" \u00ab{tpdu['text']}\u00bb"
            parts.append(s)

    if result.get('response_to'):
        parts.append('\u2192 ' + result['response_to'])
    if result.get('response_for'):
        response = result.get('response') or {}
        fd = response.get('file_descriptor')
        if fd:
            parts.append(_fcp_summary(result['response_for'], fd, response))
        else:
            parts.append('response for ' + result['response_for'])
    response = result.get('response')
    if response and response.get('name'):
        parts.append(response['name'])

    file_dec = result.get('file')
    if file_dec:
        txt = _file_summary(file_dec)
        if txt:
            parts.append(f"{file_dec.get('ef', '')} {txt}".strip())

    return ', '.join(parts) if parts else None


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

        if ins == 0xA4 and p1 in (0x08, 0x09):  # SELECT by path (from MF / current DF)
            result['body']['note'] = _decode_select_path(body.hex())

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

        # File data decode for READ/UPDATE using the current selection.
        if ins in (0xB0, 0xB2, 0xD6, 0xDC) and prev and prev.get('sel'):
            offset = (result.get('p1p2') or {}).get('value', 0)
            if ins in (0xB2, 0xDC) or offset == 0:
                file_dec = _decode_file_data(prev['sel']['fid'], body, p1=p1)
                if file_dec:
                    result['file'] = file_dec

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
                if prev_ins in (0xB0, 0xB2) and prev.get('sel') and prev.get('file_ok'):
                    file_dec = _decode_file_data(prev['sel']['fid'], remaining[:cmd_body_len])
                    if file_dec:
                        result['file'] = file_dec
                elif prev_ins == 0xA2 and prev.get('sel') and prev.get('file_ok'):
                    # SEARCH RECORD → list of matching record numbers
                    fid = prev['sel']['fid']
                    result['file'] = {
                        'fid': fid,
                        'ef': KNOWN_FIDS.get(fid, fid.upper()),
                        'record_numbers': list(remaining[:cmd_body_len]),
                    }
                else:
                    response = _decode_response_for(prev_ins, remaining[:cmd_body_len])
                    if response:
                        result['response'] = response
        else:
            result['response_for'] = None

    result['summary'] = _build_summary(result)

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


# ──────────────────── ATR / PPS decoding (ISO 7816-3) ────────────────────

# TA1/PPS1: Fi (clock rate conversion factor), f(max), Di (baud rate adjustment)
_ATR_FI = {0: 372, 1: 372, 2: 558, 3: 744, 4: 1116, 5: 1488, 6: 1860,
           9: 512, 10: 768, 11: 1024, 12: 1536, 13: 2048}
_ATR_FMAX = {0: 4, 1: 5, 2: 6, 3: 8, 4: 12, 5: 16, 6: 20,
             9: 5, 10: 7.5, 11: 10, 12: 15, 13: 20}
_ATR_DI = {1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 12, 9: 20}

_T_PROTOCOLS = {0: 'T=0', 1: 'T=1', 2: 'T=2', 3: 'T=3', 4: 'T=4', 14: 'T=14', 15: 'T=15'}

# TA3 (first TA for T=15): clock stop indicator (bits 8-7) + class indicator (bits 1-3)
_CLOCK_STOP = {0: 'clock stop not supported', 1: 'state L preferred',
               2: 'state H preferred', 3: 'no preference'}
_CLASS_BITS = {0x01: 'A', 0x02: 'B', 0x04: 'C'}


def _bit_swap(b):
    """Reverse the bits of a byte (inverse convention ATR decoding)."""
    return int(f'{b:08b}'[::-1], 2)


def _fidi_dict(fi, di):
    """Decode an Fi/Di nibble pair into a display dict."""
    entry = {'fi': fi, 'di': di}
    f = _ATR_FI.get(fi)
    d = _ATR_DI.get(di)
    if f is not None:
        entry['f'] = f
    if d is not None:
        entry['d'] = d
    if f is not None and d is not None:
        f_div_d = f / d
        entry['f_div_d'] = int(f_div_d) if f_div_d == int(f_div_d) else f_div_d
    if fi in _ATR_FMAX:
        entry['f_max'] = _ATR_FMAX[fi]
    return entry


def _decode_historical(hist):
    """Decode ATR historical bytes (ISO 7816-4 §8.1.1)."""
    result = {'raw': hist.hex().upper()}
    cat = hist[0]
    if cat == 0x80 and len(hist) >= 3:
        result['category'] = 'status information (life cycle)'
        result['sw'] = f'{hist[1]:02X}{hist[2]:02X}'
        life_cycle = _LIFE_CYCLE.get(hist[2])
        if life_cycle:
            result['life_cycle'] = life_cycle
    elif cat == 0x8F:
        result['category'] = 'TLV list'
    elif 0x00 <= cat <= 0x7F or 0x90 <= cat <= 0x9F:
        result['category'] = 'proprietary'
    elif 0x81 <= cat <= 0x8E or 0xA0 <= cat <= 0xFE:
        result['category'] = 'reserved'
    elif cat == 0xFF:
        result['category'] = 'default'
    else:
        result['category'] = f'0x{cat:02X}'
    return result


def _decode_atr(data):
    """Decode an Answer-To-Reset (ISO 7816-3 §8) into a structured dict."""
    if not data:
        return {'type': 'atr', 'raw': ''}
    ts = data[0]
    raw = data.hex().upper()
    if ts not in (0x3B, 0x3F):
        return {'type': 'atr', 'convention': 'unknown', 'raw': raw}
    inverse = ts == 0x3F
    body = data[1:]
    if inverse:
        body = bytes(_bit_swap(b) for b in body)

    result = {
        'type': 'atr',
        'ts': f'{ts:02X}',
        'convention': 'inverse' if inverse else 'direct',
        'raw': raw,
    }
    if not body:
        return result

    t0 = body[0]
    result['t0'] = f'{t0:02X}'
    result['historical_len'] = t0 & 0x0F

    interface = []
    protocols = []
    flags = t0 & 0xF0
    i = 1
    level = 1
    cur_t = None  # protocol T governing the TA/TB/TC bytes at this level (None = global)

    while flags and i < len(body):
        if flags & 0x10:  # TA
            b = body[i]
            i += 1
            if level == 1:
                entry = {'name': 'TA1', 'hex': f'{b:02X}'}
                entry.update(_fidi_dict(b >> 4, b & 0x0F))
            elif level == 2:
                entry = {'name': 'TA2', 'hex': f'{b:02X}',
                         'specific': bool(b & 0x10),
                         'protocol': _T_PROTOCOLS.get(b & 0x0F, f'T={b & 0x0F}')}
            elif cur_t == 15:  # first TA for T=15 → clock stop + class indicator
                classes = [name for bit, name in _CLASS_BITS.items() if b & bit]
                entry = {'name': f'TA{level}', 'hex': f'{b:02X}',
                         'clock_stop': _CLOCK_STOP.get((b >> 6) & 0x03),
                         'classes': classes}
            else:  # TA3 for T=1 → IFSC
                entry = {'name': f'TA{level}', 'hex': f'{b:02X}', 'ifsc': b}
            interface.append(entry)
        if flags & 0x20:  # TB
            b = body[i]
            i += 1
            if level == 1:
                interface.append({'name': 'TB1', 'hex': f'{b:02X}',
                                  'programming': 'not used' if b == 0 else f'0x{b:02X}'})
            elif level == 2:
                interface.append({'name': 'TB2', 'hex': f'{b:02X}',
                                  'programming': 'not used' if b == 0 else f'0x{b:02X}'})
            elif cur_t == 15:  # first TB for T=15 → SPU
                interface.append({'name': f'TB{level}', 'hex': f'{b:02X}',
                                  'spu': 'not used' if b == 0 else f'0x{b:02X}'})
            else:  # TB3 for T=1 → BWI/CWI
                interface.append({'name': f'TB{level}', 'hex': f'{b:02X}',
                                  'bwi': b >> 4, 'cwi': b & 0x0F})
        if flags & 0x40:  # TC
            b = body[i]
            i += 1
            if level == 1:
                interface.append({'name': 'TC1', 'hex': f'{b:02X}', 'extra_guard_time': b})
            elif level == 2:
                interface.append({'name': 'TC2', 'hex': f'{b:02X}', 'work_waiting_time': b})
            else:
                interface.append({'name': f'TC{level}', 'hex': f'{b:02X}'})
        if flags & 0x80:  # TD
            b = body[i]
            i += 1
            cur_t = b & 0x0F
            protocols.append(_T_PROTOCOLS.get(cur_t, f'T={cur_t}'))
            flags = b & 0xF0
            level += 1
        else:
            flags = 0

    if interface:
        result['interface'] = interface
    if protocols:
        result['protocols'] = protocols

    k = result['historical_len']
    if k and i + k <= len(body):
        result['historical'] = _decode_historical(body[i:i + k])
    i += k

    # TCK present unless only T=0 is proposed (ISO 7816-3 §8.2.5).
    only_t0 = not protocols or protocols == ['T=0']
    if not only_t0 and i < len(body):
        tck = body[i]
        check = 0
        for b in body[:i]:
            check ^= b
        result['tck'] = f'{tck:02X}'
        result['tck_valid'] = check == tck

    return result


def _decode_pps(data):
    """Decode a Protocol and Parameter Selection exchange (ISO 7816-3 §9.2)."""
    if not data:
        return {'type': 'pps', 'raw': ''}
    raw = data.hex().upper()
    result = {'type': 'pps', 'raw': raw}
    if data[0] != 0xFF:
        result['note'] = 'missing PPSS'
        return result
    result['ppss'] = 'FF'
    if len(data) < 2:
        return result
    pps0 = data[1]
    result['pps0'] = f'{pps0:02X}'
    result['protocol'] = _T_PROTOCOLS.get(pps0 & 0x0F, f'T={pps0 & 0x0F}')
    i = 2
    if pps0 & 0x10 and i < len(data):  # PPS1 → Fi/Di
        pps1 = data[i]
        i += 1
        entry = {'pps1': f'{pps1:02X}'}
        entry.update(_fidi_dict(pps1 >> 4, pps1 & 0x0F))
        result['fi_di'] = entry
    if pps0 & 0x20 and i < len(data):  # PPS2 → SPU
        pps2 = data[i]
        i += 1
        result['pps2'] = f'{pps2:02X}'
        result['spu'] = 'not used' if pps2 == 0 else f'0x{pps2:02X}'
    if pps0 & 0x40 and i < len(data):  # PPS3 (reserved)
        result['pps3'] = f'{data[i]:02X}'
        i += 1
    if i < len(data):
        pck = data[i]
        check = 0
        for b in data[:i]:
            check ^= b
        result['pck'] = f'{pck:02X}'
        result['pck_valid'] = check == pck
    return result


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
        return _decode_atr(raw_data)
    if msg_type == 'pps':
        return _decode_pps(raw_data)
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
