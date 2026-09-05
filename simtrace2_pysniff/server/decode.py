"""APDU/TPDU decoding — CLA, INS, P1/P2, body, and status word.

Pure Python, no dependencies.  Decodes raw TPDU bytes captured by
the SIMtrace2 sniffer into structured dicts for the PWA to display.
"""

from ..gsmtap import GSMTAP_FLAG_BAD_FCS

# ──────────────────── Status Word names ────────────────────

SW_NAMES = {
    (0x90, 0x00): 'Normal ending',
    (0x61, 0x00): 'Response data available',
    (0x62, 0x00): 'Warning — no information',
    (0x62, 0x81): 'Warning — part of data may be corrupted',
    (0x62, 0x82): 'Warning — EOF reached before reading Le bytes',
    (0x62, 0x83): 'Warning — selected file deactivated',
    (0x62, 0x84): 'Warning — FCI not formatted per ISO',
    (0x62, 0x85): 'Warning — selected file in termination state',
    (0x62, 0xf1): 'More data available',
    (0x62, 0xf2): 'More data available and proactive command pending',
    (0x62, 0xf3): 'Response data available',
    (0x63, 0x00): 'Warning — no information',
    (0x63, 0xf1): 'More data expected',
    (0x63, 0xf2): 'More data expected and proactive command pending',
    (0x64, 0x00): 'Execution error — no information',
    (0x64, 0x01): 'Execution error — immediate response required',
    (0x65, 0x00): 'Execution error — no information, NV memory changed',
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
    (0x69, 0x89): 'Command not allowed — secure channel security not satisfied',
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
    (0x93, 0x00): 'SIM Application Toolkit busy',
    (0x98, 0x50): 'INCREASE cannot be performed, max value reached',
    (0x98, 0x62): 'Authentication error, application specific',
    (0x98, 0x63): 'Security session or association expired',
    (0x98, 0x64): 'Minimum UICC suspension time too long',
}


def _sw_name(sw1, sw2):
    key = (sw1, sw2)
    return SW_NAMES.get(key)

# pattern match: 91xx, 63cx, etc.
_SW_PATTERNS = [
    ((0x91,), lambda s1, s2: 'Proactive command pending (%d bytes)' % s2),
    ((0x92,), lambda s1, s2: 'Normal ending, TRANSACT DATA info (0x%02X)' % s2),
    ((0x61,), lambda s1, s2: 'Response: %d bytes available (use GET RESPONSE)' % s2),
    ((0x63,), lambda s1, s2: ('Verification failed, %d retries remaining' % (s2 & 0x0f)
                              if s2 & 0xc0 == 0xc0 else None)),
    ((0x6c,), lambda s1, s2: 'Wrong length (Le): correct length is 0x%02X (%d bytes)' % (s2, s2)),
    ((0x9e,), lambda s1, s2: 'Normal processing, %d bytes of response' % s2),
    ((0x9f,), lambda s1, s2: 'Normal processing, %d bytes of response' % s2),
]


def decode_sw(raw_sw):
    if len(raw_sw) < 2:
        return None
    sw1, sw2 = raw_sw[-2], raw_sw[-1]
    name = _sw_name(sw1, sw2)
    if name is None:
        for keys, fn in _SW_PATTERNS:
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
    if cla == 0x80:
        interclass = 'ETSI-defined (UICC/USIM)'
    elif cla == 0xa0:
        interclass = 'ETSI-defined (SIM/GSM)'
    elif cla & 0x80:
        interclass = 'proprietary'
    elif (cla >> 6) & 0x03 == 0x00:
        interclass = 'inter-industry (ISO 7816-4)'
    elif (cla >> 6) & 0x03 == 0x01:
        interclass = 'inter-industry (further format)'
    else:
        interclass = 'reserved'
    if cla & 0x80:
        # proprietary / ETSI-defined: no standard SM/chaining/channel coding
        result = {
            'hex': f'{cla:02x}',
            'interclass': interclass,
            'channel': cla & 0x03,
            'secure_messaging': 'none',
            'chain': 'last or only',
        }
    else:
        # ISO 7816-4 §5.1.1 first/further interindustry
        chain_bit = (cla >> 5) & 0x01
        chain_names = {0: 'last or only', 1: 'first or continuing'}
        sm_names = {0: 'none', 1: 'proprietary', 2: 'SM header not authenticated',
                    3: 'SM header authenticated'}
        sm_ind = (cla >> 3) & 0x03
        channel = cla & 0x03
        if (cla >> 6) & 0x03 == 0x01:
            channel += 4  # further format: b4-b1 = channel + 4
        result = {
            'hex': f'{cla:02x}',
            'interclass': interclass,
            'channel': channel,
            'secure_messaging': sm_names.get(sm_ind, 'none'),
            'chain': chain_names.get(chain_bit, 'last or only'),
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
    '2f07': 'EF_ENV-CLASSES',
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


# Short File Identifier (SFI) → FID, scoped to the containing DF.
# SFI is only unique within a DF (TS 102 221 §8.3).  Sourced from the
# normative SFI lists: TS 31.102 Annex H (USIM ADF, DF GSM-ACCESS) and
# TS 102 221 Annex H (MF level).
_SFI_BY_DF = {
    '3f00': {   # MF (TS 102 221 Annex H)
        0x02: '2fe2',   # EF_ICCID
        0x05: '2f05',   # EF_PL
        0x06: '2f06',   # EF_ARR
        0x07: '2f07',   # EF_ENV-CLASSES (TS 102 671)
        0x08: '2f08',   # EF_UMPC
        0x1e: '2f00',   # EF_DIR
    },
    '7fff': {   # ADF_USIM (TS 31.102 Annex H H.1)
        0x01: '6fb7',   # EF_ECC
        0x02: '6f05',   # EF_LI
        0x03: '6fad',   # EF_AD
        0x04: '6f38',   # EF_UST
        0x05: '6f56',   # EF_EST
        0x06: '6f78',   # EF_ACC
        0x07: '6f07',   # EF_IMSI
        0x08: '6f08',   # EF_Keys
        0x09: '6f09',   # EF_KeysPS
        0x0a: '6f60',   # EF_PLMNwAcT
        0x0b: '6f7e',   # EF_LOCI
        0x0c: '6f73',   # EF_PSLOCI
        0x0d: '6f7b',   # EF_FPLMN
        0x0e: '6f48',   # EF_CBMID
        0x0f: '6f5b',   # EF_START-HFN
        0x10: '6f5c',   # EF_THRESHOLD
        0x11: '6f61',   # EF_OPLMNwAcT
        0x12: '6f31',   # EF_HPPLMN
        0x13: '6f62',   # EF_HPLMNwAcT
        0x14: '6f80',   # EF_ICI
        0x15: '6f81',   # EF_OCI
        0x16: '6f4f',   # EF_CCP2
        0x17: '6f06',   # EF_ARR
        0x18: '6fe4',   # EF_EPSNSC
        0x19: '6fc5',   # EF_PNN
        0x1a: '6fc6',   # EF_OPL
        0x1b: '6fcd',   # EF_SPDI
        0x1c: '6f39',   # EF_ACM
        0x1d: '6fd9',   # EF_EHPLMN
        0x1e: '6fe3',   # EF_EPSLOCI
    },
    '5f3b': {   # DF_GSM_ACCESS (TS 31.102 Annex H H.2)
        0x01: '4f20',   # EF_Kc
        0x02: '4f52',   # EF_KcGPRS
    },
}


def _is_df_fid(fid):
    """True if *fid* (2-hex-byte string) denotes a DF/ADF (MF, 7Fxx, 5Fxx)."""
    return fid == '3f00' or fid.startswith('7f') or fid.startswith('5f')


def selected_df_fid(d):
    """Return the current DF after a SELECT, or None if the SELECT does not
    (re)enter a DF.  Handles SELECT by FID (P1 00/01), by path (P1 08/09),
    and by DF name/AID (P1 04)."""
    if d.get('ins_hex') != 'a4':
        return None
    p1 = (d.get('p1') or {}).get('raw')
    h = (d.get('body') or {}).get('hex') or ''
    if p1 in ('00', '01'):
        return h if len(h) == 4 and _is_df_fid(h) else None
    if p1 in ('08', '09'):
        comps = [h[i:i + 4] for i in range(0, len(h) - 3, 4)]
        for comp in reversed(comps):
            if _is_df_fid(comp):
                return comp
        return None
    if p1 == '04':  # select by DF name (AID) → map known application AIDs
        if h.startswith('a0000000871002'):   # USIM AID
            return '7fff'
        return None
    return None


def sfi_table(df):
    """Return the SFI→FID table for a DF FID, or an empty dict."""
    return _SFI_BY_DF.get(df or '', {})


# ──────────────────── Per-INS specifications ────────────────────

# TS 102 221 Table 9.3 — PIN mapping into key references (P2 of the PIN commands)
PIN_KEY_REFS = {
    0x01: 'PIN Appl 1', 0x02: 'PIN Appl 2', 0x03: 'PIN Appl 3', 0x04: 'PIN Appl 4',
    0x05: 'PIN Appl 5', 0x06: 'PIN Appl 6', 0x07: 'PIN Appl 7', 0x08: 'PIN Appl 8',
    0x0A: 'ADM1', 0x0B: 'ADM2', 0x0C: 'ADM3', 0x0D: 'ADM4', 0x0E: 'ADM5',
    0x11: 'Universal PIN',
    0x81: 'Second PIN Appl 1', 0x82: 'Second PIN Appl 2', 0x83: 'Second PIN Appl 3',
    0x84: 'Second PIN Appl 4', 0x85: 'Second PIN Appl 5', 0x86: 'Second PIN Appl 6',
    0x87: 'Second PIN Appl 7', 0x88: 'Second PIN Appl 8',
}

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
        'le': True,
        'p1p2': {'fmt': 'uint16be', 'label': 'Offset'},
        'body': None,
    },
    0xB2: {
        'name': 'READ RECORD',
        'le': True,
        'p1': {'fmt': 'uint8', 'label': 'Record number'},
        'p2': {
            'label': 'Mode',
            'bits': {
                0x02: 'next record',
                0x03: 'previous record',
                0x04: 'absolute mode (record number in P1)',
            },
        },
        'body': None,
    },
    0xB1: {
        'name': 'READ RECORD (B1)',
        'le': True,
        'p1': {'fmt': 'uint8', 'label': 'Record number'},
        'p2': {
            'label': 'Mode',
            'bits': {
                0x02: 'next record',
                0x03: 'previous record',
                0x04: 'absolute mode (record number in P1)',
            },
        },
        'body': None,
    },
    0xD6: {
        'name': 'UPDATE BINARY',
        'p1p2': {'fmt': 'uint16be', 'label': 'Offset'},
        'body': {'label': 'Data'},
    },
    0xD7: {
        'name': 'UPDATE BINARY (odd INS)',
        'p1p2': {'fmt': 'uint16be', 'label': 'Offset'},
        'body': {'label': 'BER-TLV data'},
    },
    0xDD: {
        'name': 'UPDATE RECORD (odd INS)',
        'p1': {'fmt': 'uint8', 'label': 'Record number'},
        'p2': {
            'label': 'Mode',
            'bits': {
                0x02: 'next record',
                0x03: 'previous record',
                0x04: 'absolute mode (record number in P1)',
            },
        },
        'body': {'label': 'BER-TLV data'},
    },
    0xD2: {
        'name': 'WRITE RECORD',
        'p1': {'fmt': 'uint8', 'label': 'Record number'},
        'p2': {
            'label': 'Mode',
            'bits': {
                0x02: 'next record',
                0x03: 'previous record',
                0x04: 'absolute mode (record number in P1)',
            },
        },
        'body': {'label': 'Data'},
    },
    0xDC: {
        'name': 'UPDATE RECORD',
        'p1': {'fmt': 'uint8', 'label': 'Record number'},
        'p2': {
            'label': 'Mode',
            'bits': {
                0x02: 'next record',
                0x03: 'previous record',
                0x04: 'absolute mode (record number in P1)',
            },
        },
        'body': {'label': 'Data'},
    },
    0x20: {
        'name': 'VERIFY PIN',
        'p1': {0x00: 'No indication'},
        'p2': PIN_KEY_REFS,
        'body': {'label': 'PIN value'},
    },
    0x21: {
        'name': 'VERIFY',
        'p1p2': {'unused': True},
        'body': {'label': 'Data'},
    },
    0x24: {
        'name': 'CHANGE PIN',
        'p1': {0x00: 'No indication'},
        'p2': PIN_KEY_REFS,
        'body': {'label': 'Old+new PIN'},
    },
    0x26: {
        'name': 'DISABLE PIN',
        'p1': {0x00: 'No indication'},
        'p2': PIN_KEY_REFS,
        'body': {'label': 'PIN value'},
    },
    0x28: {
        'name': 'ENABLE PIN',
        'p1': {0x00: 'No indication'},
        'p2': PIN_KEY_REFS,
        'body': {'label': 'PIN value'},
    },
    0x2C: {
        'name': 'UNBLOCK PIN',
        'p1': {0x00: 'No indication'},
        'p2': PIN_KEY_REFS,
        'body': {'label': 'PUK + new PIN'},
    },
    0x88: {
        'name': 'AUTHENTICATE',
        'p1': {0x00: 'No indication'},
        'p2': {'label': 'Auth context', 'bits': {
            0x00: 'GSM context',
            0x01: '3G/EPS/5G context',
            0x02: 'VGCS/VBS context',
            0x04: 'GBA context',
            0x80: 'Specific reference data',
        }},
        'body': {'label': 'Challenge/session key'},
    },
    0x89: {
        'name': 'AUTHENTICATE',
        'body': {'label': 'Response/resynchronisation data'},
    },
    0x82: {
        'name': 'EXTERNAL AUTHENTICATE',
        'p1': {'label': 'Security level'},
        'p2': {0x00: 'No indication'},
        'body': {'label': 'Cryptogram'},
    },
    0x86: {
        'name': 'GENERAL AUTHENTICATE',
        'p1p2': {'unused': True},
        'body': {'label': 'Auth data'},
    },
    0x87: {
        'name': 'GENERAL AUTHENTICATE (odd INS)',
        'p1p2': {'unused': True},
        'body': {'label': 'BER-TLV auth data'},
    },
    0x22: {
        'name': 'MANAGE SECURITY ENVIRONMENT',
        'p1': {0x00: 'No indication', 0x01: 'Set', 0x02: 'Verify', 0x03: 'Restore', 0xF3: 'Erase'},
        'p2': {'label': 'SE reference'},
        'body': {'label': 'SE parameters'},
    },
    0x84: {
        'name': 'GET CHALLENGE',
        'le': True,
        'p1p2': {'unused': True},
        'body': None,
    },
    0x70: {
        'name': 'MANAGE CHANNEL',
        'p1': {0x00: 'Open channel', 0x80: 'Close channel'},
        'p2': {0x00: 'Auto-assign channel', **{n: f'Channel {n}' for n in range(1, 20)}},
        'body': None,
    },
    0xC0: {
        'name': 'GET RESPONSE',
        'le': True,
        'p1p2': {'unused': True},
        'body': None,
    },
    0xC2: {
        'name': 'ENVELOPE',
        'p1p2': {'unused': True},
        'body': {'label': 'TLV data'},
    },
    0x12: {
        'name': 'FETCH',
        'le': True,
        'p1p2': {'unused': True},
        'body': None,
    },
    0x14: {
        'name': 'TERMINAL RESPONSE',
        'p1p2': {'unused': True},
        'body': {'label': 'TLV data'},
    },
    0x32: {
        'name': 'INCREASE',
        'p1p2': {'unused': True},
        'body': {'label': 'Data'},
    },
    0x04: {
        'name': 'DEACTIVATE FILE',
        'p1': {0x00: 'EF by file ID', 0x08: 'Path from MF', 0x09: 'Path from current DF'},
        'p2': {0x00: 'No indication'},
        'body': {'label': 'File ID/path'},
    },
    0x44: {
        'name': 'ACTIVATE FILE',
        'p1': {0x00: 'EF by file ID', 0x08: 'Path from MF', 0x09: 'Path from current DF'},
        'p2': {0x00: 'No indication'},
        'body': {'label': 'File ID/path'},
    },
    0x0E: {
        'name': 'ERASE BINARY',
        'p1p2': {'fmt': 'uint16be', 'label': 'Offset'},
        'body': {'label': 'Erase data'},
    },
    0x0C: {
        'name': 'ERASE RECORDS',
        'p1': {'fmt': 'uint8', 'label': 'Record number'},
        'p2': {
            'label': 'Mode',
            'bits': {
                0x02: 'next record',
                0x03: 'previous record',
                0x04: 'absolute mode (record number in P1)',
            },
        },
        'body': None,
    },
    0x7C: {
        'name': 'MANAGE LSI',
        'p1p2': {'unused': True},
        'body': {'label': 'LSI parameters'},
    },
    0xF2: {
        'name': 'STATUS',
        'le': True,
        'p1': {0x00: 'No indication', 0x01: 'Current DF', 0x02: 'EF under current DF',
               0x04: 'DF name', 0x0d: 'Applet status'},
        'p2': {0x00: 'No indication'},
        'body': None,
    },
    0xE0: {
        'name': 'CREATE FILE',
        'p1p2': {'unused': True},
        'body': {'label': 'TLV data'},
    },
    0xE4: {
        'name': 'DELETE FILE',
        'p1': {0x00: 'Delete EF/DF', 0x0c: 'Delete EF', 0x0d: 'Delete DF'},
        'p2': {0x00: 'No indication'},
        'body': None,
    },
    0xAA: {
        'name': 'TERMINAL CAPABILITY',
        'p1p2': {'unused': True},
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
        'p1p2': {'unused': True},
        'body': {'label': 'TLV data'},
    },
    0xA2: {
        'name': 'SEARCH RECORD',
        'p1': {'fmt': 'uint8', 'label': 'Record number'},
        'p2': {
            'label': 'Mode',
            'bits': {
                0x04: 'Simple search (forward)',
                0x05: 'Simple search (backward)',
                0x06: 'Enhanced search',
                0x07: 'Proprietary search',
            },
        },
        'body': {'label': 'Search pattern'},
    },
    0xCB: {
        'name': 'RETRIEVE DATA',
        'le': True,
        'p1': {0x00: 'No indication'},
        'p2': {'label': 'Mode', 'bits': {
            0x80: 'First block',
            0x40: 'Retransmit previous block',
        }},
        'body': {'label': 'TLV data'},
    },
    0xDB: {
        'name': 'SET DATA',
        'p1': {0x00: 'No indication'},
        'p2': {'label': 'Mode', 'bits': {
            0x80: 'First block',
            0x40: 'Retransmit previous block',
        }},
        'body': {'label': 'TLV data'},
    },
    0x10: {
        'name': 'TERMINAL PROFILE',
        'p1p2': {'unused': True},
        'body': {'label': 'TLV data'},
    },
    0x76: {
        'name': 'SUSPEND UICC',
        'p1p2': {'unused': True},
        'body': None,
    },
    0xCA: {
        'name': 'GET DATA',
        'le': True,
        'p1p2': {'fmt': 'uint16be', 'label': 'Tag'},
        'body': {'label': 'TLV data'},
    },
    0xDA: {
        'name': 'PUT DATA',
        'p1p2': {'fmt': 'uint16be', 'label': 'Tag'},
        'body': {'label': 'TLV data'},
    },
    0xE2: {
        'name': 'STORE DATA',
        'p1p2': {'unused': True},
        'body': {'label': 'TLV data'},
    },
    0xD0: {
        'name': 'WRITE BINARY',
        'p1p2': {'fmt': 'uint16be', 'label': 'Offset'},
        'body': {'label': 'Data'},
    },
    0xD1: {
        'name': 'WRITE BINARY (odd INS)',
        'p1p2': {'fmt': 'uint16be', 'label': 'Offset'},
        'body': {'label': 'BER-TLV data'},
    },
    0xA0: {
        'name': 'SEARCH BINARY',
        'p1p2': {'fmt': 'uint16be', 'label': 'Offset'},
        'body': {'label': 'Search parameters'},
    },
    0xB3: {
        'name': 'READ RECORD (odd INS)',
        'le': True,
        'p1': {'fmt': 'uint8', 'label': 'Record number'},
        'p2': {
            'label': 'Mode',
            'bits': {
                0x02: 'next record',
                0x03: 'previous record',
                0x04: 'absolute mode (record number in P1)',
            },
        },
    },
    0xC3: {
        'name': 'ENVELOPE (odd INS)',
        'body': {'label': 'BER-TLV data'},
    },
    0x7A: {
        'name': 'EXCHANGE CAPABILITIES',
        'p1p2': {'unused': True},
        'body': {'label': 'Capability list'},
    },
    0xD4: {
        'name': 'RESIZE FILE',
        'p1p2': {'unused': True},
        'body': {'label': 'BER-TLV data'},
    },
    0x0F: {
        'name': 'ERASE BINARY (odd INS)',
        'p1p2': {'fmt': 'uint16be', 'label': 'Offset'},
        'body': {'label': 'BER-TLV data'},
    },
    0x2A: {
        'name': 'PERFORM SECURITY OPERATION',
        'p1': {'label': 'Operation'},
        'p2': {'label': 'Operation'},
        'body': {'label': 'Command data'},
    },
    0x46: {
        'name': 'GENERATE ASYMMETRIC KEY PAIR',
        'p1': {0x00: 'new key', 0x80: 'generate/derive', 0x81: 'read public key'},
        'p2': {0x00: 'No indication'},
        'body': {'label': 'BER-TLV data'},
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
    0x79: 'LSI COMMAND',
    0x81: 'END OF PROACTIVE SESSION',
}

# TS 102 223 §8.6 — REFRESH command qualifier (mode)
REFRESH_MODES = {
    0x00: 'NAA Initialization and Full File Change Notification',
    0x01: 'File Change Notification',
    0x02: 'NAA Initialization and File Change Notification',
    0x03: 'NAA Initialization',
    0x04: 'UICC Reset',
    0x05: 'NAA Application Reset',
    0x06: 'NAA Session Reset',
    0x07: 'Reserved (Steering of Roaming)',
    0x08: 'Reserved (Steering of Roaming for I-WLAN)',
    0x09: 'eUICC Profile State Change',
    0x0A: 'Application Update',
}

ENVELOPE_TYPES = {
    0xD1: 'SMS-PP DOWNLOAD',
    0xD2: 'CELL BROADCAST DOWNLOAD',
    0xD3: 'MENU SELECTION',
    0xD4: 'CALL CONTROL',
    0xD5: 'MO SHORT MESSAGE CONTROL',
    0xD6: 'EVENT DOWNLOAD',
    0xD7: 'TIMER EXPIRATION',
    # TS 101 220 table 7.17 + TS 31.111 §9.1
    0xD9: 'USSD DOWNLOAD',
    0xDA: 'MMS TRANSFER STATUS',
    0xDB: 'MMS NOTIFICATION',
    0xDC: 'TERMINAL APPLICATIONS',
    0xDD: 'GEOGRAPHICAL LOCATION REPORTING',
    0xDE: 'ENVELOPE CONTAINER',
    0xDF: 'PROSE REPORT',
    0xE0: '5G PROSE REPORT',
    0xE1: 'Reserved for 3GPP',
    0xE2: 'Reserved for 3GPP',
    0xE3: 'Reserved for 3GPP',
    0xE4: 'GSMA',
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
    0x07: 'ESN of the terminal',
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
    0x1A: 'Supported Radio Access Technologies',
}


# TS 102 223 §8.6 — Command Qualifier tables per Type of Command.
# Only commands with a known qualifier coding are listed; others fall back
# to a raw '0xXX' in _command_qualifier.  An entry may also be a callable
# for bitmask-style qualifiers (returns the decoded string or None).
COMMAND_QUALIFIERS = {
    0x01: REFRESH_MODES,   # REFRESH
    0x26: PLI_QUALIFIERS,  # PROVIDE LOCAL INFORMATION
}
# NOTE: SET UP IDLE MODE TEXT ('28') has no entry — its Command Qualifier
# is RFU per TS 102 223 V18.3.0 §8.6 ("this byte is RFU"); the generic
# fallback (hidden at '00', raw hex otherwise) applies.


# ──────────────────── §8.6 bitmask qualifier decoders ────────────────────
# Each decoder lists the *deviations from default*; an all-default (0x00)
# qualifier stays hidden, a non-zero qualifier with only RFU bits set
# falls back to raw hex.

def _bitmask(fn):
    def decoder(q):
        val = fn(q)
        parts = [val] if isinstance(val, str) else [p for p in val if p]
        if parts:
            return ', '.join(parts)
        return None if q == 0 else f'0x{q:02X}'
    return decoder


def _alphabet_bit(q):
    return 'UCS2 alphabet requested' if q & 0x02 else None


def _help_bit(q):
    return 'help information available' if q & 0x80 else None


@_bitmask
def _send_sm_qualifier(q):
    return ['SMS packing by terminal required'] if q & 0x01 else []


@_bitmask
def _play_tone_qualifier(q):
    return ['vibrate alert if available'] if q & 0x01 else []


@_bitmask
def _display_text_qualifier(q):
    return [('high priority' if q & 0x01 else None),
            ('wait for user to clear message' if q & 0x80 else None)]


@_bitmask
def _get_inkey_qualifier(q):
    if q & 0x04:  # Yes/No mode disables the b1/b2 character-set coding
        return ['Yes/No response requested',
                'immediate digit response requested' if q & 0x08 else None,
                _help_bit(q)]
    return [
        'alphabet set requested' if q & 0x01 else None,
        _alphabet_bit(q),
        'Yes/No response requested' if q & 0x04 else None,
        'immediate digit response requested' if q & 0x08 else None,
        _help_bit(q),
    ]


@_bitmask
def _get_input_qualifier(q):
    return [
        'alphabet set requested' if q & 0x01 else None,
        _alphabet_bit(q),
        'input shall not be revealed' if q & 0x04 else None,
        'SMS packed format requested' if q & 0x08 else None,
        _help_bit(q),
    ]


@_bitmask
def _select_item_qualifier(q):
    pres = []
    if q & 0x01:
        pres.append('navigation options presentation'
                    if q & 0x02 else 'data values presentation')
    return pres + ['selection using soft key preferred' if q & 0x04 else None,
                   _help_bit(q)]


@_bitmask
def _set_up_menu_qualifier(q):
    return ['selection using soft key preferred' if q & 0x01 else None,
            _help_bit(q)]


@_bitmask
def _timer_mgmt_qualifier(q):
    # TS 102 223 §8.6: bits 1 to 2 — '00' start, '01' deactivate,
    # '10' get current value, '11' RFU.
    op = q & 0x03
    return {1: 'deactivate timer', 2: 'get current timer value'}.get(op, [])


@_bitmask
def _language_notification_qualifier(q):
    return ['specific language notification'] if q & 0x01 else []


@_bitmask
def _open_channel_qualifier(q):
    # Coding depends on the bearer; bits decoded per the packet-data /
    # local bearer definition (TS 102 223 §8.6).
    parts = [p for p in [
        'immediate link establishment' if q & 0x01 else None,
        'automatic reconnection' if q & 0x02 else None,
        'background mode link establishment' if q & 0x04 else None,
        'DNS server address(es) requested' if q & 0x08 else None] if p]
    return [p + ' (bearer-dependent)' for p in parts]


@_bitmask
def _close_channel_qualifier(q):
    # Packet data service: b1 = reuse Network Access Name indication;
    # other bearers code b1 differently — hence the note.
    if q & 0x01:
        return ['next OPEN CHANNEL reuses same NAA/bearer (bearer-dependent)']
    return []


@_bitmask
def _send_data_qualifier(q):
    return ['send data immediately'] if q & 0x01 else []


@_bitmask
def _declare_service_qualifier(q):
    return ['delete service from terminal database'] if q & 0x01 else []


@_bitmask
def _display_mms_qualifier(q):
    return [('high priority' if q & 0x01 else None),
            ('wait for user to clear message' if q & 0x80 else None)]


COMMAND_QUALIFIERS.update({
    0x10: {0x00: 'set up call, but only if not currently busy',
           0x01: 'set up call, not busy, with redial',
           0x02: 'set up call, holding all other calls',
           0x03: 'set up call, holding others, with redial',
           0x04: 'set up call, disconnecting all other calls (if any)',
           0x05: 'set up call, disconnecting others, with redial'},
    0x13: _send_sm_qualifier,               # SEND SHORT MESSAGE
    0x15: {0x00: 'launch browser if not already launched',
           0x02: 'use existing browser (no secured session)',
           0x03: 'close browser session and launch new'},   # LAUNCH BROWSER
    0x20: _play_tone_qualifier,             # PLAY TONE
    0x21: _display_text_qualifier,          # DISPLAY TEXT
    0x22: _get_inkey_qualifier,             # GET INKEY
    0x23: _get_input_qualifier,             # GET INPUT
    0x24: _select_item_qualifier,           # SELECT ITEM
    0x25: _set_up_menu_qualifier,           # SET UP MENU
    0x27: _timer_mgmt_qualifier,            # TIMER MANAGEMENT
    0x33: {0x00: 'Card reader status',
           0x01: 'Card reader identifier'},  # GET READER STATUS
    0x35: _language_notification_qualifier,  # LANGUAGE NOTIFICATION
    0x40: _open_channel_qualifier,          # OPEN CHANNEL
    0x41: _close_channel_qualifier,         # CLOSE CHANNEL
    0x43: _send_data_qualifier,             # SEND DATA
    0x47: _declare_service_qualifier,       # DECLARE SERVICE
    0x50: {0x00: 'draw separator between adjoining frames',
           0x01: 'no separator between frames'},            # SET FRAMES
    0x62: _display_mms_qualifier,           # DISPLAY MULTIMEDIA MESSAGE
    0x73: {0x00: 'end encapsulated command session',
           0x01: 'request Master SA setup',
           0x02: 'request Connection SA setup',
           0x03: 'request Secure Channel Start',
           0x04: 'close Master/Connection SA, keep session'},  # eCAT
    0x79: {0x00: 'Proactive Session Request',
           0x01: 'UICC Platform Reset'},     # LSI COMMAND
})


def _command_qualifier(cmd_type, qualifier):
    """Decode a Command Qualifier (Command Details byte 3) into a string.

    Returns None when no meaningful qualifier is present, the raw '0xXX'
    for a non-zero qualifier without a table, or '0xXX <name>' when a
    table entry exists.
    """
    if qualifier is None:
        return None
    table = COMMAND_QUALIFIERS.get(cmd_type)
    if callable(table):
        return table(qualifier)
    if table:
        name = table.get(qualifier)
        if name is None:
            return f'0x{qualifier:02X}'
        return f'0x{qualifier:02X} {name}'
    if qualifier == 0x00:
        return None
    return f'0x{qualifier:02X}'


def _command_details_name(value):
    """Decode a Command Details TLV value into the command type name."""
    if len(value) < 2:
        return None
    if 0xF0 <= value[1] <= 0xFE:  # TS 102 223 §9.4 — reserved for proprietary use
        return f'Proprietary (0x{value[1]:02X})'
    return CAT_COMMAND_TYPES.get(value[1])


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


def decode_tr_qualifier(body):
    """Extract the Command Qualifier echoed in a TERMINAL RESPONSE body."""
    if not body:
        return None
    for tag, _length, value in parse_tlv(body):
        if tag == 0x81 and len(value) >= 3:
            return _command_qualifier(value[1], value[2])
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
    0x10: 'Proactive UICC session terminated by the user',
    0x11: 'Backward move in the proactive UICC session requested by the user',
    0x12: 'No response from user',
    0x13: 'Help information required by the user',
    0x14: 'USSD or SS transaction terminated by the user',
    # TS 102 223 §8.12.1 / TS 31.111: '15'-'16' reserved for 3GPP;
    # per-cause "terminal unable" details are Additional information
    # bytes of result '20', not separate general results.
    0x20: 'ME currently unable to process command',
    0x21: 'Network currently unable to process command',
    0x22: 'User did not accept the proactive command',
    0x23: 'User cleared down call before connection or network release',
    0x24: 'Action in contradiction with the current timer state',
    0x25: 'Interaction with call control by NAA, temporary problem',
    0x26: 'Launch browser generic error',
    0x27: 'MMS temporary problem',
    # '28'-'29' reserved for 3GPP
    0x30: 'Command beyond ME capabilities',
    0x31: 'Command type not understood by ME',
    0x32: 'Command data not understood by ME',
    0x33: 'Command number not known by ME',
    0x34: 'SS Return Error',
    0x35: 'SMS RP-ERROR',
    0x36: 'Error, required values are missing',
    0x37: 'USSD return error',
    0x38: 'Multiple Card command error',
    0x39: 'Interaction with call/SM control by USIM, permanent problem',
    0x3A: 'Bearer Independent Protocol error',
    0x3B: 'Access Technology unable to process command',
    0x3C: 'Frames error',
    0x3D: 'MMS error',
    # '3E'-'3F' reserved for 3GPP
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
    bcd = lambda x: (x & 0x0F) * 10 + (x >> 4)
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
    # TS 102 221 Table 11.5 (overrides ISO 7816-4 Table 14, where 110 =
    # cyclic and 100 = linear variable): 100 = cyclic, 110 = BER-TLV.
    0b000: 'no information',
    0b001: 'transparent',
    0b010: 'linear fixed',
    0b100: 'cyclic',
    0b110: 'BER-TLV',
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
    ft = (b >> 3) & 0x07  # bits b6-b4 = file type (1-based; 0-based 5..3)
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
    """Decode an FCP/FCI/FMD template (TS 102 221 §11.1.1.3).

    SFI (tag 0x88) is resolved per TS 102 221 §11.1.2:
    - length 1 → SFI = value >> 3 (bits b8..b4);
    - length 0 → file does not support SFI;
    - absent   → SFI = 5 LSBs of the FID (only if in range 1..30).
    """
    result = {}
    fid = None
    sfi_seen = False
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
            sfi_seen = True
            result['sfi'] = value[0] >> 3 if value else None
        elif tag == 0x8A:
            result['life_cycle'] = _LIFE_CYCLE.get(value[0] if value else 0, f'0x{(value[0] if value else 0):02X}')
        elif tag == 0x86:
            result['security_attr_proprietary'] = value.hex().upper()
        elif tag == 0x87:
            result['extending_ef_id'] = value.hex().upper()
        elif tag == 0x8B:
            result['security_attr_expanded'] = value.hex().upper()
        elif tag == 0x8C:
            result['security_attr_compact'] = value.hex().upper()
        elif tag == 0xAB:
            result['security_attr_template'] = value.hex().upper()
    if not sfi_seen and fid:
        sfi = int(fid, 16) & 0x1F
        result['sfi'] = sfi if 1 <= sfi <= 30 else None
    return result


def _decode_auth_3g(data):
    """Decode a 3G AUTHENTICATE response (tag DB success / DC sync-fail)."""
    tag = data[0]
    if tag == 0xDC:  # synchronisation failure → length byte + AUTS
        if len(data) >= 2:
            auts_len = data[1]
            auts = data[2:2 + auts_len]
        else:
            auts = data[1:]
        result = {'type': '3G/EPS/5G', 'status': 'sync fail', 'auts': auts.hex().upper()}
        # AUTS = SQN_MS⊕AK (6) || MAC-S (8)  (TS 33.102)
        if len(auts) >= 14:
            result['sqn_ak'] = auts[0:6].hex().upper()
            result['mac_s'] = auts[6:14].hex().upper()
        return result
    # tag 0xDB: success → length-prefixed RES, CK, IK, (KC)
    result = {'type': '3G/EPS/5G', 'status': 'success'}
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

def _decode_auth_cmd(data, p2):
    """Decode an AUTHENTICATE command body (RAND / RAND+AUTN)."""
    ctx = p2 & 0x07
    result = {}
    if p2 & 0x80:
        result['specific_key'] = True
    if ctx in (0, 1) and data:
        i = 0
        if i < len(data):
            rlen = data[i]
            i += 1
            result['rand'] = data[i:i + rlen].hex().upper()
            i += rlen
        if ctx == 1 and i < len(data):  # 3G/EPS/5G → AUTN
            alen = data[i]
            i += 1
            autn = data[i:i + alen]
            result['autn'] = autn.hex().upper()
            # AUTN = SQN⊕AK (6) || AMF (2) || MAC-A (8)  (TS 33.102)
            if len(autn) >= 16:
                result['sqn_ak'] = autn[0:6].hex().upper()
                result['amf'] = autn[6:8].hex().upper()
                result['mac'] = autn[8:16].hex().upper()
    return result


# TS 102 223 §8.25 — Event list values
EVENT_TYPES = {
    0x00: 'MT call', 0x01: 'Call connected', 0x02: 'Call disconnected',
    0x03: 'Location status', 0x04: 'User activity', 0x05: 'Idle screen available',
    0x06: 'Card reader status', 0x07: 'Language selection',
    0x08: 'Browser termination', 0x09: 'Data available',
    0x0A: 'Channel status', 0x0B: 'Access Technology Change (single)',
    0x0C: 'Display parameters changed', 0x0D: 'Local connection',
    0x0E: 'Network Search Mode Change', 0x0F: 'Browsing status',
    0x10: 'Frames Information Change', 0x11: '(I-)WLAN Access Status',
    0x12: 'Network Rejection', 0x13: 'HCI connectivity event',
    0x14: 'Access Technology Change (multiple)', 0x15: 'CSG cell selection',
    0x16: 'Contactless state request', 0x17: 'IMS Registration',
    0x18: 'IMS Incoming data', 0x19: 'Profile Container',
    0x1A: 'Void', 0x1B: 'Secured Profile Container',
    0x1C: 'Poll Interval Negotiation', 0x1D: 'Data Connection Status Change',
    0x1E: 'CAG cell selection', 0x1F: 'Slices Status Change',
    # TS 102 223 §8.25: '20'-'22' reserved for 3GPP (future usage)
}

LOCATION_STATUS = {
    0x00: 'Normal service',
    0x01: 'Limited service',
    0x02: 'No service',
}


# TS 102 223 §8.7 device identity coding (summary per UICC_SPECS.md §6.2)
_DEVICE_ID_RANGES = [
    (0x10, 0x17, lambda v: f'Card reader {v - 0x10}'),
    (0x21, 0x27, lambda v: f'Channel {v - 0x21}'),
    (0x31, 0x3F, lambda v: f'eCAT client {v - 0x30}'),
]
_DEVICE_IDS = {
    0x01: 'Keypad', 0x02: 'Display', 0x03: 'Earpiece',
    0x81: 'UICC', 0x82: 'Terminal', 0x83: 'Network',
}


def _device_id_name(value):
    """Decode one Device Identity byte (TS 102 223 §8.7)."""
    if value in _DEVICE_IDS:
        return _DEVICE_IDS[value]
    for lo, hi, fmt in _DEVICE_ID_RANGES:
        if lo <= value <= hi:
            return fmt(value)
    return f'0x{value:02X}'


def _decode_device_ids(value):
    """Decode a Device Identities TLV value into {src, dst} names."""
    if len(value) < 2:
        return None
    return {'src': _device_id_name(value[0]), 'dst': _device_id_name(value[1])}


def _decode_timer_value(b):
    """Decode a 3-byte Timer Value (TS 102 223 §8.38): TP-SCTS-style
    semi-octets (first digit in the low nibble) for hour/minute/second."""
    if len(b) != 3:
        return None
    def so(x):
        # TS 23.040 semi-octet representation: digit 1 in bits 1-4
        return '%d%d' % (x & 0x0F, (x >> 4) & 0x0F)
    return f'{so(b[0])}:{so(b[1])}:{so(b[2])}'


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
    0x70: 'Command Packet Identifier (CPI)',
    0x71: 'Response Packet Identifier (RPI)',
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
        if len(data) < length:
            break  # truncated UDH
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
    """Decode a TS 102 221 Annex A / TS 24.008 text string (GsmOrUcs2).

    Magic prefix 0x80/0x81/0x82 → UCS-2 variants (Annex A); 0x90 → UCS-2;
    0x83-0x87 → GSM 7-bit packed; 0x88-0x8F → UCS-2 with the high bit of
    the first octet cleared; otherwise GSM 7-bit default alphabet, packed
    when any octet has the high bit set, else one octet per character.
    """
    if not raw:
        return ''
    if raw == b'\xff' * len(raw):
        return ''
    if raw[0] == 0x80:
        return raw[1:].decode('utf_16_be', 'replace')
    if raw[0] == 0x90:
        data = raw[1:]
        null = data.find(b'\x00\x00')
        if null != -1:
            data = data[:null]
        return data.decode('utf-16-be', 'replace')
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
    if 0x83 <= raw[0] <= 0x87:
        data = raw[1:].rstrip(b'\xff')
        return _decode_gsm7(data, None) if data else ''
    if raw[0] & 0x80:
        ucs2 = bytearray(raw)
        ucs2[0] &= 0x7F
        while len(ucs2) >= 2 and ucs2[-1] == 0xFF and ucs2[-2] == 0xFF:
            ucs2 = ucs2[:-2]
        null = ucs2.find(b'\x00\x00')
        if null != -1:
            ucs2 = ucs2[:null]
        return bytes(ucs2).decode('utf-16-be', 'replace')
    data = raw.rstrip(b'\xff')
    if all(b < 0x80 for b in data):
        return _decode_gsm7_octets(data)
    return _decode_gsm7(data, None)


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


# TS 102 225 §5.1.1 — SPI bit-field names
_OTA_COUNTER = {0: 'no counter', 1: 'counter (no replay/seq check)',
                2: 'counter must be higher', 3: 'counter must be one higher'}
_OTA_RC_CC_DS = {0: 'none', 1: 'RC', 2: 'CC', 3: 'DS'}
_OTA_POR = {0: 'no PoR', 1: 'PoR required', 2: 'PoR only on error'}

# TS 102 225 §5.1.2 / §5.1.3 — KIc / KID algorithms (low nibble)
_KIC_ALGO = {0: 'implicit', 1: 'DES', 2: 'AES-CBC', 5: '3DES-CBC (2 keys)', 9: '3DES-CBC (3 keys)'}
_KID_CC_ALGO = {0: 'implicit', 1: 'DES', 5: '3DES-CBC (2 keys)', 9: '3DES-CBC (3 keys)', 2: 'AES-CMAC'}
_KID_RC_ALGO = {0: 'implicit', 1: 'CRC16', 5: 'CRC32', 3: 'proprietary'}

# TS 102 225 §5.2 Table 5 + TS 31.115 §7 — Response status codes
RESPONSE_STATUS = {
    0x00: 'PoR OK',
    0x01: 'RC/CC/DS failed',
    0x02: 'CNTR low',
    0x03: 'CNTR high',
    0x04: 'CNTR blocked',
    0x05: 'Ciphering error',
    0x06: 'Unidentified security error',
    0x07: 'Insufficient memory',
    0x08: 'More time needed',
    0x09: 'TAR unknown',
    0x0A: 'Insufficient security level',
    0x0B: 'Actual response data to be sent using SMS-SUBMIT',
    0x0C: 'Actual response data to be sent using USSD',
}


def _udh_ieis(udh):
    """Extract the numeric IEI values from a raw UDH byte string."""
    ieis = set()
    i = 0
    while i + 2 <= len(udh):
        ieis.add(udh[i])
        i += 2 + udh[i + 1]
    return ieis


def _decode_secured_packet(body):
    """Decode a secured Command Packet (TS 102 225 §5.1 / TS 31.115 §4.2).

    *body* is the TP-UD remainder after the UDH (CPI IEI 0x70).  Returns a
    dict of the decoded header fields; ``{'raw': hex}`` when unparseable.

    When SPI indicates ciphering, the on-wire CNTR, PCNTR and RC/CC/DS are
    CIPHERTEXT (TS 102 225 Table 2, note 1 — the whole block from CNTR
    through the secured data is encrypted); ``'ciphered'`` is set so
    callers do not present those bytes as the real values.
    """
    if not body or len(body) < 16:
        return {'raw': body.hex().upper()} if body else {}
    cpl = int.from_bytes(body[:2], 'big')
    chl = body[2]
    spi = body[3:5]
    kic = body[5]
    kid = body[6]
    tar = body[7:10]
    cntr = body[10:15]
    pcntr = body[15]
    spi1, spi2 = spi[0], spi[1]
    ciphered = bool(spi1 & 0x04)
    rc_cc_ds_kind = spi1 & 0x03
    rc_cc_ds_len = max(0, chl - 13)  # 13 = SPI+KIc+KID+TAR+CNTR+PCNTR
    rc_cc_ds = body[16:16 + rc_cc_ds_len]
    data = body[16 + rc_cc_ds_len:]

    result = {
        'cpl': cpl,
        'chl': chl,
        'ciphered': ciphered,
        'spi': {
            'hex': spi.hex().upper(),
            'counter': _OTA_COUNTER.get((spi1 >> 4) & 0x03, 'reserved'),
            'ciphering': bool(spi1 & 0x04),
            'rc_cc_ds': _OTA_RC_CC_DS.get(rc_cc_ds_kind, 'reserved'),
            'por': _OTA_POR.get(spi2 & 0x03, 'reserved'),
            'por_rc_cc_ds': _OTA_RC_CC_DS.get((spi2 >> 2) & 0x03, 'reserved'),
            'por_ciphered': bool(spi2 & 0x10),
            'por_transport': 'SMS-DELIVER-REPORT' if not (spi2 & 0x20) else 'SMS-SUBMIT',
        },
        'kic': {'key': kic >> 4, 'algo': _KIC_ALGO.get(kic & 0x0F, 'reserved')},
        'tar': tar.hex().upper(),
        'cntr': cntr.hex().upper(),
        'pcntr': pcntr,
        'data': data.hex().upper(),
        # Contiguous ciphered on-wire octets (CNTR ‖ PCNTR ‖ RC/CC/DS ‖
        # secured data + padding) — the block a client-side decryptor
        # feeds to 3DES/AES-CBC with a zero IV (TS 102 225 Table 2 n.1).
        'cipher_block': body[10:].hex().upper(),
        'kic_raw': kic,
        'kid_raw': kid,
    }
    kic_algo = _KIC_ALGO.get(kic & 0x0F, 'reserved')
    if not (spi1 & 0x04):  # SPI says no ciphering → KIc unused
        kic_algo += ' (unused)'
    result['kic'] = {'key': kic >> 4, 'algo': kic_algo}
    if rc_cc_ds_kind == 2:  # CC
        kid_algo = _KID_CC_ALGO.get(kid & 0x0F, 'reserved')
    elif rc_cc_ds_kind == 1:  # RC
        kid_algo = _KID_RC_ALGO.get(kid & 0x0F, 'reserved')
    elif rc_cc_ds_kind == 3:  # DS — no simple nibble table
        kid_algo = 'DS'
    else:  # none — decode the nibble anyway (CC interpretation)
        kid_algo = _KID_CC_ALGO.get(kid & 0x0F, 'reserved')
    if rc_cc_ds_kind == 0:
        kid_algo += ' (unused)'
    result['kid'] = {'key': kid >> 4, 'algo': kid_algo}
    if rc_cc_ds:
        result['rc_cc_ds'] = rc_cc_ds.hex().upper()
    return result


def _decode_response_packet(body, ciphered=False):
    """Decode a Response Packet (TS 102 225 §5.2 / TS 31.115 §4.4).

    *body* is the TP-UD remainder after the UDH (RPI IEI 0x71).  Returns a
    dict of the decoded header fields; ``{'raw': hex}`` when unparseable.

    *ciphered* reflects the command's SPI2.b5 (PoR ciphering): when set,
    the on-wire CNTR, PCNTR and RC/CC/DS are ciphertext (Table 4, note 1)
    and ``'ciphered'`` is set in the result.  A standalone Response Packet
    (e.g. inside an SMS-SUBMIT) carries no SPI, so the state is unknowable
    there and defaults to False.
    """
    if not body or len(body) < 13:
        return {'raw': body.hex().upper()} if body else {}
    rpl = int.from_bytes(body[:2], 'big')
    rhl = body[2]
    tar = body[3:6]
    cntr = body[6:11]
    pcntr = body[11]
    status = body[12]
    rc_cc_ds_len = max(0, rhl - 10)  # 10 = TAR+CNTR+PCNTR+Status
    rc_cc_ds = body[13:13 + rc_cc_ds_len]
    data = body[13 + rc_cc_ds_len:]

    result = {
        'rpl': rpl,
        'rhl': rhl,
        'ciphered': bool(ciphered),
        'tar': tar.hex().upper(),
        'cntr': cntr.hex().upper(),
        'pcntr': pcntr,
        'status': {'code': f'{status:02X}', 'name': RESPONSE_STATUS.get(status)},
        'data': data.hex().upper(),
    }
    if rc_cc_ds:
        result['rc_cc_ds'] = rc_cc_ds.hex().upper()
    return result


def _decode_ud(ud, udl, dcs, udhi, result):
    encoding, msg_class = _decode_dcs(dcs)
    result['encoding'] = encoding
    result['msg_class'] = msg_class

    pid = result.get('pid')
    ud_data = ud[:udl]

    # Parse UDH first — the presence of a CPI/RPI IEI identifies a secured
    # command/response packet (TS 31.115) regardless of the PID.
    udh_ieis = set()
    body = ud_data
    if udhi and ud_data:
        udhl = ud_data[0]
        result['udhl'] = udhl
        result['udh'] = _decode_udh(ud_data[1:1 + udhl])
        udh_ieis = _udh_ieis(ud_data[1:1 + udhl])
        body = ud_data[1 + udhl:]

    if pid == 0x7F or 0x70 in udh_ieis:  # secured Command Packet
        if pid == 0x7F:
            result['pid_name'] = 'SIM data download (secured packet)'
        secured = _decode_secured_packet(body)
        result['secured'] = secured
        if 'raw' in secured:
            result['payload'] = secured['raw']
        return result

    if 0x71 in udh_ieis:  # secured Response Packet (PoR)
        rp = _decode_response_packet(body)
        result['response_packet'] = rp
        if 'raw' in rp:
            result['payload'] = rp['raw']
        return result

    if udhi and ud_data:
        if encoding == 'GSM 7-bit':
            fill_bits = (udhl + 1) * 8
            n = udl - ((fill_bits + 6) // 7)
            result['text'] = _decode_gsm7(body, n)
            result['payload'] = body.hex().upper()
        elif encoding == 'UCS2':
            result['text'] = body[:udl].decode('utf-16-be', errors='replace')
        else:
            result['payload'] = body[:udl].hex().upper()
            text = _decode_8bit_text(body[:udl])
            if text is not None:
                result['text'] = text
    else:
        if encoding == 'GSM 7-bit':
            result['text'] = _decode_gsm7(ud_data, udl)
            result['payload'] = ud_data.hex().upper()
        elif encoding == 'UCS2':
            result['text'] = ud_data[:udl].decode('utf-16-be', errors='replace')
        else:
            result['payload'] = ud_data[:udl].hex().upper()
            text = _decode_8bit_text(ud_data[:udl])
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

    if tag == 0xDE:  # ENVELOPE CONTAINER — wraps another complete envelope
        for t, _l, v in parse_tlv(value):
            if t in ENVELOPE_TYPES:
                sub = _decode_envelope(bytes([t, len(v)]) + v)
                sub['encapsulated'] = True
                result['encapsulated'] = sub
            elif (t & 0x7F) == _P_DEVICE_IDS:
                d = _decode_device_ids(v)
                if d:
                    result['device_ids'] = d
        return result

    inner = parse_tlv(value)
    raw_tlv = []
    for t, _l, v in inner:
        base = t & 0x7F
        if base == _P_DEVICE_IDS:  # common to every envelope type
            d = _decode_device_ids(v)
            if d:
                result['device_ids'] = d
            continue
        if tag == 0xD6:  # EVENT DOWNLOAD
            if base == _P_EVENT_LIST and v:
                result['events'] = [EVENT_TYPES.get(e, f'0x{e:02X}') for e in v]
            elif base == _P_LOCATION_STATUS:
                if v:
                    result['location_status'] = LOCATION_STATUS.get(v[0], f'0x{v[0]:02X}')
            elif base == _P_LOCAL_INFO:
                li = _decode_local_info(PLI_LOCATION_INFO, v)
                result['location_info'] = li['value'] if li else v.hex().upper()
            elif base == _P_ADDRESS and v:  # caller's number (MT call)
                result['caller'] = _decode_bcd_address(v)
            elif base == _P_TRANSACTION_ID:
                if v:
                    result['transaction_id'] = v[0]
            elif base == _P_SUBADDRESS:
                result['subaddress'] = v.hex().upper()
            else:
                raw_tlv.append({'tag': f'{base:02X}', 'value': v.hex().upper()})
        elif tag == 0xD5:  # MO SHORT MESSAGE CONTROL
            if base == _P_ADDRESS and v:
                if 'smsc' not in result:
                    result['smsc'] = _decode_bcd_address(v)
                else:
                    result['tp_da'] = _decode_bcd_address(v)
            elif base == _P_LOCAL_INFO:
                result['location_info'] = v.hex().upper()
            else:
                raw_tlv.append({'tag': f'{base:02X}', 'value': v.hex().upper()})
        elif tag == 0xD1:  # SMS-PP DOWNLOAD
            if base == _P_ADDRESS and v:
                result['smsc'] = _decode_bcd_address(v)
            elif base == _P_SMS_TPDU and v:
                result['tpdu'] = _decode_sm_tpdu(v)
            else:
                raw_tlv.append({'tag': f'{base:02X}', 'value': v.hex().upper()})
        elif tag == 0xD2:  # CELL BROADCAST DOWNLOAD
            if base == _P_CB_PAGE and v:
                result['cb_page'] = _decode_cb_page(v)
            else:
                raw_tlv.append({'tag': f'{base:02X}', 'value': v.hex().upper()})
        elif tag == 0xD3:  # MENU SELECTION
            if base == _P_ITEM_ID and v:
                result['item_id'] = v[0]
            elif base == _P_HELP_REQUEST:  # TS 101 220: '15'/'95', length 00
                result['help'] = True
            else:
                raw_tlv.append({'tag': f'{base:02X}', 'value': v.hex().upper()})
        elif tag == 0xD4:  # CALL CONTROL
            if base == _P_ADDRESS and v:
                result['address'] = _decode_bcd_address(v)
            elif base == _P_CCP and v:
                result['ccp'] = v.hex().upper()
            elif base == _P_SUBADDRESS and v:
                result['subaddress'] = v.hex().upper()
            else:
                raw_tlv.append({'tag': f'{base:02X}', 'value': v.hex().upper()})
        elif tag == 0xD7:  # TIMER EXPIRATION
            if base == _P_TIMER_ID and v:
                result['timer_id'] = v[0] if len(v) == 1 else v.hex().upper()
            elif base == _P_TIMER_VALUE:
                tv = _decode_timer_value(v)
                if tv:
                    result['timer_value'] = tv
            else:
                raw_tlv.append({'tag': f'{base:02X}', 'value': v.hex().upper()})
        elif tag == 0xD9:  # USSD DOWNLOAD
            if base == _P_USSD_STRING and v:
                result['ussd'] = _decode_dcs_text(v)
            else:
                raw_tlv.append({'tag': f'{base:02X}', 'value': v.hex().upper()})
        elif tag == 0xDD:  # GEOGRAPHICAL LOCATION REPORTING
            if base == _P_LOCAL_INFO and v:
                li = _decode_local_info(PLI_LOCATION_INFO, v)
                result['location_info'] = li['value'] if li else v.hex().upper()
            else:
                raw_tlv.append({'tag': f'{base:02X}', 'value': v.hex().upper()})
        else:  # DA/DB/DC/DF/E0/… — keep objects visible as hex
            raw_tlv.append({'tag': f'{base:02X}', 'value': v.hex().upper()})

    if raw_tlv:
        result['raw_tlv'] = raw_tlv
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
_P_FILE_LIST = 0x12
_P_RESPONSE_LEN = 0x11
_P_EVENT_LIST = 0x19
_P_ICON_ID = 0x1E
_P_AID = 0x2F
# TS 101 220 table (COMPREHENSION-TLV tags, base values; CR form = +0x80)
_P_CCP = 0x07
_P_SUBADDRESS = 0x08
_P_USSD_STRING = 0x0A
_P_CB_PAGE = 0x0C
_P_LOCAL_INFO = 0x13
_P_HELP_REQUEST = 0x15
_P_ITEM_ID = 0x10
_P_LOCATION_STATUS = 0x1B
_P_TRANSACTION_ID = 0x1C
_P_TIMER_ID = 0x24
_P_TIMER_VALUE = 0x25

# Commands whose payload is defined as a Text String (GSM 11.14 / TS 102 223):
# DISPLAY TEXT, GET INKEY, GET INPUT, SET UP IDLE MODE TEXT.  Used for a
# guarded fallback against non-compliant cards that send the Text String
# with the next object's tag ('10', Item identifier).
_TEXT_STRING_COMMANDS = {0x21, 0x22, 0x23, 0x28}


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
    qualifier = None
    result = {}
    items = []
    file_list = []
    aid = None
    raw_tlv = []
    text_seen = False
    for tag, _length, value in inner:
        base = tag & 0x7F
        if base == _P_CMD_DETAILS and len(value) >= 2:
            cmd_type = value[1]
            if len(value) >= 3:
                qualifier = value[2]
        elif base == _P_ALPHA_ID and value:
            result['title'] = _decode_annex_a(value)
        elif base == _P_TEXT_STRING:
            result['text'] = _decode_dcs_text(value)
            result.pop('text_note', None)  # compliant TLV wins over quirk note
            text_seen = True
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
        elif base == _P_ICON_ID and value:
            result['icon_id'] = value[0]
        elif base == _P_ITEM_ID and len(value) == 1:
            result['item_id'] = value[0]
        elif base == _P_ITEM_ID and len(value) >= 2 and cmd_type in _TEXT_STRING_COMMANDS \
                and not text_seen:
            # Non-compliant card quirk (observed on a real SAT SIM): the
            # Text String carries the Item identifier tag '10' instead of
            # '8D'.  A genuine Item identifier is one byte, so length plus
            # command context disambiguate the two.
            result['text'] = _decode_dcs_text(value)
            result['text_note'] = "text string with non-standard tag '10'"
            text_seen = True
        elif base == _P_FILE_LIST and value:
            file_list = [value[i:i + 2].hex().upper() for i in range(0, len(value), 2)]
        elif base == _P_AID and value:
            aid = value.hex().upper()
        elif base == _P_DEVICE_IDS and len(value) >= 2:
            result['device_ids'] = _decode_device_ids(value)
        else:
            raw_tlv.append({'tag': f'{base:02X}', 'value': value.hex().upper()})

    if cmd_type is None:
        return None
    if 0xF0 <= cmd_type <= 0xFE:  # TS 102 223 §9.4 — reserved for proprietary use
        result['type'] = f'Proprietary (0x{cmd_type:02X})'
    else:
        result['type'] = CAT_COMMAND_TYPES.get(cmd_type, f'0x{cmd_type:02X}')
    qualifier_desc = _command_qualifier(cmd_type, qualifier)
    if qualifier_desc:
        result['qualifier'] = qualifier_desc
    if file_list:
        result['file_list'] = file_list
    if aid:
        result['aid'] = aid
    if items:
        result['items'] = items
    if raw_tlv:
        result['raw_tlv'] = raw_tlv
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
    # First nibble is the mobile-identity type (001) + parity indicator
    # (TS 24.008), not an IMSI digit.
    if digits:
        digits = digits[1:]
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


def _looks_like_ber_tlv(data):
    """Heuristic: does *data* look like a BER-TLV rather than Annex-A text?

    Annex-A UCS2 prefixes are 0x80/0x81/0x82, so those are excluded; other
    0x83-0xBF leading bytes are treated as BER-TLV tags if their length
    field is consistent with the data length.
    """
    if len(data) < 2:
        return False
    if data[0] in (0x80, 0x81, 0x82):
        return False
    if not (0x80 <= data[0] <= 0xBF):
        return False
    length = data[1]
    if length & 0x80:
        num = length & 0x7F
        if num == 0 or 2 + num > len(data):
            return False
        length = int.from_bytes(data[2:2 + num], 'big')
        header = 2 + num
    else:
        header = 2
    return header + length >= len(data) - 1


def _decode_adn(raw, p1=None):
    """ADN-format record: alpha + len_bcd + TON/NPI + number + CCP + ext1."""
    if not raw or all(b == 0xff for b in raw):
        return {'empty': True}
    if len(raw) < 14:
        return {'raw': raw.hex().upper()}
    alpha = raw[:-14].rstrip(b'\xff')
    # If the alpha is not text (e.g. BER-TLV), show raw hex instead.
    if alpha and _looks_like_ber_tlv(alpha):
        return {'raw': raw.hex().upper()}
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
    """EF_DIR record: application template(s) — AID (4F) + label (50)
    + optional EAP discretionary template (73, TS 102 310)."""
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
            elif t2 == 0x73:
                eap = _decode_eap_template(v2)
                if eap:
                    app['eap'] = eap
        if app:
            apps.append(app)
    return {'applications': apps} if apps else {'raw': raw.hex().upper()}


# IANA EAP method types seen in TS 102 310 EF_DIR entries.
_EAP_TYPES = {
    18: 'EAP-SIM',
    23: 'EAP-AKA',
    50: 'EAP-AKA\'',
}


def _decode_eap_template(value):
    """TS 102 310 §5.2: 73 → A0 { 80 EAP types, 81 DF FIDs, 82 label }."""
    for t2, _l2, v2 in parse_tlv(value):
        if t2 != 0xA0:
            continue
        eap = {}
        for t3, _l3, v3 in parse_tlv(v2):
            if t3 == 0x80:
                eap['eap_types'] = [_EAP_TYPES.get(b, b) for b in v3]
            elif t3 == 0x81:
                eap['dfs'] = [v3[i:i + 2].hex() for i in range(0, len(v3), 2)]
            elif t3 == 0x82:
                eap['label'] = v3.decode('ascii', 'replace')
        return eap
    return {}


def _decode_arr(raw, p1=None):
    entries = []
    for tag, _length, value in parse_tlv(raw):
        entries.append({'tag': f'0x{tag:02X}', 'hex': value.hex().upper()})
    return {'rules': entries} if entries else {'raw': raw.hex().upper()}


def _decode_pnn_text(value):
    """Decode a TS 24.008 §10.5.3.5a Network Name (DCS byte + text)."""
    if len(value) < 2:
        return ''
    dcs = value[0]
    coding = (dcs >> 4) & 0x07
    data = value[1:].rstrip(b'\xff')
    if coding == 1:  # UCS2
        null = data.find(b'\x00\x00')
        if null != -1:
            data = data[:null]
        return data.decode('utf-16-be', 'replace')
    if coding == 0:  # GSM 7-bit default alphabet
        if all(b < 0x80 for b in data):
            return _decode_gsm7_octets(data)
        return _decode_gsm7(data, None)
    return ''


def _decode_pnn(raw, p1=None):
    if not raw or all(b == 0xff for b in raw):
        return {'empty': True}
    names = {}
    for tag, _length, value in parse_tlv(raw):
        if tag == 0x43:
            names['full'] = _decode_pnn_text(value)
        elif tag == 0x45:
            names['short'] = _decode_pnn_text(value)
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
    """EF_CBMIR (§10.3.28): 4-byte ranges [msg-id low(2) + high(2)], 4n B."""
    ranges = []
    for i in range(0, len(raw) - 3, 4):
        rec = raw[i:i + 4]
        if all(b == 0xff for b in rec):
            continue
        low = (rec[0] << 8) | rec[1]
        high = (rec[2] << 8) | rec[3]
        ranges.append([low, high])
    if not ranges:
        return {'raw': raw.hex().upper()}
    return {'ranges': ranges if len(ranges) > 1 else ranges[0]}


def _decode_ecc(raw, p1=None):
    """EF_ECC records (UICC_FILES §10.3.27): ECC digits BCD(2) + ESC(1)."""
    if all(b == 0xff for b in raw):
        return {'empty': True}
    recs = []
    for i in range(0, len(raw) - 2, 3):
        rec = raw[i:i + 3]
        if all(b == 0xff for b in rec):
            continue
        digits = _swap_nibbles(rec[:2].hex()).rstrip('fF')
        recs.append({'number': digits or None, 'esc': f'0x{rec[2]:02X}'})
    if not recs:
        return {'raw': raw.hex().upper()}
    return recs[0] if len(recs) == 1 else {'numbers': recs}


def _decode_kc(raw, p1=None):
    """EF_Kc / EF_KcGPRS (UICC_FILES §10.3.3): Kc(8) + Kc/KSI byte
    (b8-b5 ciphering key sequence number, b4-b1 RFU)."""
    if all(b == 0xff for b in raw):
        return {'empty': True}
    out = {'kc': raw[:8].hex().upper()} if len(raw) >= 8 else {}
    if len(raw) >= 9:
        out['ksi'] = (raw[8] >> 4) & 0x0F
    return out or {'raw': raw.hex().upper()}


def _decode_opl(raw, p1=None):
    """EF_OPL (§10.3.42): PLMN(3, 'D' = wild) + LAC range(2+2) + PNN rec(1)."""
    if all(b == 0xff for b in raw):
        return {'empty': True}
    recs = []
    for i in range(0, len(raw) - 7, 8):
        rec = raw[i:i + 8]
        if all(b == 0xff for b in rec):
            continue
        plmn = _decode_plmn(rec[:3]) or {}
        lac_lo = rec[3:5].hex().upper()
        lac_hi = rec[5:7].hex().upper()
        recs.append({
            'mcc': plmn.get('mcc'), 'mnc': plmn.get('mnc'),
            'lac_range': [lac_lo, lac_hi],
            'pnn_record': rec[7],
        })
    if not recs:
        return {'raw': raw.hex().upper()}
    return recs[0] if len(recs) == 1 else {'records': recs}


def _decode_ext1(raw, p1=None):
    """EXT records (§10.5.10): len(1) + BCD(10) + CCP(1) + EXT(1)."""
    if all(b == 0xff for b in raw):
        return {'empty': True}
    n = raw[0]
    digits = _swap_nibbles(raw[1:11].hex())[:n * 2].rstrip('fF') if n else ''
    return {
        'number': digits or None,
        'ccp': None if raw[11] == 0xff else raw[11],
        'ext': None if raw[12] == 0xff else raw[12],
    }


def _decode_ad(raw, p1=None):
    """EF_AD (§10.3.18): op mode + additional info + optional MNC length."""
    if all(b == 0xff for b in raw):
        return {'empty': True}
    op = raw[0] & 0x03
    out = {'op_mode': {0: 'normal operation', 1: 'specific features'}.get(op, f'0x{op:02X}'),
           'test_mode': bool(raw[0] & 0x04)}
    if len(raw) >= 3:
        out['additional_info'] = raw[1:3].hex().upper()
    if len(raw) >= 4 and raw[3] != 0xff:
        out['mnc_length'] = raw[3]
    return out


def _decode_acl(raw, p1=None):
    """EF_ACL (§4.2.48): APN count byte + 'DD'-tagged APN TLVs."""
    if all(b == 0xff for b in raw):
        return {'empty': True}
    apns = []
    for tag, _length, value in parse_tlv(raw[1:]):
        if tag == 0xDD:
            apns.append(value.decode('ascii', 'replace') if value else
                        '(network provided)')
    return {'apns': apns} if apns else {'raw': raw.hex().upper()}


def _decode_smsp(raw, p1=None):
    """EF_SMSP (§10.5.6): alpha(Y) + PI + TP-DA(12) + SCA(12) + PID/DCS/VP."""
    if all(b == 0xff for b in raw):
        return {'empty': True}
    if len(raw) < 28:
        return {'raw': raw.hex().upper()}
    y = len(raw) - 28
    out = {}
    alpha = _decode_annex_a(raw[:y].rstrip(b'\xff'))
    if alpha:
        out['alpha'] = alpha
    pi = raw[y]
    out['param_indicators'] = f'0x{pi:02X}'
    if not (pi & 0x01):
        out['tp_da'] = _decode_bcd_address(raw[y + 1:y + 13][:12])
    if not (pi & 0x10):
        out['sca'] = _decode_bcd_address(raw[y + 13:y + 25][:12])
    if not (pi & 0x02):
        out['tp_pid'] = f'0x{raw[y + 25]:02X}'
    if not (pi & 0x04):
        out['tp_dcs'] = f'0x{raw[y + 26]:02X}'
    if not (pi & 0x08):
        out['tp_vp'] = f'0x{raw[y + 27]:02X}'
    return out


def _decode_spdi(raw, p1=None):
    """EF_SPDI (§4.2.66): 'A3' container (or bare '80' value tags) with
    3-byte PLMN records — same shape as EF_PLMNwAcT for _file_summary."""
    if all(b == 0xff for b in raw):
        return {'empty': True}
    plmns = []

    def collect(value):
        for i in range(0, len(value) - 2, 3):
            plmn = _decode_plmn(value[i:i + 3])
            if plmn and plmn not in plmns:
                plmns.append(plmn)

    for tag, _length, value in parse_tlv(raw):
        if tag == 0xA3:
            got = False
            for t2, _l2, v2 in parse_tlv(value):
                if t2 == 0x80:
                    collect(v2)
                    got = True
            if not got:
                collect(value)  # bare records inside A3
        elif tag == 0x80:
            collect(value)
    if not plmns:
        return {'raw': raw.hex().upper()}
    return {'plmns': plmns}


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
    # EF_LOCI (TS 31.102 §4.2.16): TMSI 4 + LAI 5 + TMSI_TIME 1 + update status 1 = 11 bytes.
    if len(raw) < 11:
        return {'raw': raw.hex().upper()}
    tmsi = raw[0:4]
    lai = raw[4:9]
    plmn = _decode_plmn(lai[:3]) or {}
    return {
        'tmsi': None if all(b == 0xff for b in tmsi) else tmsi.hex().upper(),
        'mcc': plmn.get('mcc'), 'mnc': plmn.get('mnc'),
        'lac': '0x' + lai[3:5].hex().upper(),
        'tmsi_time': f'0x{raw[9]:02X}',
        'location_update_status': f'0x{raw[10]:02X}',
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


def _decode_epsloci(raw, p1=None):
    # EF_EPSLOCI (TS 31.102 §4.2.91): GUTI 12 + TAI 5 + update status 1 = 18 bytes.
    if all(b == 0xff for b in raw):
        return {'empty': True}
    if len(raw) < 18:
        return {'raw': raw.hex().upper()}
    guti = raw[0:12]
    tai = raw[12:17]
    plmn = _decode_plmn(tai[:3]) or {}
    return {
        'guti': None if all(b == 0xff for b in guti) else guti.hex().upper(),
        'mcc': plmn.get('mcc'), 'mnc': plmn.get('mnc'),
        'tac': '0x' + tai[3:5].hex().upper(),
        'eps_update_status': f'0x{raw[17]:02X}',
    }


def _decode_psloci(raw, p1=None):
    # EF_PSLOCI (TS 31.102 §4.2.23): P-TMSI 4 + P-TMSI sig 3 + RAI 6 + status 1 = 14 bytes.
    if all(b == 0xff for b in raw):
        return {'empty': True}
    if len(raw) < 14:
        return {'raw': raw.hex().upper()}
    ptmsi = raw[0:4]
    rai = raw[7:13]
    plmn = _decode_plmn(rai[:3]) or {}
    return {
        'p_tmsi': None if all(b == 0xff for b in ptmsi) else ptmsi.hex().upper(),
        'p_tmsi_signature': raw[4:7].hex().upper(),
        'mcc': plmn.get('mcc'), 'mnc': plmn.get('mnc'),
        'lac': '0x' + rai[3:5].hex().upper(),
        'rac': '0x' + rai[5:6].hex().upper(),
        'update_status': f'0x{raw[13]:02X}',
    }


def _decode_nai(raw, p1=None):
    """ISIM identity files (EF_IMPI/DOMAIN/IMPU): BER-TLV tag 0x80/0x81 + value.

    An erased or unused record is all-0xFF, or a lone identity tag, or a
    tag with a zero-length value (e.g. ``80 00`` + FF filler) — these are
    reported as empty rather than decoded as text.  Only the TLV *value*
    bytes are decoded (UTF-8 for a SIP/TEL URI); the TLV header and any
    trailing erase filler are never fed to the text decoder.
    """
    if not raw or all(b == 0xff for b in raw):
        return {'empty': True}
    data = bytes(raw).rstrip(b'\xff')  # drop erase filler
    if not data or (data[0] in (0x80, 0x81) and len(data) <= 2):
        return {'empty': True}  # lone tag, or tag + zero-length value = unused
    texts = []
    for tag, _length, value in parse_tlv(data):
        if tag in (0x80, 0x81) and value:
            texts.append(value.decode('utf-8', 'replace'))
    if texts:
        return {'text': texts[0] if len(texts) == 1 else ', '.join(texts)}
    return {'raw': raw.hex().upper()}


def _decode_epsnsc(raw, p1=None):
    # EF_EPSNSC (TS 31.102 §4.2.92): record = A0 { 80 KSI_ASME, 81 K_ASME,
    # 82 UpLink NAS COUNT, 83 DownLink NAS COUNT, 84 NAS algorithms }.
    if not raw or all(b == 0xff for b in raw):
        return {'empty': True}
    inner = raw
    for tag, _length, value in parse_tlv(raw):
        if tag == 0xA0:
            inner = value
            break
    out = {}
    for tag, _length, value in parse_tlv(inner):
        if tag == 0x80:
            out['ksi_asme'] = value.hex().upper()
        elif tag == 0x81:
            out['k_asme'] = value.hex().upper()
        elif tag == 0x82:
            out['uplink_nas_count'] = int.from_bytes(value, 'big')
        elif tag == 0x83:
            out['downlink_nas_count'] = int.from_bytes(value, 'big')
        elif tag == 0x84:
            out['nas_algorithms'] = value.hex().upper()
    if not out:
        return {'raw': raw.hex().upper()}
    return out


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
    '6f73': _decode_psloci,
    '6fe3': _decode_epsloci,
    '6fe4': _decode_epsnsc,
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
    '6f20': _decode_kc,
    '6f52': _decode_kc,
    '6fc6': _decode_opl,
    '6f4a': _decode_ext1,
    '6f4b': _decode_ext1,
    '6f4c': _decode_ext1,
    '6f4e': _decode_ext1,
    '6f55': _decode_ext1,
    '6fad': _decode_ad,
    '6f57': _decode_acl,
    '6f42': _decode_smsp,
    '6fcd': _decode_spdi,
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


_RECORD_STRUCTURES = ('linear fixed', 'cyclic')


def _is_record_file(sel):
    """True if *sel* is (or may be) a record-based EF.

    A None structure means we don't know the file structure (e.g. the
    FCP/GET RESPONSE was lost too), so we allow the decode as best effort.
    """
    if not sel:
        return True
    structure = sel.get('structure')
    if structure is None:
        return True
    return structure in _RECORD_STRUCTURES


def _stale_file_note(sel):
    """Mark a decode as skipped because the selection is inconsistent."""
    fid = sel.get('fid') or ''
    return {'fid': fid, 'ef': KNOWN_FIDS.get(fid, fid.upper()), 'stale': True}


def _file_summary(f):
    """Compact one-line summary of a decoded file body."""
    if f.get('stale'):
        return 'record op on non-record file (selection stale?)'
    if f.get('empty'):
        return 'empty'
    if f.get('unknown'):
        return 'unknown file'
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
        parts = []
        for a in f['applications']:
            s = a.get('label') or a.get('aid') or ''
            eap = a.get('eap')
            if eap:
                types = ', '.join(str(t) for t in eap.get('eap_types', []))
                dfs = ', '.join(KNOWN_FIDS.get(d, d) for d in eap.get('dfs', []))
                s += f" [{eap.get('label', 'EAP')}: {types} in {dfs}]"
            parts.append(s)
        return '; '.join(parts)
    if f.get('tpdu'):
        t = f['tpdu']
        s = t.get('mti', '')
        if t.get('text'):
            s += f" \u00ab{t['text']}\u00bb"
        return f"SMS {s}".strip()
    if f.get('direction'):
        return f"SMS {f['direction']} — {f['status']}"
    if f.get('guti'):
        return f"GUTI {f['guti']} · TAC {f.get('tac', '')} · status {f.get('eps_update_status', '')}"
    if f.get('p_tmsi'):
        return f"P-TMSI {f['p_tmsi']} · status {f.get('update_status', '')}"
    if 'ksi_asme' in f:
        return f"KSI {f['ksi_asme']} · NAS counts {f.get('uplink_nas_count', '?')}/{f.get('downlink_nas_count', '?')}"
    if f.get('mcc'):
        parts = [f"MCC {f['mcc']} MNC {f['mnc']}"]
        if f.get('lac'):
            parts.append(f"LAC {f['lac']}")
        if f.get('tac'):
            parts.append(f"TAC {f['tac']}")
        if f.get('rac'):
            parts.append(f"RAC {f['rac']}")
        return ' · '.join(parts)
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
    p1p2 = result.get('p1p2')
    if p1p2 and not p1p2.get('unused'):
        if 'sfi' in p1p2:
            p1txt = f"SFI {p1p2['sfi']}"
            if p1p2.get('offset'):
                p1txt += f", offset {p1p2['offset']}"
        elif 'offset' in p1p2:
            p1txt = f"Offset: 0x{p1p2['offset']:04X}"
        else:
            p1txt = f"{p1p2['label']}: 0x{p1p2['value']:04X}"
    else:
        if p1:
            p1txt = p1.get('name')
            if not p1txt and p1.get('label') is not None and p1.get('value') is not None:
                p1txt = f"{p1['label']}: {p1['value']}"
            if not p1txt and p1.get('bits'):
                p1txt = ', '.join(p1['bits'])
        if p2:
            p2txt = p2.get('name')
            if p2.get('sfi'):
                p2txt = f"SFI {p2['sfi']}"
            elif not p2txt and p2.get('bits'):
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
        if cmd.get('qualifier'):
            parts.append(cmd['qualifier'])
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
    response = result.get('response')
    if response and response.get('qualifier'):
        parts.append(response['qualifier'])
    if result.get('response_for'):
        response = result.get('response') or {}
        fd = response.get('file_descriptor')
        if fd:
            parts.append(_fcp_summary(result['response_for'], fd, response))
        elif response.get('tar'):
            st = response.get('status') or {}
            parts.append(f"{st.get('name') or ('0x' + st.get('code', ''))} · TAR {response['tar']}")
        else:
            parts.append('response for ' + result['response_for'])
    if response and response.get('name'):
        parts.append(response['name'])

    file_dec = result.get('file')
    if file_dec:
        if file_dec.get('unknown'):
            parts.append('unknown file')
        else:
            ef = file_dec.get('ef') or file_dec.get('fid') or ''
            txt = _file_summary(file_dec)
            if txt:
                parts.append(f"{ef} {txt}".strip())
            elif ef:
                parts.append(ef)

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
    if ins in (0xB0, 0xD6):  # READ/UPDATE BINARY → SFI/offset P1-P2
        result['p1p2'] = _decode_binary_offset(p1, p2)
    elif spec:
        if 'p1p2' in spec:
            offset = (p1 << 8) | p2
            if spec['p1p2'].get('unused'):
                result['p1p2'] = {'unused': True, 'value': offset}
            else:
                result['p1p2'] = {'label': spec['p1p2']['label'], 'value': offset}
        else:
            result['p1'] = _decode_field(spec.get('p1', {}), p1)
            result['p2'] = _decode_field(spec.get('p2', {}), p2)
            if ins in (0xB2, 0xDC, 0xA2):
                # Record commands: P2 b8-b4 = SFI (TS 102 221 §11.1.5/6/7).
                sfi = p2 >> 3
                if sfi:
                    result['p2']['sfi'] = sfi

    # Body: at least P3 bytes from byte 5; extra bytes may be SW
    remaining = raw_data[5:]
    extra_total = len(remaining) - p3
    sw_bytes = None

    if len(remaining) >= 2 and (extra_total >= 2 or extra_total < 0):
        sw_candidate = remaining[-2:]
        if sw_candidate[0] in (0x60, 0x61, 0x62, 0x63, 0x64, 0x65,
                               0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
                               0x6c, 0x6d, 0x6e, 0x6f, 0x90, 0x91,
                               0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                               0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
                               0x9e, 0x9f):
            sw_bytes = sw_candidate

    cmd_body_len = len(remaining) - 2 if sw_bytes else len(remaining)

    # Length sanity: P3 (Lc/Le) vs actual data captured.
    if cmd_body_len > p3:
        result['length_mismatch'] = {'kind': 'excessive', 'expected': p3, 'actual': cmd_body_len}
    elif cmd_body_len < p3 and not (spec and spec.get('le')):
        result['length_mismatch'] = {'kind': 'truncated', 'expected': p3, 'actual': cmd_body_len}

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
            response = _decode_tr_result(body) or {}
            tr_qualifier = decode_tr_qualifier(body)
            if tr_qualifier:
                response['qualifier'] = tr_qualifier
            result['response'] = response or None
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
            elif ins == 0xF2:  # STATUS → response data is the FCP of the current DF/EF
                fcp = _decode_fcp(body)
                if fcp:
                    result['response'] = fcp

        # File data decode for READ/UPDATE using the current selection.
        p1p2 = result.get('p1p2') or {}
        rec_sfi = (result.get('p2') or {}).get('sfi')
        if ins in (0xB0, 0xD6) and prev and 'sfi' in p1p2:
            # SFI referencing → resolve the target EF, not the last selection.
            sfi = p1p2['sfi']
            fid = (prev.get('sfi_map') or {}).get(sfi)
            if fid:
                file_dec = _decode_file_data(fid, body, p1=p1)
                if file_dec:
                    result['file'] = file_dec
                else:
                    result['file'] = {'fid': fid, 'ef': KNOWN_FIDS.get(fid, fid.upper()),
                                      'raw': body.hex().upper()}
            else:
                result['file'] = {'sfi': sfi, 'unknown': True, 'ef': f'SFI {sfi}'}
        elif ins in (0xB2, 0xDC) and prev and rec_sfi:
            # Record command with SFI (P2 b8-b4) → resolve the target EF.
            fid = (prev.get('sfi_map') or {}).get(rec_sfi)
            if fid:
                file_dec = _decode_file_data(fid, body, p1=p1)
                if file_dec:
                    result['file'] = file_dec
                else:
                    result['file'] = {'fid': fid, 'ef': KNOWN_FIDS.get(fid, fid.upper()),
                                      'raw': body.hex().upper()}
            else:
                result['file'] = {'sfi': rec_sfi, 'unknown': True, 'ef': f'SFI {rec_sfi}'}
        elif ins == 0xA2 and prev and rec_sfi:
            # SEARCH RECORD with SFI → attach the target file name (the body
            # is a search pattern, not file data).
            fid = (prev.get('sfi_map') or {}).get(rec_sfi)
            if fid:
                result['file'] = {'fid': fid, 'ef': KNOWN_FIDS.get(fid, fid.upper())}
            else:
                result['file'] = {'sfi': rec_sfi, 'unknown': True, 'ef': f'SFI {rec_sfi}'}
        elif ins in (0xB0, 0xB2, 0xD6, 0xDC) and prev and prev.get('sel'):
            offset = p1p2.get('offset', 0)
            if ins in (0xB2, 0xDC) and not _is_record_file(prev['sel']):
                result['file'] = _stale_file_note(prev['sel'])
            else:
                file_dec = None
                if ins in (0xB2, 0xDC) or offset == 0:
                    file_dec = _decode_file_data(prev['sel']['fid'], body, p1=p1)
                if file_dec:
                    result['file'] = file_dec
                else:
                    # Known file, no content decoder (or non-zero offset) —
                    # still attribute the operation to the selected file.
                    result['file'] = {
                        'fid': prev['sel']['fid'],
                        'ef': KNOWN_FIDS.get(prev['sel']['fid'],
                                             prev['sel']['fid'].upper()),
                    }

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
                    if prev_ins == 0xB2 and not _is_record_file(prev['sel']):
                        result['file'] = _stale_file_note(prev['sel'])
                    else:
                        file_dec = _decode_file_data(prev['sel']['fid'], remaining[:cmd_body_len])
                        if file_dec:
                            result['file'] = file_dec
                        else:
                            # Known file, no content decoder — attribute anyway.
                            fid = prev['sel']['fid']
                            result['file'] = {
                                'fid': fid,
                                'ef': KNOWN_FIDS.get(fid, fid.upper()),
                            }
                elif prev_ins == 0xA2 and prev.get('sel') and prev.get('file_ok'):
                    if not _is_record_file(prev['sel']):
                        result['file'] = _stale_file_note(prev['sel'])
                    else:
                        # SEARCH RECORD → list of matching record numbers
                        fid = prev['sel']['fid']
                        result['file'] = {
                            'fid': fid,
                            'ef': KNOWN_FIDS.get(fid, fid.upper()),
                            'record_numbers': list(remaining[:cmd_body_len]),
                        }
                elif prev_ins == 0xC2:  # ENVELOPE → Response Packet (PoR)
                    data = remaining[:cmd_body_len]
                    # RPI mapping precedes the packet: UDHL='02', IEIa='71',
                    # IEIDLa='00' (TS 31.115 §4.4).
                    if data[:3] == b'\x02\x71\x00':
                        result['response'] = _decode_response_packet(
                            data[3:], ciphered=bool(prev.get('por_ciphered')))
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

# Sniff data error flags (SNIFF_DATA_FLAG_ERROR_*, simtrace_prot.h).
DATA_FLAGS = {
    1 << 5: 'incomplete',
    1 << 6: 'malformed',
    1 << 7: 'checksum error',
    1 << 8: 'overrun',
    1 << 9: 'framing error',
    1 << 10: 'parity error',
}


def _flag_names(flags, mapping):
    names = []
    for mask, name in sorted(mapping.items()):
        if flags & mask:
            names.append(name)
    return names


def decode_change(flags):
    """Decode SIMtrace2 sniff_change flags into a list of human-readable names."""
    bits = _flag_names(flags, CHANGE_FLAGS)
    return {
        'type': 'change',
        'flags_hex': f'{flags:08x}',
        'flags': bits if bits else ['no changes'],
    }


def decode_line_event(raw_data, kind):
    """Decode a sigrok-iso7816-stream RST/VCC line event (GSMTAP sub_type
    0x10/0x11): payload [direction, level, reserved].

    direction — RST: 1 = asserted (high→low), 0 = de-asserted (low→high);
    VCC: 1 = power applied (low→high), 0 = removed (high→low).
    level — resulting line level: 0 = low, 1 = high.

    ``event`` is the canonical value; ``label`` is the human-facing
    summary (e.g. RST de-asserted → "ATR STARTS", VCC applied →
    "VCC ON (power-up)").
    """
    result = {'type': kind}
    if raw_data and len(raw_data) >= 2:
        direction, level = raw_data[0], raw_data[1]
        if kind == 'rst':
            if direction:
                result['event'] = 'reset asserted'
                result['label'] = 'RESET ASSERTED'
            else:
                result['event'] = 'reset de-asserted'
                result['label'] = 'ATR STARTS'
        else:
            if direction:
                result['event'] = 'power applied'
                result['label'] = 'VCC ON (power-up)'
            else:
                result['event'] = 'power removed'
                result['label'] = 'VCC OFF (power-down)'
        result['level'] = 'high' if level else 'low'
        result['raw'] = raw_data.hex().upper()
    return result


def decode_data_flags(flags):
    """Decode SIMtrace2 sniff_data error flags into a list of names (or None)."""
    if not flags:
        return None
    names = _flag_names(flags, DATA_FLAGS)
    return names or None


def gsmtap_flag_names(flags):
    """Decode the GSMTAP header ``res`` per-packet flag bits into a list of
    human-readable names (or None).

    GSMTAP_FLAG_BAD_FCS is set by the sigrok-iso7816-stream decoder on a
    desynced TPDU (mis-framed exchange / implausible status word).
    """
    names = []
    if flags & GSMTAP_FLAG_BAD_FCS:
        names.append('bad FCS (desynced)')
    return names or None


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
    pps = False
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
            if cur_t == 15:
                pps = True
            else:
                protocols.append(_T_PROTOCOLS.get(cur_t, f'T={cur_t}'))
            flags = b & 0xF0
            level += 1
        else:
            flags = 0

    if interface:
        result['interface'] = interface
    if protocols:
        result['protocols'] = protocols
    if pps:
        result['pps'] = True

    k = result['historical_len']
    if k and i + k <= len(body):
        result['historical'] = _decode_historical(body[i:i + k])
    i += k

    # TCK present unless only T=0 is proposed (ISO 7816-3 §8.2.5).
    only_t0 = (not protocols or protocols == ['T=0']) and not pps
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
        result = decode_message(raw_data, prev=prev)
        if result is not None:
            errs = (decode_data_flags(flags) or []) + (gsmtap_flag_names(flags) or [])
            if errs:
                result['errors'] = errs
        return result
    if msg_type == 'change':
        return decode_change(flags)
    if msg_type in ('rst', 'vcc'):
        result = decode_line_event(raw_data, msg_type)
        errs = gsmtap_flag_names(flags)
        if errs:
            result['errors'] = errs
        return result
    if msg_type == 'fidi' and raw_data:
        return decode_fidi(raw_data)
    if msg_type == 'atr':
        result = _decode_atr(raw_data)
        if result is not None:
            errs = (decode_data_flags(flags) or []) + (gsmtap_flag_names(flags) or [])
            if errs:
                result['errors'] = errs
        return result
    if msg_type == 'pps':
        result = _decode_pps(raw_data)
        if result is not None:
            errs = (decode_data_flags(flags) or []) + (gsmtap_flag_names(flags) or [])
            if errs:
                result['errors'] = errs
        return result
    return None


def _decode_binary_offset(p1, p2):
    """Decode READ/UPDATE BINARY P1/P2 (TS 102 221 §11.1.3.2 Table 11.10).

    b8 of P1 = 0 → offset = b7..b1 of P1 << 8 | P2.
    b8 of P1 = 1 → SFI referencing: b5..b1 of P1 = SFI, P2 = offset.
    """
    raw = (p1 << 8) | p2
    if p1 & 0x80:
        return {'value': raw, 'sfi': p1 & 0x1F, 'offset': p2}
    return {'value': raw, 'offset': ((p1 & 0x7F) << 8) | p2}


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
