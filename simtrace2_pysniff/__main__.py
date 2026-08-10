"""simtrace2-pysniff — CLI entry point.

Usage: python -m simtrace2_pysniff [options]
"""

import argparse
import signal
import sys
import time

from . import (
    SniffSession,
    DeviceDisconnected,
    GsmtapSender,
    PcapWriter,
    FileDumper,
    format_message,
    __version__,
)
from .gsmtap import build_gsmtap_packet, GSMTAP_SIM_ATR, GSMTAP_SIM_APDU


def parse_gsmtap_addr(value):
    parts = value.rsplit(':', 1)
    host = parts[0]
    port = 4729
    if len(parts) == 2:
        try:
            port = int(parts[1])
        except ValueError:
            raise argparse.ArgumentTypeError(
                f'Invalid GSMTAP port: {parts[1]}')
    return host, port


def build_parser():
    p = argparse.ArgumentParser(
        prog='simtrace2-pysniff',
        description='Python-based SIMtrace2 sniffer with GSMTAP/PCAP output',
    )
    p.add_argument('--version', action='version',
                   version=f'simtrace2-pysniff {__version__}')
    p.add_argument('--gsmtap', type=parse_gsmtap_addr, metavar='HOST[:PORT]',
                   help='Send ATR/TPDU as GSMTAP over UDP (default port 4729)')
    p.add_argument('--pcap', metavar='FILE',
                   help='Write sniffed data to PCAP file for Wireshark')
    p.add_argument('--output', '-o', metavar='FILE',
                   help='Write hex dump to file')
    p.add_argument('--no-stdout', action='store_true',
                   help='Suppress hex dump to stdout')
    p.add_argument('--vendor', type=lambda x: int(x, 16),
                   default=0x1d50, metavar='HEX',
                   help='USB vendor ID (default: 0x1d50)')
    p.add_argument('--product', type=lambda x: int(x, 16),
                   default=None, metavar='HEX',
                   help='USB product ID (default: auto-detect)')

    rec = p.add_argument_group('recovery options')
    rec.add_argument('--no-reconnect', action='store_true',
                     help='Exit on USB disconnect instead of reconnecting')
    rec.add_argument('--reconnect-delay-min', type=float, default=1.0,
                     metavar='SECONDS',
                     help='Initial reconnect delay (default: 1.0)')
    rec.add_argument('--reconnect-delay-max', type=float, default=30.0,
                     metavar='SECONDS',
                     help='Maximum reconnect delay (default: 30.0)')
    rec.add_argument('--backoff-factor', type=float, default=1.5,
                     metavar='N',
                     help='Exponential backoff multiplier (default: 1.5)')
    rec.add_argument('--inactivity-timeout', type=float, default=0.0,
                     metavar='SECONDS',
                     help='Reconnect after N seconds of silence (default: disabled)')
    return p


def print_banner():
    print('simtrace2-pysniff — Phone-SIM card communication sniffer\n'
          f'Version {__version__} — Python-based replacement for simtrace2-sniff\n',
          file=sys.stderr)
    print('Entering main loop', file=sys.stderr)


def main():
    parser = build_parser()
    args = parser.parse_args()

    print_banner()

    gsmtap = None
    if args.gsmtap:
        host, port = args.gsmtap
        gsmtap = GsmtapSender(host, port)
        print(f'GSMTAP output: {host}:{port}', file=sys.stderr)

    pcap = None
    if args.pcap:
        pcap = PcapWriter(args.pcap)
        print(f'PCAP output: {args.pcap}', file=sys.stderr)

    file_dumper = None
    if args.output:
        file_dumper = FileDumper(args.output)
        print(f'File output: {args.output}', file=sys.stderr)

    session = SniffSession(
        reconnect=not args.no_reconnect,
        reconnect_delay_min=args.reconnect_delay_min,
        reconnect_delay_max=args.reconnect_delay_max,
        backoff_factor=args.backoff_factor,
        inactivity_timeout=args.inactivity_timeout,
    )

    exiting = False

    def on_signal(signum, frame):
        nonlocal exiting
        if exiting:
            raise SystemExit(1)
        exiting = True
        print('\nShutting down...', file=sys.stderr)
        session.close()
        if gsmtap:
            gsmtap.close()
        if pcap:
            pcap.close()
        if file_dumper:
            file_dumper.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    try:
        for msg in session.iter_messages():
            if not args.no_stdout:
                print(format_message(msg))

            if file_dumper is not None:
                file_dumper.write(msg)

            if gsmtap is not None and msg.type in ('atr', 'tpdu'):
                if msg.type == 'atr':
                    gsmtap.send_atr(msg.data, msg.slot_nr)
                else:
                    gsmtap.send_apdu(msg.data, msg.slot_nr)

            if pcap is not None:
                sub_type = GSMTAP_SIM_ATR if msg.type == 'atr' else GSMTAP_SIM_APDU
                gsmtap_hdr = build_gsmtap_packet(sub_type, b'')[:16]
                pcap.write_packet(gsmtap_hdr, msg.data, msg.timestamp)

    except DeviceDisconnected as e:
        print(f'Device disconnected: {e}', file=sys.stderr)
    except KeyboardInterrupt:
        pass
    finally:
        session.close()
        if gsmtap:
            gsmtap.close()
        if pcap:
            pcap.close()
        if file_dumper:
            file_dumper.close()


if __name__ == '__main__':
    main()
