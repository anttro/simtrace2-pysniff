"""simtrace2-pysniff-server — CLI entry point.

Usage:
    simtrace2-pysniff-server --capture gsmtap [--gsmtap-port 4729] [--port 8081]
    simtrace2-pysniff-server --capture direct [--port 8081]
"""

import argparse
import sys
from http.server import HTTPServer

from .server import RequestHandler
from .database import Database, DEFAULT_DB_PATH
from .capture import CaptureManager, GsmtapListener, DirectSniffer


def main():
    p = argparse.ArgumentParser(
        prog='simtrace2-pysniff-server',
        description='HTTP API server for SIMtrace2 APDU capture and analysis')
    p.add_argument('--port', type=int, default=8081,
                   help='HTTP server port (default: 8081)')
    p.add_argument('--db', default=DEFAULT_DB_PATH,
                   help=f'SQLite database path (default: {DEFAULT_DB_PATH})')
    p.add_argument('--capture', choices=['gsmtap', 'direct'], default='gsmtap',
                   help='Capture mode: gsmtap (listen UDP 4729) or direct (SIMtrace2 USB)')
    p.add_argument('--gsmtap-port', type=int, default=4729,
                   help='UDP port for GSMTAP listener (default: 4729)')
    args = p.parse_args()

    db = Database(args.db)

    if args.capture == 'gsmtap':
        backend = GsmtapListener(bind_port=args.gsmtap_port)
    else:
        backend = DirectSniffer()

    capture = CaptureManager(backend, db)

    RequestHandler.db = db
    RequestHandler.capture = capture

    server = HTTPServer(('127.0.0.1', args.port), RequestHandler)

    print(f'simtrace2-pysniff-server — http://127.0.0.1:{args.port}', file=sys.stderr)
    print(f'  capture mode: {args.capture}', file=sys.stderr)
    if args.capture == 'gsmtap':
        print(f'  GSMTAP port:  {args.gsmtap_port}', file=sys.stderr)
    print(f'  database:     {args.db}', file=sys.stderr)
    print(file=sys.stderr)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if capture.active:
            capture.stop_session()
        server.server_close()


if __name__ == '__main__':
    main()
