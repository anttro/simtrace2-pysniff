"""simtrace2-pysniff-server — CLI entry point.

Usage:
    simtrace2-pysniff-server --capture gsmtap [--gsmtap-port 4729] [--port 8081]
    simtrace2-pysniff-server --capture direct [--port 8081]
"""

import argparse
import os
import sys
from http.server import HTTPServer

from .server import RequestHandler
from .database import Database, DEFAULT_DB_PATH
from .capture import CaptureManager, GsmtapListener, DirectSniffer
from .. import __version__


def _default_web_dir():
    # <repo>/frontend, whether run from source or an editable install.
    # __file__ is <repo>/simtrace2_pysniff/server/__main__.py → up three levels.
    return os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'frontend')


def main():
    p = argparse.ArgumentParser(
        prog='simtrace2-pysniff-server',
        description='HTTP API + PWA server for SIMtrace2 APDU capture and analysis')
    p.add_argument('--host', default='127.0.0.1',
                   help='HTTP bind address (default: 127.0.0.1)')
    p.add_argument('--port', type=int, default=8081,
                   help='HTTP server port (default: 8081)')
    p.add_argument('--db', default=DEFAULT_DB_PATH,
                   help=f'SQLite database path (default: {DEFAULT_DB_PATH})')
    p.add_argument('--capture', choices=['gsmtap', 'direct', 'disabled'], default='gsmtap',
                   help='Capture mode: gsmtap (listen UDP 4729), direct (SIMtrace2 USB), or disabled (no capture)')
    p.add_argument('--gsmtap-port', type=int, default=4729,
                    help='UDP port for GSMTAP listener (default: 4729)')
    p.add_argument('--log-interval', type=float, default=60.0,
                    help='Seconds between capture liveness heartbeat logs '
                         '(default: 60.0)')
    p.add_argument('--log-requests', action='store_true', default=False,
                   help='Log every HTTP request (off by default)')
    p.add_argument('--web-dir', default=_default_web_dir(), metavar='PATH',
                   help='Directory with the simtrace-analyser PWA static files to serve (default: <repo>/frontend)')
    args = p.parse_args()

    db = Database(args.db)

    capture = None
    if args.capture == 'gsmtap':
        backend = GsmtapListener(bind_port=args.gsmtap_port)
        capture = CaptureManager(backend, db, log_interval=args.log_interval)
    elif args.capture == 'direct':
        backend = DirectSniffer()
        capture = CaptureManager(backend, db, log_interval=args.log_interval)

    RequestHandler.db = db
    RequestHandler.capture = capture
    RequestHandler.capture_mode = args.capture
    RequestHandler.log_requests = args.log_requests

    server = HTTPServer((args.host, args.port), RequestHandler)
    server.web_dir = args.web_dir

    print(f'simtrace2-pysniff-server v{__version__} — http://{args.host}:{args.port}', file=sys.stderr)
    print(f'  capture mode: {args.capture}', file=sys.stderr)
    if args.capture == 'gsmtap':
        print(f'  GSMTAP port:  {args.gsmtap_port}', file=sys.stderr)
    print(f'  database:     {args.db}', file=sys.stderr)
    print(f'  PWA served at http://{args.host}:{args.port}/', file=sys.stderr)
    print(file=sys.stderr)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if capture and capture.active:
            capture.stop_session()
        server.server_close()


if __name__ == '__main__':
    main()
