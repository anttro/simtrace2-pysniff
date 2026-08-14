"""HTTP API + static PWA server for simtrace2-pysniff."""

import json
import os
import sys
import threading
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, quote

from .database import Database
from .capture import CaptureManager, GsmtapListener, DirectSniffer
from ..gsmtap import build_gsmtap_packet, GSMTAP_SIM_ATR, GSMTAP_SIM_APDU
from ..pcap import build_pcap, parse_pcap, parse_pcapng
from .. import __version__


# Static file serving (the PWA lives in <repo>/frontend, served by this server
# so the UI and the API share an origin and no CORS/PNA is involved).
_STATIC_MIME = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css',
    '.js': 'application/javascript',
    '.json': 'application/json',
    '.png': 'image/png',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.webmanifest': 'application/manifest+json',
    '.map': 'application/json',
    '.wasm': 'application/wasm',
}


def _content_disposition(filename):
    """RFC 6266/5987 Content-Disposition filename (ASCII fallback + UTF-8)."""
    fallback = filename.encode('ascii', 'replace').decode('ascii').replace('"', '_')
    return f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{quote(filename, safe='')}"


class RequestHandler(BaseHTTPRequestHandler):
    db: Database = None
    capture: CaptureManager = None
    capture_mode: str = 'gsmtap'

    def log_message(self, fmt, *args):
        print(f'[{self.log_date_time_string()}] {args[0]}', file=sys.stderr)

    def _send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Access-Control-Allow-Private-Network', 'true')
        self.end_headers()
        self.wfile.write(body)

    def _send_binary(self, data, content_type, filename):
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', len(data))
        self.send_header('Content-Disposition', _content_disposition(filename))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Private-Network', 'true')
        self.end_headers()
        self.wfile.write(data)

    def _send_error(self, status, message):
        self._send_json({'error': message}, status)

    def _read_json(self):
        length = int(self.headers.get('Content-Length', 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length))

    def _read_body(self):
        length = int(self.headers.get('Content-Length', 0))
        if length == 0:
            return b''
        return self.rfile.read(length)

    def _parse_path(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')
        return path, parse_qs(parsed.query)

    def _serve_static(self):
        web_dir = getattr(self.server, 'web_dir', None)
        if not web_dir:
            self._send_error(404, 'Not found')
            return
        rel = self.path.split('?', 1)[0].lstrip('/')
        if rel in ('', '/'):
            rel = 'index.html'
        if '..' in rel.split('/') or rel.startswith('/'):
            self._send_error(404, 'Not found')
            return
        fs_path = os.path.join(web_dir, rel)
        if not os.path.isfile(fs_path):
            self._send_error(404, 'Not found')
            return
        with open(fs_path, 'rb') as f:
            data = f.read()
        content_type = _STATIC_MIME.get(os.path.splitext(rel)[1].lower(), 'application/octet-stream')
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        if rel in ('index.html', 'sw.js'):
            self.send_header('Cache-Control', 'no-cache')
        self.end_headers()
        self.wfile.write(data)

    # --- CORS preflight ---
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Access-Control-Allow-Private-Network', 'true')
        self.end_headers()

    # --- GET ---
    def do_GET(self):
        path, params = self._parse_path()

        if path == '/api/status':
            self._handle_status()
        elif path == '/api/sessions':
            self._handle_list_sessions()
        elif path.startswith('/api/sessions/') and path.endswith('/pcap'):
            session_id = int(path.split('/')[-2])
            self._handle_get_session_pcap(session_id)
        elif path.startswith('/api/sessions/'):
            session_id = int(path.split('/')[-1])
            self._handle_get_session(session_id, params)
        elif path == '/api/capture/latest':
            self._handle_capture_latest(params)
        elif path == '/api/capture/status':
            self._handle_capture_status()
        elif path.startswith('/api/apdu/search'):
            session_id = int(params.get('session_id', [0])[0])
            query = params.get('q', [''])[0]
            self._handle_search(session_id, query)
        elif path.startswith('/api/apdu/filter'):
            session_id = int(params.get('session_id', [0])[0])
            msg_type = params.get('type', [''])[0]
            self._handle_filter(session_id, msg_type)
        elif path.startswith('/api/apdu/'):
            msg_id = int(path.split('/')[-1])
            self._handle_get_apdu(msg_id)
        else:
            self._serve_static()

    # --- POST ---
    def do_POST(self):
        path, params = self._parse_path()

        if path == '/api/capture/start':
            self._handle_capture_start()
        elif path == '/api/capture/stop':
            self._handle_capture_stop()
        elif path == '/api/sessions/import':
            self._handle_import_pcap(params)
        else:
            self._send_error(404, 'Not found')

    # --- PATCH ---
    def do_PATCH(self):
        path, _ = self._parse_path()

        if path.startswith('/api/sessions/') and path.endswith('/name'):
            session_id = int(path.split('/')[-2])
            body = self._read_json()
            self._handle_rename_session(session_id, body.get('name', ''))
        else:
            self._send_error(404, 'Not found')

    # --- DELETE ---
    def do_DELETE(self):
        path, _ = self._parse_path()

        if path.startswith('/api/sessions/'):
            session_id = int(path.split('/')[-1])
            self._handle_delete_session(session_id)
        else:
            self._send_error(404, 'Not found')

    # --- Handlers ---

    def _handle_status(self):
        active_session = self.db.get_active_session()
        capture = self.capture
        self._send_json({
            'server': 'simtrace-analyser-server',
            'version': __version__,
            'capture_mode': self.capture_mode,
            'capture_active': capture.active if capture else False,
            'session_id': capture.session_id if capture else None,
            'mode': active_session['mode'] if active_session else None,
            'messages_count': self.db.count_messages(capture.session_id) if capture and capture.session_id else 0,
        })

    def _handle_list_sessions(self):
        sessions = self.db.list_sessions()
        self._send_json({
            'sessions': sessions,
            'total_sessions': self.db.count_sessions(),
            'db_size': self.db.db_size(),
        })

    def _handle_get_session(self, session_id, params):
        session = self.db.get_session(session_id)
        if session is None:
            self._send_error(404, 'Session not found')
            return
        offset = int(params.get('offset', [0])[0])
        limit = int(params.get('limit', [200])[0])
        messages = self.db.get_messages(session_id, offset=offset, limit=limit)
        total = self.db.count_messages(session_id)
        type_counts = self.db.get_type_counts(session_id)
        self._send_json({
            'session': session,
            'messages': messages,
            'total': total,
            'type_counts': type_counts,
        })

    def _handle_get_session_pcap(self, session_id):
        session = self.db.get_session(session_id)
        if session is None:
            self._send_error(404, 'Session not found')
            return

        try:
            start_ts = datetime.fromisoformat(session['started']).timestamp()
        except (ValueError, TypeError):
            start_ts = time.time()

        packets = []
        for m in self.db.get_messages_raw(session_id):
            if m['type'] == 'atr':
                sub_type = GSMTAP_SIM_ATR
            elif m['type'] == 'tpdu':
                sub_type = GSMTAP_SIM_APDU
            else:
                continue
            gsmtap_hdr = build_gsmtap_packet(sub_type, b'')[:16]
            packets.append((gsmtap_hdr, m['data'], start_ts + m['elapsed']))

        pcap = build_pcap(packets)
        name = (session.get('name') or f'session-{session_id}') + '.pcap'
        self._send_binary(pcap, 'application/vnd.tcpdump.pcap', name)

    def _handle_capture_latest(self, params):
        after_id = int(params.get('after', [0])[0])
        if not self.capture or not self.capture.active:
            self._send_json({'messages': [], 'next_after': after_id, 'active': False})
            return
        msg_id = self.capture.latest_msg_id
        messages = self.db.get_messages_after(self.capture.session_id, after_id)
        self._send_json({
            'messages': messages,
            'next_after': msg_id,
            'active': True,
            'session_id': self.capture.session_id,
        })

    def _handle_capture_status(self):
        self._send_json({
            'active': self.capture.active if self.capture else False,
            'session_id': self.capture.session_id if self.capture else None,
        })

    def _handle_capture_start(self):
        if self.capture_mode == 'disabled' or self.capture is None:
            self._send_error(403, 'Capture disabled')
            return
        if self.capture.active:
            self.capture.stop_session()
        session_id = self.capture.start_session()
        started = self.db.get_session(session_id)['started']
        self._send_json({'session_id': session_id, 'started': started})

    def _handle_capture_stop(self):
        if self.capture_mode == 'disabled' or self.capture is None:
            self._send_error(403, 'Capture disabled')
            return
        if not self.capture.active:
            self._send_error(400, 'No active capture')
            return
        session_id = self.capture.stop_session()
        session = self.db.get_session(session_id)
        self._send_json({
            'session_id': session_id,
            'ended': session['ended'],
            'messages_count': self.db.count_messages(session_id),
        })

    def _handle_import_pcap(self, params):
        raw = self._read_body()
        name = (params.get('name', [''])[0]).strip()

        if not raw:
            self._send_error(400, 'Empty file')
            return

        if raw[:4] == b'\x0a\x0d\x0d\x0a':
            packets = list(parse_pcapng(raw))
        else:
            packets = list(parse_pcap(raw))

        if not packets:
            self._send_error(400, 'No GSMTAP data found in trace')
            return

        session_id = self.db.create_session('pcap')
        if name:
            self.db.rename_session(session_id, name)

        first_ts = packets[0][0]
        rows = []
        for ts, msg_type, payload in packets:
            elapsed = round(ts - first_ts, 6) if ts is not None else 0.0
            rows.append((max(0.0, elapsed), msg_type, payload, 0))
        self.db.insert_messages(session_id, rows)
        self.db.close_session(session_id)

        self._send_json({
            'session_id': session_id,
            'name': name,
            'message_count': len(packets),
        })

    def _handle_rename_session(self, session_id, name):
        self.db.rename_session(session_id, name)
        self._send_json({'ok': True})

    def _handle_delete_session(self, session_id):
        if self.capture and self.capture.session_id == session_id:
            self.capture.stop_session()
        self.db.delete_session(session_id)
        self.db.vacuum()
        self._send_json({'ok': True})

    def _handle_search(self, session_id, query):
        if not query:
            self._send_json({'messages': []})
            return
        messages = self.db.search_messages(session_id, query)
        self._send_json({'messages': messages})

    def _handle_filter(self, session_id, msg_type):
        if not msg_type:
            self._send_json({'messages': []})
            return
        messages = self.db.filter_messages(session_id, msg_type)
        self._send_json({'messages': messages})

    def _handle_get_apdu(self, msg_id):
        msg = self.db.get_message(msg_id)
        if msg is None:
            self._send_error(404, 'Message not found')
            return
        self._send_json(msg)
