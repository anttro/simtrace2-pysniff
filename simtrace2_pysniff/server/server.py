"""HTTP API server for simtrace-analyser PWA."""

import json
import os
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from .database import Database
from .capture import CaptureManager, GsmtapListener, DirectSniffer


class RequestHandler(BaseHTTPRequestHandler):
    db: Database = None
    capture: CaptureManager = None

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
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status, message):
        self._send_json({'error': message}, status)

    def _read_json(self):
        length = int(self.headers.get('Content-Length', 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length))

    def _parse_path(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')
        return path, parse_qs(parsed.query)

    # --- CORS preflight ---
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    # --- GET ---
    def do_GET(self):
        path, params = self._parse_path()

        if path == '/api/status':
            self._handle_status()
        elif path == '/api/sessions':
            self._handle_list_sessions()
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
            self._send_error(404, 'Not found')

    # --- POST ---
    def do_POST(self):
        path, _ = self._parse_path()

        if path == '/api/capture/start':
            self._handle_capture_start()
        elif path == '/api/capture/stop':
            self._handle_capture_stop()
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
        self._send_json({
            'server': 'simtrace-analyser-server',
            'capture_active': self.capture.active,
            'session_id': self.capture.session_id,
            'mode': active_session['mode'] if active_session else None,
            'messages_count': self.db.count_messages(self.capture.session_id) if self.capture.session_id else 0,
        })

    def _handle_list_sessions(self):
        sessions = self.db.list_sessions()
        self._send_json({'sessions': sessions})

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

    def _handle_capture_latest(self, params):
        after_id = int(params.get('after', [0])[0])
        if not self.capture.active:
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
            'active': self.capture.active,
            'session_id': self.capture.session_id,
        })

    def _handle_capture_start(self):
        if self.capture.active:
            self.capture.stop_session()
        session_id = self.capture.start_session()
        started = self.db.get_session(session_id)['started']
        self._send_json({'session_id': session_id, 'started': started})

    def _handle_capture_stop(self):
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

    def _handle_rename_session(self, session_id, name):
        self.db.rename_session(session_id, name)
        self._send_json({'ok': True})

    def _handle_delete_session(self, session_id):
        if self.capture.session_id == session_id:
            self.capture.stop_session()
        self.db.delete_session(session_id)
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
