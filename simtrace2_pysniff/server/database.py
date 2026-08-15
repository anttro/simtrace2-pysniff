"""SQLite database for session and APDU storage."""

import os
import sqlite3
import time
from contextlib import contextmanager

DEFAULT_DB_DIR = os.path.expanduser('~/.simtrace-analyser')
DEFAULT_DB_PATH = os.path.join(DEFAULT_DB_DIR, 'sessions.db')

# SW1 values that mean a SELECT succeeded (normal, warnings, response pending).
# Everything else (0x64-0x6F: execution/checking/security errors) leaves the
# current file unchanged.
_SUCCESS_SW1 = {'61', '62', '63', '90', '91', '92', '9e', '9f'}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    name     TEXT,
    started  TEXT NOT NULL,
    ended    TEXT,
    mode     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    elapsed    REAL NOT NULL,
    type       TEXT NOT NULL,
    data       BLOB NOT NULL,
    flags      INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id);
CREATE INDEX IF NOT EXISTS idx_messages_type ON messages(type);
CREATE INDEX IF NOT EXISTS idx_messages_elapsed ON messages(session_id, elapsed);
"""


def _iso_now():
    return time.strftime('%Y-%m-%dT%H:%M:%S.', time.localtime()) + \
        f'{time.time() % 1 * 1000:03.0f}'


def _iso_from_ts(ts):
    return time.strftime('%Y-%m-%dT%H:%M:%S.', time.localtime(ts)) + \
        f'{ts % 1 * 1000:03.0f}'


class Database:
    def __init__(self, db_path=None):
        if db_path is None:
            db_path = DEFAULT_DB_PATH
        self._db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute('PRAGMA journal_mode=WAL')
        self._conn.execute('PRAGMA foreign_keys=ON')
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # --- Sessions ---

    def create_session(self, mode):
        cur = self._conn.execute(
            'INSERT INTO sessions (started, mode) VALUES (?, ?)',
            (_iso_now(), mode))
        self._conn.commit()
        return cur.lastrowid

    def close_session(self, session_id):
        self._conn.execute(
            'UPDATE sessions SET ended=? WHERE id=? AND ended IS NULL',
            (_iso_now(), session_id))
        self._conn.commit()

    def set_session_times_from_ts(self, session_id, first_ts, last_ts):
        self._conn.execute(
            'UPDATE sessions SET started=?, ended=? WHERE id=?',
            (_iso_from_ts(first_ts), _iso_from_ts(last_ts), session_id))
        self._conn.commit()

    def rename_session(self, session_id, name):
        self._conn.execute(
            'UPDATE sessions SET name=? WHERE id=?',
            (name, session_id))
        self._conn.commit()

    def delete_session(self, session_id):
        self._conn.execute('DELETE FROM messages WHERE session_id=?', (session_id,))
        self._conn.execute('DELETE FROM sessions WHERE id=?', (session_id,))
        self._conn.commit()

    def count_sessions(self):
        row = self._conn.execute('SELECT COUNT(*) FROM sessions').fetchone()
        return row[0]

    def db_size(self):
        """Total on-disk size of the SQLite database (db + WAL + SHM)."""
        total = 0
        for suffix in ('', '-wal', '-shm'):
            p = self._db_path + suffix
            if os.path.exists(p):
                total += os.path.getsize(p)
        return total

    def vacuum(self):
        self._conn.execute('VACUUM')
        self._conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        self._conn.commit()

    def get_session(self, session_id):
        row = self._conn.execute(
            'SELECT id, name, started, ended, mode FROM sessions WHERE id=?',
            (session_id,)).fetchone()
        if row is None:
            return None
        return self._row_to_session(row)

    def list_sessions(self):
        rows = self._conn.execute("""
            SELECT s.id, s.name, s.started, s.ended, s.mode,
                   COUNT(m.id) AS msg_count
            FROM sessions s LEFT JOIN messages m ON m.session_id = s.id
            GROUP BY s.id
            ORDER BY s.started DESC
        """).fetchall()
        return [self._row_to_session(r) for r in rows]

    def get_active_session(self):
        row = self._conn.execute(
            'SELECT id, name, started, ended, mode FROM sessions WHERE ended IS NULL ORDER BY id DESC LIMIT 1'
        ).fetchone()
        if row is None:
            return None
        return self._row_to_session(row)

    def _row_to_session(self, row):
        d = {'id': row[0], 'name': row[1], 'started': row[2], 'ended': row[3], 'mode': row[4]}
        if len(row) > 5:
            d['message_count'] = row[5]
        return d

    # --- Messages ---

    def insert_message(self, session_id, elapsed, msg_type, data, flags=0):
        cur = self._conn.execute(
            'INSERT INTO messages (session_id, elapsed, type, data, flags) VALUES (?,?,?,?,?)',
            (session_id, elapsed, msg_type, data, flags))
        self._conn.commit()
        return cur.lastrowid

    def insert_messages(self, session_id, rows):
        """Bulk-insert messages; *rows* is an iterable of
        (elapsed, msg_type, data, flags) tuples.  Returns the last rowid."""
        self._conn.executemany(
            'INSERT INTO messages (session_id, elapsed, type, data, flags) VALUES (?,?,?,?,?)',
            [(session_id, elapsed, msg_type, data, flags) for elapsed, msg_type, data, flags in rows])
        self._conn.commit()

    def get_message(self, msg_id):
        row = self._conn.execute(
            'SELECT id, session_id, elapsed, type, data, flags FROM messages WHERE id=?',
            (msg_id,)).fetchone()
        if row is None:
            return None
        return self._row_to_message(row)

    def get_messages(self, session_id, offset=0, limit=200):
        rows = self._conn.execute(
            'SELECT id, session_id, elapsed, type, data, flags FROM messages '
            'WHERE session_id=? ORDER BY elapsed, id LIMIT ? OFFSET ?',
            (session_id, limit, offset)).fetchall()
        initial_prev = None
        if offset > 0 and rows:
            initial_prev = self._last_tpdu_context(session_id, rows[0][0]) or {}
            initial_prev['sel'] = self._last_selection(session_id, rows[0][0])
        return self._decode_rows(rows, initial_prev=initial_prev)

    def get_messages_after(self, session_id, after_id):
        rows = self._conn.execute(
            'SELECT id, session_id, elapsed, type, data, flags FROM messages '
            'WHERE session_id=? AND id > ? ORDER BY elapsed, id',
            (session_id, after_id)).fetchall()
        initial_prev = self._last_tpdu_context(session_id, after_id + 1) or {}
        initial_prev['sel'] = self._last_selection(session_id, after_id + 1)
        return self._decode_rows(rows, initial_prev=initial_prev)

    def get_messages_raw(self, session_id):
        rows = self._conn.execute(
            'SELECT elapsed, type, data FROM messages WHERE session_id=? ORDER BY elapsed, id',
            (session_id,)).fetchall()
        return [{'elapsed': r[0], 'type': r[1], 'data': r[2]} for r in rows]

    def count_messages(self, session_id):
        row = self._conn.execute(
            'SELECT COUNT(*) FROM messages WHERE session_id=?',
            (session_id,)).fetchone()
        return row[0]

    def search_messages(self, session_id, query):
        hex_q = ''.join(c for c in query if c in '0123456789abcdefABCDEF')
        if not hex_q:
            return []
        rows = self._conn.execute(
            "SELECT id, session_id, elapsed, type, data, flags FROM messages "
            "WHERE session_id=? AND hex(data) LIKE ? ORDER BY elapsed, id",
            (session_id, f'%{hex_q.lower()}%')).fetchall()
        return [self._row_to_message(r) for r in rows]

    def filter_messages(self, session_id, msg_type):
        rows = self._conn.execute(
            'SELECT id, session_id, elapsed, type, data, flags FROM messages '
            'WHERE session_id=? AND type=? ORDER BY elapsed, id',
            (session_id, msg_type)).fetchall()
        return [self._row_to_message(r) for r in rows]

    def get_type_counts(self, session_id):
        rows = self._conn.execute(
            'SELECT type, COUNT(*) FROM messages WHERE session_id=? GROUP BY type ORDER BY COUNT(*) DESC',
            (session_id,)).fetchall()
        return [{'type': r[0], 'count': r[1]} for r in rows]

    def _row_to_message(self, row, prev=None):
        data_blob = row[4]
        flags = row[5]
        msg = {
            'id': row[0],
            'session_id': row[1],
            'elapsed': row[2],
            'type': row[3],
            'data': data_blob.hex(),
            'flags': flags,
        }
        if row[3] in ('tpdu', 'change', 'fidi', 'atr', 'pps'):
            try:
                from .decode import decode_sniff_msg
                msg['decoded'] = decode_sniff_msg(data_blob, row[3], flags, prev=prev)
            except Exception as e:
                import sys
                print(f'Decode error for msg {row[0]} ({row[3]}, {len(data_blob)} bytes): {e}',
                      file=sys.stderr)
        return msg

    def _last_tpdu_context(self, session_id, before_id):
        """Return previous-command context from the last TPDU with id < before_id."""
        row = self._conn.execute(
            "SELECT data FROM messages WHERE session_id=? AND id < ? AND type='tpdu' "
            "ORDER BY id DESC LIMIT 1", (session_id, before_id)).fetchone()
        if row is None:
            return None
        from .decode import decode_sniff_msg
        d = decode_sniff_msg(row[0], 'tpdu', 0)
        if not d:
            return None
        return self._context_from_decoded(d)

    def _last_selection(self, session_id, before_id):
        """Replay (bounded, backwards) to find the current selection.

        Scans back from *before_id* to the last file-defining event:
        an ATR/card-change resets selection; a SELECT sets it.
        """
        from .decode import decode_sniff_msg, select_target_fid, KNOWN_FIDS
        rows = self._conn.execute(
            "SELECT data, type FROM messages WHERE session_id=? AND id < ? "
            "AND type IN ('tpdu','atr','change') ORDER BY id DESC LIMIT 500",
            (session_id, before_id)).fetchall()
        for data, typ in rows:
            if typ in ('atr', 'change'):
                return None
            d = decode_sniff_msg(data, 'tpdu', 0)
            if d and d.get('ins_hex') == 'a4':
                fid = select_target_fid(d)
                if fid:
                    return {'fid': fid, 'name': KNOWN_FIDS.get(fid)}
                if (d.get('p1') or {}).get('raw') in ('03', '04'):
                    return None
        return None

    def _context_from_decoded(self, d):
        ins_hex = d.get('ins_hex')
        ins = int(ins_hex, 16) if ins_hex else None
        file_ok = False
        if ins in (0xB2, 0xDC, 0xA2):
            file_ok = True
        elif ins in (0xB0, 0xD6):
            file_ok = (d.get('p1p2') or {}).get('value', 0) == 0
        return {
            'ins': ins,
            'ins_name': d.get('ins_name'),
            'sw1': (d.get('sw') or {}).get('sw1'),
            'file_ok': file_ok,
        }

    def _selection_after(self, d, sel):
        ins_hex = d.get('ins_hex')
        if ins_hex == 'a4':
            from .decode import select_target_fid, KNOWN_FIDS
            sw1 = (d.get('sw') or {}).get('sw1')
            # Only a successful SELECT changes the current file.  On an error
            # status word (e.g. 6A82 file-not-found) the file is unchanged.
            if sw1 not in _SUCCESS_SW1:
                return sel
            fid = select_target_fid(d)
            if fid:
                return {'fid': fid, 'name': KNOWN_FIDS.get(fid), 'structure': None}
            if (d.get('p1') or {}).get('raw') in ('03', '04'):
                return None
        elif ins_hex == 'c0' and d.get('response_for') == 'SELECT' and sel:
            # GET RESPONSE carrying the FCP of the last SELECT → capture the
            # file structure so we can sanity-check record operations.
            fd = (d.get('response') or {}).get('file_descriptor')
            if fd:
                new = dict(sel)
                new['structure'] = fd.get('structure')
                return new
        return sel

    def _decode_rows(self, rows, initial_prev=None):
        msgs = []
        prev = initial_prev
        sel = (initial_prev or {}).get('sel')
        for row in rows:
            ctx = dict(prev) if prev else {}
            ctx['sel'] = sel
            msg = self._row_to_message(row, prev=ctx)
            d = msg.get('decoded')
            if msg['type'] == 'tpdu' and d and d.get('ins_hex'):
                sel = self._selection_after(d, sel)
                prev = self._context_from_decoded(d)
            elif msg['type'] in ('atr', 'change'):
                sel = None
                prev = None
            msgs.append(msg)
        return msgs
