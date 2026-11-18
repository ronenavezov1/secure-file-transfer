import datetime
import sqlite3
import uuid

import constants
from model import file_details
from model.user import User


def _fmt(dt):
    if dt is None:
        return None
    return dt.isoformat() if hasattr(dt, 'isoformat') else str(dt)


def _to_dt(value):
    if not value:
        return None
    try:
        return datetime.datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


def _connect():
    return sqlite3.connect(constants.DB_NAME, timeout=5)   # timeout so threads wait, not fail


def create_tables():
    try:
        conn = _connect()
        conn.execute('''CREATE TABLE IF NOT EXISTS clients (
                            id         BLOB(16) PRIMARY KEY,
                            name       TEXT,
                            public_key BLOB(160),
                            lastseen   TEXT,
                            aes        BLOB(32)
                        );''')
        conn.execute('''CREATE TABLE IF NOT EXISTS files (
                            id         BLOB(16),
                            file_name  TEXT,
                            file_path  TEXT,
                            verified   INTEGER,
                            PRIMARY KEY (id, file_name)
                        );''')
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print("DB error (create_tables):", e)


def get_all_users():
    users = {}
    try:
        conn = _connect()
        for row in conn.execute('SELECT id, name, public_key, lastseen, aes FROM clients'):
            token = uuid.UUID(bytes=row[0])
            users[token.hex] = User(token, row[1], row[2] or b'', _to_dt(row[3]), row[4] or b'')
        conn.close()
    except sqlite3.Error as e:
        print("DB error (get_all_users):", e)
    return users


def add_user(user):
    try:
        conn = _connect()
        conn.execute(
            'INSERT OR REPLACE INTO clients (id, name, public_key, lastseen, aes) VALUES (?,?,?,?,?)',
            (user.token.bytes, user.name, user.publicKey, _fmt(user.lastSeen), user.aes))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print("DB error (add_user):", e)


def update_user_keys(user):
    try:
        conn = _connect()
        conn.execute(
            'UPDATE clients SET public_key=?, aes=?, lastseen=? WHERE id=?',
            (user.publicKey, user.aes, _fmt(user.lastSeen), user.token.bytes))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print("DB error (update_user_keys):", e)


def update_last_seen(user):
    try:
        conn = _connect()
        conn.execute('UPDATE clients SET lastseen=? WHERE id=?',
                     (_fmt(user.lastSeen), user.token.bytes))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print("DB error (update_last_seen):", e)


def upsert_file(file):
    try:
        conn = _connect()
        conn.execute(
            'INSERT OR REPLACE INTO files (id, file_name, file_path, verified) VALUES (?,?,?,?)',
            (file.owner_token.bytes, file.file_name, file.file_path, 1 if file.verified else 0))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print("DB error (upsert_file):", e)


def set_file_verified(owner_token, file_name, verified):
    try:
        conn = _connect()
        conn.execute('UPDATE files SET verified=? WHERE id=? AND file_name=?',
                     (1 if verified else 0, owner_token.bytes, file_name))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print("DB error (set_file_verified):", e)


def get_file(owner_token, file_name):
    try:
        conn = _connect()
        cur = conn.execute(
            'SELECT id, file_name, file_path, verified FROM files WHERE id=? AND file_name=?',
            (owner_token.bytes, file_name))
        row = cur.fetchone()
        conn.close()
        if row is None:
            return None
        return file_details.File(uuid.UUID(bytes=row[0]), row[1], row[2], bool(row[3]))
    except sqlite3.Error as e:
        print("DB error (get_file):", e)
        return None
