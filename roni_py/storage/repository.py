import datetime
import os
import threading
import uuid

import constants
import logger
from model import file_details
from model.user import User
from storage import database

log = logger.get("repository")


class Repository:
    # the only stateful object: users (synced to sqlite), in-progress transfers, saved files
    def __init__(self):
        self._lock = threading.RLock()
        database.create_tables()
        self._users = database.get_all_users()
        self._transfers = {}
        log.debug("repository loaded with %d known client(s)", len(self._users))

    @staticmethod
    def _key(token):
        return token.hex if isinstance(token, uuid.UUID) else str(token)

    # users
    def get_user(self, token):
        with self._lock:
            return self._users.get(self._key(token))

    def get_user_by_name(self, name):
        with self._lock:
            return next((u for u in self._users.values() if u.name == name), None)

    def name_exists(self, name):
        return self.get_user_by_name(name) is not None

    def add_user(self, name):
        with self._lock:
            user = User(uuid.uuid4(), name, b'', datetime.datetime.now(), b'')
            self._users[user.token.hex] = user
            database.add_user(user)
        log.debug("registered '%s' as client %s", name, user.token.hex[:8])
        return user

    def set_user_keys(self, token, public_key, aes_key):
        with self._lock:
            user = self.get_user(token)
            if user is None:
                return None
            user.publicKey = public_key
            user.aes = aes_key
            user.lastSeen = datetime.datetime.now()
            database.update_user_keys(user)
        log.debug("stored public key and issued AES key for %s", logger.short_id(token))
        return user

    def set_user_aes(self, token, aes_key):
        with self._lock:
            user = self.get_user(token)
            if user is None:
                return None
            user.aes = aes_key
            user.lastSeen = datetime.datetime.now()
            database.update_user_keys(user)
        log.debug("issued a new AES key for %s (reconnect)", logger.short_id(token))
        return user

    def touch(self, token):
        with self._lock:
            user = self.get_user(token)
            if user is not None:
                user.lastSeen = datetime.datetime.now()
                database.update_last_seen(user)

    # file transfers
    def add_file_packet(self, token, file_name, packet_num, total_packets, chunk):
        key = (self._key(token), file_name)
        with self._lock:
            buf = self._transfers.get(key)
            if buf is None:
                buf = bytearray()
                self._transfers[key] = buf
            if len(buf) + len(chunk) > constants.MAX_FILE_SIZE:
                del self._transfers[key]
                raise ValueError("transfer exceeds MAX_FILE_SIZE")
            buf.extend(chunk)
            done = packet_num >= total_packets
            buffered = len(buf)
            if done:
                del self._transfers[key]
        log.debug("file '%s' packet %d/%d (%d bytes buffered)%s",
                  file_name, packet_num, total_packets, buffered,
                  " - complete" if done else "")
        return bytes(buf) if done else None

    def cancel_transfer(self, token, file_name):
        with self._lock:
            self._transfers.pop((self._key(token), file_name), None)

    # files
    def save_file(self, token, file_name, data, verified=False):
        folder = os.path.join(constants.FILES_FOLDER, self._key(token))
        os.makedirs(folder, exist_ok=True)
        safe_name = os.path.basename(file_name) or 'unnamed'   # avoid path traversal
        path = os.path.join(folder, safe_name)
        with open(path, 'wb') as f:
            f.write(data)
        owner = token if isinstance(token, uuid.UUID) else uuid.UUID(hex=self._key(token))
        with self._lock:
            database.upsert_file(file_details.File(owner, file_name, path, verified))
        log.debug("saved '%s' (%d bytes) -> %s", file_name, len(data), path)
        return path

    def set_file_verified(self, token, file_name, verified=True):
        owner = token if isinstance(token, uuid.UUID) else uuid.UUID(hex=self._key(token))
        with self._lock:
            database.set_file_verified(owner, file_name, verified)
        log.debug("file '%s' marked verified=%s", file_name, bool(verified))

    def get_file(self, token, file_name):
        owner = token if isinstance(token, uuid.UUID) else uuid.UUID(hex=self._key(token))
        return database.get_file(owner, file_name)
