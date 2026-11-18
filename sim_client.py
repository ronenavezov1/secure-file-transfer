"""Simulated client for the Maman-06 server.

Exercises every service the server offers, over the real wire protocol:
  825 register            -> 1600 register-ok / 1601 register-fail
  826 send public key     -> 1602 encrypted AES key
  828 send file (packets) -> 1603 file-ok + cksum, then 900/901/902
  827 reconnect           -> 1605 new AES key / 1606 rejected

It is standalone: it talks to the server over a socket and does NOT import the
server code. The only dependency is pycryptodome.

The public-key field is 160 bytes. This client sends the RSA public key as a
PKCS#1 DER (140 bytes) padded to 160, which the server imports as-is, so it works
against the server with no changes. (PyCryptodome's X.509 export is 162 bytes and
would not fit the field; the real C++ CryptoPP client sends its own 160-byte key.)

Usage:
    python sim_client.py [host] [port] [name] [file]
Defaults: 127.0.0.1 1234 SimClient  (a ~20 KB sample file is generated).
"""
import os
import socket
import struct
import sys

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad

# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 1234
CLIENT_NAME = "SimClient"

VERSION = 3
PUBLIC_KEY_SIZE = 160          # protocol field size; the key is padded to this
NAME_SIZE = 255
FILE_NAME_SIZE = 255
PACKET_SIZE = 8192             # split the encrypted file into packets of this size
ZERO_IV = bytes(16)           # protocol fixes the AES-CBC IV to all zeros
MAX_CRC_ATTEMPTS = 4          # 1 try + up to 3 retries

# request codes
REQ_REGISTER = 825
REQ_SEND_PUBLIC_KEY = 826
REQ_RECONNECT = 827
REQ_SEND_FILE = 828
REQ_CRC_OK = 900
REQ_CRC_INVALID_RETRY = 901
REQ_CRC_INVALID_ABORT = 902

# response codes
RESP_REGISTER_OK = 1600
RESP_REGISTER_FAIL = 1601
RESP_PUBLIC_KEY_RECEIVED = 1602
RESP_FILE_OK_CRC = 1603
RESP_MSG_ACK = 1604
RESP_RECONNECT_OK = 1605
RESP_RECONNECT_REJECT = 1606
RESP_GENERAL_ERROR = 1607


# ---------------------------------------------------------------------------
# CRC-32 identical to the Linux `cksum` command (must match the server)
# ---------------------------------------------------------------------------
def _build_table():
    table = []
    for i in range(256):
        c = i << 24
        for _ in range(8):
            c = ((c << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if c & 0x80000000 else (c << 1) & 0xFFFFFFFF
        table.append(c)
    return table


_CRC_TABLE = _build_table()


def cksum(data):
    crc = 0
    for b in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ _CRC_TABLE[((crc >> 24) ^ b) & 0xFF]
    length = len(data)
    while length:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ _CRC_TABLE[((crc >> 24) ^ (length & 0xFF)) & 0xFF]
        length >>= 8
    return (~crc) & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def name_field(name):
    return name.encode("ascii", "ignore")[:NAME_SIZE].ljust(NAME_SIZE, b"\x00")


# Build the RSA public key as a PKCS#1 DER (140 bytes for RSA-1024) so it fits
# the 160-byte field; the server's import_key parses it after dropping padding.
def _der_len(n):
    if n < 0x80:
        return bytes([n])
    out = bytearray()
    while n:
        out.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)


def _der_int(value):
    b = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + _der_len(len(b)) + b


def public_key_field(rsa):
    body = _der_int(rsa.n) + _der_int(rsa.e)
    der = b"\x30" + _der_len(len(body)) + body
    return der.ljust(PUBLIC_KEY_SIZE, b"\x00")[:PUBLIC_KEY_SIZE]


def recv_all(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("server closed the connection")
        buf.extend(chunk)
    return bytes(buf)


class SimClient:
    def __init__(self, host, port, name):
        self.host = host
        self.port = port
        self.name = name
        self.client_id = bytes(16)   # zeros until we register
        self.aes_key = None
        self.rsa = None
        self.sock = None

    # -- connection ----------------------------------------------------------
    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def _send(self, code, payload=b""):
        header = self.client_id + bytes([VERSION]) + struct.pack("<H", code) + struct.pack("<I", len(payload))
        self.sock.sendall(header + payload)

    def _recv(self):
        header = recv_all(self.sock, 7)
        version = header[0]
        code = struct.unpack("<H", header[1:3])[0]
        size = struct.unpack("<I", header[3:7])[0]
        payload = recv_all(self.sock, size) if size else b""
        return code, payload

    # -- 825 register --------------------------------------------------------
    def register(self):
        print(f"[register]   -> 825  name={self.name}")
        self._send(REQ_REGISTER, name_field(self.name))
        code, payload = self._recv()
        if code == RESP_REGISTER_FAIL:
            print("[register]   <- 1601 name already taken")
            return False
        if code != RESP_REGISTER_OK:
            print(f"[register]   <- {code} unexpected")
            return False
        self.client_id = payload[:16]
        print(f"[register]   <- 1600 registered, id={self.client_id.hex()[:8]}...")
        return True

    # -- 826 public key ------------------------------------------------------
    def send_public_key(self):
        self.rsa = RSA.generate(1024)
        pub = public_key_field(self.rsa)
        print("[pubkey]     -> 826  sending RSA public key")
        self._send(REQ_SEND_PUBLIC_KEY, name_field(self.name) + pub)
        code, payload = self._recv()
        if code != RESP_PUBLIC_KEY_RECEIVED:
            print(f"[pubkey]     <- {code} unexpected")
            return False
        self.aes_key = PKCS1_OAEP.new(self.rsa).decrypt(payload[16:])
        print(f"[pubkey]     <- 1602 got encrypted AES key, decrypted ({len(self.aes_key)} bytes)")
        return True

    # -- 828 send file (+ 900/901/902) --------------------------------------
    def send_file(self, file_name, data):
        my_crc = cksum(data)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=ZERO_IV)
        ciphertext = cipher.encrypt(pad(data, 16))
        total = max(1, (len(ciphertext) + PACKET_SIZE - 1) // PACKET_SIZE)

        for attempt in range(1, MAX_CRC_ATTEMPTS + 1):
            print(f"[file]       -> 828  '{file_name}' {len(data)} bytes in {total} packet(s) (attempt {attempt})")
            for i in range(total):
                chunk = ciphertext[i * PACKET_SIZE:(i + 1) * PACKET_SIZE]
                meta = (struct.pack("<I", len(ciphertext)) + struct.pack("<I", len(data))
                        + struct.pack("<H", i + 1) + struct.pack("<H", total) + name_field(file_name))
                self._send(REQ_SEND_FILE, meta + chunk)

            code, payload = self._recv()          # server replies only after the last packet
            if code != RESP_FILE_OK_CRC:
                print(f"[file]       <- {code} unexpected")
                return False
            server_crc = struct.unpack("<I", payload[16 + 4 + FILE_NAME_SIZE:16 + 4 + FILE_NAME_SIZE + 4])[0]
            match = server_crc == my_crc
            print(f"[file]       <- 1603 server cksum={server_crc}  (mine={my_crc})  {'MATCH' if match else 'MISMATCH'}")

            if match:
                print("[file]       -> 900  crc ok")
                self._send(REQ_CRC_OK, name_field(file_name))
                code, _ = self._recv()
                print(f"[file]       <- {code} ack" if code == RESP_MSG_ACK else f"[file]       <- {code}")
                return True

            if attempt < MAX_CRC_ATTEMPTS:
                print("[file]       -> 901  crc mismatch, resending")
                self._send(REQ_CRC_INVALID_RETRY, name_field(file_name))   # server sends no reply
            else:
                print("[file]       -> 902  giving up after retries")
                self._send(REQ_CRC_INVALID_ABORT, name_field(file_name))
                code, _ = self._recv()
                print(f"[file]       <- {code} ack")
                return False

    # -- 827 reconnect -------------------------------------------------------
    def reconnect(self):
        print(f"[reconnect]  -> 827  name={self.name}")
        self._send(REQ_RECONNECT, name_field(self.name))
        code, payload = self._recv()
        if code == RESP_RECONNECT_OK:
            self.aes_key = PKCS1_OAEP.new(self.rsa).decrypt(payload[16:])
            print(f"[reconnect]  <- 1605 reconnected, new AES key ({len(self.aes_key)} bytes)")
            return True
        if code == RESP_RECONNECT_REJECT:
            print("[reconnect]  <- 1606 rejected (need to register again)")
            return False
        print(f"[reconnect]  <- {code} unexpected")
        return False


def run_all(host, port, name, file_name, data):
    print(f"=== simulated client -> {host}:{port} ===")
    c = SimClient(host, port, name)

    # first session: register, exchange keys, send a file
    c.connect()
    if not c.register():
        c.close()
        return
    if not c.send_public_key():
        print("[abort] key exchange failed, stopping")
        c.close()
        return
    c.send_file(file_name, data)
    c.close()

    # second session: reconnect (server issues a fresh AES key) and send again
    print("--- new session ---")
    c.connect()
    if c.reconnect():
        c.send_file(file_name, data)
    c.close()
    print("=== done ===")


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else SERVER_HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else SERVER_PORT
    name = sys.argv[3] if len(sys.argv) > 3 else CLIENT_NAME

    if len(sys.argv) > 4:
        file_name = os.path.basename(sys.argv[4])
        with open(sys.argv[4], "rb") as f:
            data = f.read()
    else:
        file_name = "sample.txt"
        data = ("Maman 06 sample file for the simulated client.\n" * 400).encode("ascii")

    run_all(host, port, name, file_name, data)


if __name__ == "__main__":
    main()
