import socket
import uuid

import constants
from protocol.request import Request


def read_exact(sock, n):
    # loop until n bytes arrive; None if the socket closed or timed out
    if n == 0:
        return b''
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except OSError:
            return None
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def read_request(sock):
    header = read_exact(sock, constants.REQUEST_HEADER_SIZE)
    if header is None:
        return None
    client_uuid = uuid.UUID(bytes=header[0:16])
    version = header[16]
    operation = int.from_bytes(header[17:19], byteorder='little')
    size = int.from_bytes(header[19:23], byteorder='little')
    if size > constants.MAX_REQUEST_SIZE:
        return None                     # too big, drop the connection
    body = read_exact(sock, size)
    if body is None:
        return None
    return Request(client_uuid, version, operation, size, body)


# names are a 255-byte null-terminated ascii field
def decode_name(raw):
    return raw.split(b'\x00', 1)[0].decode('ascii', errors='ignore')


def encode_name(name):
    raw = name.encode('ascii', errors='ignore')[:constants.NAME_SIZE]
    return raw.ljust(constants.NAME_SIZE, b'\x00')


# crc matching the linux `cksum` command (not binascii.crc32)
def _build_table():
    table = []
    for i in range(256):
        c = i << 24
        for _ in range(8):
            if c & 0x80000000:
                c = ((c << 1) ^ 0x04C11DB7) & 0xFFFFFFFF
            else:
                c = (c << 1) & 0xFFFFFFFF
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
