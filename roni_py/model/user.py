import uuid
from datetime import datetime


class User:
    def __init__(self, token, name, publicKey=b'', lastSeen=None, aes=b''):
        self.token = token
        self.name = name
        self.publicKey = publicKey
        self.lastSeen = lastSeen
        self.aes = aes
