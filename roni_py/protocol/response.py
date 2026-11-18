import constants


class Response:
    def __init__(self, code: int = None, body: bytes = b'', version: int = constants.VERSION):
        self.code = code
        self.version = version
        self.body = body if body is not None else b''
        self.skip = False   # True = don't send a reply (e.g. 901)

    def set(self, code: int, body: bytes = b''):
        self.code = code
        self.body = body if body is not None else b''

    def no_response(self):
        self.skip = True

    @property
    def size(self) -> int:
        return len(self.body)

    def pack(self) -> bytes:
        return (self.version.to_bytes(constants.VERSION_SIZE, byteorder='little')
                + self.code.to_bytes(constants.CODE_SIZE, byteorder='little')
                + self.size.to_bytes(constants.PAYLOAD_SIZE_SIZE, byteorder='little')
                + self.body)
