from uuid import UUID


class Request:
    def __init__(self, client_uuid: UUID, version: int, operation: int, size: int, body: bytes = b''):
        self.client_uuid = client_uuid
        self.version = version
        self.operation = operation
        self.size = size
        self.body = body
