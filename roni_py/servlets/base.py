from abc import ABC, abstractmethod

from protocol.request import Request
from protocol.response import Response


class Servlet(ABC):
    # base for the per-code handlers; stateless, works through the repository
    def __init__(self, repository):
        self.repository = repository

    @abstractmethod
    def handle(self, request: Request, response: Response) -> None:
        raise NotImplementedError
