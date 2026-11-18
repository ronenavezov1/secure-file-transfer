import socket
import threading

import constants
import logger
from network.client_thread import ClientThread
from network.dispatcher import Dispatcher
from storage.repository import Repository

log = logger.get("server")


class ServerSocket(threading.Thread):
    # accepts connections, one thread per client; caps concurrent clients
    def __init__(self, host, port):
        super().__init__()
        self.bind_to = (host, port)
        self.go = True
        self.repository = Repository()
        self.dispatcher = Dispatcher(self.repository)
        self._slots = threading.Semaphore(constants.MAX_CONNECTIONS)

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(self.bind_to)
            server.listen()
            server.settimeout(1)   # so the loop can check self.go
            log.info("ready, listening on %s", self.bind_to)
            while self.go:
                try:
                    conn, addr = server.accept()
                except socket.timeout:
                    continue
                except OSError as e:
                    log.error("accept error: %s", e)
                    break

                if not self._slots.acquire(blocking=False):
                    log.warning("at capacity (%d), refusing %s", constants.MAX_CONNECTIONS, addr)
                    conn.close()
                    continue

                conn.settimeout(constants.CLIENT_TIMEOUT)   # drop idle clients
                log.info("client connected: %s", addr)
                worker = ClientThread(self.dispatcher, conn, on_finish=self._slots.release)
                worker.daemon = True
                worker.start()
        log.info("server socket closed")

    def stop(self):
        self.go = False
