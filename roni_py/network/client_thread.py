import threading

from protocol import utils


class ClientThread(threading.Thread):
    # one thread per client connection
    def __init__(self, dispatcher, conn, on_finish=None):
        super().__init__()
        self.dispatcher = dispatcher
        self.conn = conn
        self.on_finish = on_finish

    def run(self):
        try:
            with self.conn:
                while True:
                    request = utils.read_request(self.conn)
                    if request is None:
                        break
                    response = self.dispatcher.dispatch(request)
                    if response.skip:
                        continue
                    try:
                        self.conn.sendall(response.pack())
                    except OSError:
                        break
        finally:
            if self.on_finish is not None:
                self.on_finish()   # free the connection slot
