import constants
import logger
from protocol.response import Response
from servlets.crc_abort import CrcAbortServlet
from servlets.crc_ok import CrcOkServlet
from servlets.crc_retry import CrcRetryServlet
from servlets.public_key import PublicKeyServlet
from servlets.reconnect import ReconnectServlet
from servlets.register import RegisterServlet
from servlets.send_file import SendFileServlet

log = logger.get("dispatcher")


class Dispatcher:
    # maps a request code to its servlet
    def __init__(self, repository):
        self.repository = repository
        self._servlets = {}
        self._register_servlets()

    def register(self, code, servlet):
        self._servlets[code] = servlet

    def _register_servlets(self):
        self.register(constants.REQ_REGISTER, RegisterServlet(self.repository))
        self.register(constants.REQ_SEND_PUBLIC_KEY, PublicKeyServlet(self.repository))
        self.register(constants.REQ_RECONNECT, ReconnectServlet(self.repository))
        self.register(constants.REQ_SEND_FILE, SendFileServlet(self.repository))
        self.register(constants.REQ_CRC_OK, CrcOkServlet(self.repository))
        self.register(constants.REQ_CRC_INVALID_RETRY, CrcRetryServlet(self.repository))
        self.register(constants.REQ_CRC_INVALID_ABORT, CrcAbortServlet(self.repository))

    def dispatch(self, request):
        log.debug("<- %s  client=%s  payload=%dB",
                  logger.code_name(request.operation),
                  logger.short_id(request.client_uuid), request.size)

        response = Response()
        servlet = self._servlets.get(request.operation)
        if servlet is None:
            log.warning("no servlet for code %s", request.operation)
            response.set(constants.RESP_GENERAL_ERROR)
            return response
        try:
            servlet.handle(request, response)
        except Exception as e:              # one bad request must not kill the thread
            log.error("servlet error on %s: %s", logger.code_name(request.operation), e)
            response.skip = False
            response.set(constants.RESP_GENERAL_ERROR)
            return response
        if not response.skip and response.code is None:
            response.set(constants.RESP_GENERAL_ERROR)

        if response.skip:
            log.debug("-> (no response)")
        else:
            log.debug("-> %s  payload=%dB", logger.code_name(response.code), response.size)
        return response
