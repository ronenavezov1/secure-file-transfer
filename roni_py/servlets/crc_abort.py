import constants
from protocol import utils
from servlets.base import Servlet


class CrcAbortServlet(Servlet):
    # 902 -> 1604: client gave up; file stays unverified
    def handle(self, request, response):
        user = self.repository.get_user(request.client_uuid)
        if user is None or not user.aes:
            response.set(constants.RESP_GENERAL_ERROR)
            return
        file_name = utils.decode_name(request.body[:constants.FILE_NAME_SIZE])
        self.repository.cancel_transfer(user.token, file_name)
        self.repository.touch(user.token)
        response.set(constants.RESP_MSG_ACK, user.token.bytes)
