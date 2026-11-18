import constants
from protocol import utils
from servlets.base import Servlet


class CrcOkServlet(Servlet):
    # 900 -> 1604: checksum matched, mark the file verified
    def handle(self, request, response):
        user = self.repository.get_user(request.client_uuid)
        if user is None or not user.aes:
            response.set(constants.RESP_GENERAL_ERROR)
            return
        file_name = utils.decode_name(request.body[:constants.FILE_NAME_SIZE])
        self.repository.set_file_verified(user.token, file_name, True)
        self.repository.touch(user.token)
        response.set(constants.RESP_MSG_ACK, user.token.bytes)
