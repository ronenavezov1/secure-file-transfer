import constants
from protocol import utils
from servlets.base import Servlet


class CrcRetryServlet(Servlet):
    # 901: checksum failed, client will resend. no reply (1604 is only for 900/902)
    def handle(self, request, response):
        user = self.repository.get_user(request.client_uuid)
        if user is None or not user.aes:
            response.set(constants.RESP_GENERAL_ERROR)
            return
        file_name = utils.decode_name(request.body[:constants.FILE_NAME_SIZE])
        self.repository.cancel_transfer(user.token, file_name)
        response.no_response()
