import constants
from protocol import utils
from servlets.base import Servlet


class RegisterServlet(Servlet):
    # 825 -> 1600 / 1601
    def handle(self, request, response):
        name = utils.decode_name(request.body[:constants.NAME_SIZE])
        if self.repository.name_exists(name):
            response.set(constants.RESP_REGISTER_FAIL)
            return
        user = self.repository.add_user(name)
        response.set(constants.RESP_REGISTER_OK, user.token.bytes)
