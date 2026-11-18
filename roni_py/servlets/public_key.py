import constants
from protocol import crypto
from servlets.base import Servlet


class PublicKeyServlet(Servlet):
    # 826 -> 1602: store the public key, send back an AES key encrypted with it
    def handle(self, request, response):
        user = self.repository.get_user(request.client_uuid)
        if user is None:
            response.set(constants.RESP_GENERAL_ERROR)
            return

        public_key = request.body[constants.NAME_SIZE:constants.NAME_SIZE + constants.PUBLIC_KEY_SIZE]
        aes_key = crypto.new_aes_key()
        try:
            encrypted = crypto.encrypt_aes_key(aes_key, public_key)
        except (ValueError, IndexError, TypeError):
            response.set(constants.RESP_GENERAL_ERROR)
            return

        self.repository.set_user_keys(user.token, public_key, aes_key)
        response.set(constants.RESP_PUBLIC_KEY_RECEIVED, user.token.bytes + encrypted)
