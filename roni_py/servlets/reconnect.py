import constants
from protocol import crypto, utils
from servlets.base import Servlet


class ReconnectServlet(Servlet):
    # 827 -> 1605 (new AES key) or 1606 (reject, client re-registers)
    def handle(self, request, response):
        name = utils.decode_name(request.body[:constants.NAME_SIZE])
        user = self.repository.get_user(request.client_uuid)
        if user is None or user.name != name:
            user = self.repository.get_user_by_name(name)

        if user is None or not user.publicKey:
            reject_id = user.token.bytes if user else request.client_uuid.bytes
            response.set(constants.RESP_RECONNECT_REJECT, reject_id)
            return

        aes_key = crypto.new_aes_key()
        try:
            encrypted = crypto.encrypt_aes_key(aes_key, user.publicKey)
        except (ValueError, IndexError, TypeError):
            response.set(constants.RESP_RECONNECT_REJECT, user.token.bytes)
            return

        self.repository.set_user_aes(user.token, aes_key)
        response.set(constants.RESP_RECONNECT_OK, user.token.bytes + encrypted)
