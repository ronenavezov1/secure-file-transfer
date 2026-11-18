import constants
import logger
from protocol import crypto, utils
from servlets.base import Servlet

log = logger.get("servlet.file")


class SendFileServlet(Servlet):
    # 828: collect packets, decrypt on the last one, reply 1603 with the cksum
    def handle(self, request, response):
        user = self.repository.get_user(request.client_uuid)
        if user is None or not user.aes:
            response.set(constants.RESP_GENERAL_ERROR)
            return

        body = request.body
        content_size = int.from_bytes(body[0:4], byteorder='little')
        orig_size = int.from_bytes(body[4:8], byteorder='little')
        packet_num = int.from_bytes(body[8:10], byteorder='little')
        total_packets = int.from_bytes(body[10:12], byteorder='little')
        file_name = utils.decode_name(body[12:constants.FILE_META_SIZE])
        chunk = body[constants.FILE_META_SIZE:]

        try:
            ciphertext = self.repository.add_file_packet(
                user.token, file_name, packet_num, total_packets, chunk)
        except ValueError:
            response.set(constants.RESP_GENERAL_ERROR)
            return
        if ciphertext is None:
            response.no_response()          # more packets still coming
            return

        try:
            plaintext = crypto.decrypt_file(ciphertext, user.aes)
        except ValueError:
            self.repository.cancel_transfer(user.token, file_name)
            response.set(constants.RESP_GENERAL_ERROR)
            return
        original = plaintext[:orig_size]

        self.repository.save_file(user.token, file_name, original, verified=False)
        self.repository.touch(user.token)
        crc = utils.cksum(original)
        log.debug("file '%s' assembled: %d bytes, cksum=%d", file_name, len(original), crc)

        response.set(constants.RESP_FILE_OK_CRC,
                     user.token.bytes
                     + content_size.to_bytes(4, byteorder='little')
                     + utils.encode_name(file_name)
                     + crc.to_bytes(4, byteorder='little'))
