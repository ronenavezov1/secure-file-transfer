import logging

import constants

# code -> readable name for the log
_REQ_NAMES = {
    constants.REQ_REGISTER: "825 register",
    constants.REQ_SEND_PUBLIC_KEY: "826 public-key",
    constants.REQ_RECONNECT: "827 reconnect",
    constants.REQ_SEND_FILE: "828 send-file",
    constants.REQ_CRC_OK: "900 crc-ok",
    constants.REQ_CRC_INVALID_RETRY: "901 crc-retry",
    constants.REQ_CRC_INVALID_ABORT: "902 crc-abort",
}
_RESP_NAMES = {
    constants.RESP_REGISTER_OK: "1600 register-ok",
    constants.RESP_REGISTER_FAIL: "1601 register-fail",
    constants.RESP_PUBLIC_KEY_RECEIVED: "1602 aes-key",
    constants.RESP_FILE_OK_CRC: "1603 file-ok-crc",
    constants.RESP_MSG_ACK: "1604 ack",
    constants.RESP_RECONNECT_OK: "1605 reconnect-aes",
    constants.RESP_RECONNECT_REJECT: "1606 reconnect-reject",
    constants.RESP_GENERAL_ERROR: "1607 error",
}


def setup():
    logging.basicConfig(
        level=logging.DEBUG if constants.DEBUG else logging.INFO,
        format="%(asctime)s  %(levelname)-5s  %(name)-16s %(message)s",
        datefmt="%H:%M:%S",
    )


def get(name):
    return logging.getLogger(name)


def code_name(code):
    return _REQ_NAMES.get(code) or _RESP_NAMES.get(code) or str(code)


def short_id(client_uuid):
    try:
        return client_uuid.hex[:8]
    except AttributeError:
        return str(client_uuid)
