import constants
import logger
from network.server_socket import ServerSocket

log = logger.get("main")


def read_port():
    try:
        with open(constants.PORT_FILE, 'r') as f:
            return int(f.readline().strip())
    except (OSError, ValueError):
        log.warning("%s missing or invalid, using default port %d",
                    constants.PORT_FILE, constants.DEFAULT_PORT)
        return constants.DEFAULT_PORT


def main():
    logger.setup()
    port = read_port()
    log.info("server starting on port %d (DEBUG=%s)", port, constants.DEBUG)

    server = ServerSocket('', port)
    server.start()
    try:
        while server.is_alive():
            server.join(1)
    except KeyboardInterrupt:
        log.info("shutting down")
        server.stop()
        server.join()


if __name__ == "__main__":
    main()
