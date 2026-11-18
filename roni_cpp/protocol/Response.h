#pragma once
#include <cstdint>
#include "protocol.h"

// parses the 7-byte response header (version, code, size); the caller reads the payload
class Response {
public:
    void parseHeader(const uint8_t header[RESPONSE_HEADER_SIZE]);
    uint8_t  version() const { return _version; }
    uint16_t code() const { return _code; }
    uint32_t payloadSize() const { return _payloadSize; }

private:
    uint8_t _version = 0;
    uint16_t _code = 0;
    uint32_t _payloadSize = 0;
};
