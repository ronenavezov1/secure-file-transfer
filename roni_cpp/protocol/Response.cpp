#include "Response.h"

void Response::parseHeader(const uint8_t h[RESPONSE_HEADER_SIZE])
{
    _version = h[0];
    _code = static_cast<uint16_t>(h[1]) | (static_cast<uint16_t>(h[2]) << 8);
    _payloadSize = static_cast<uint32_t>(h[3])
                 | (static_cast<uint32_t>(h[4]) << 8)
                 | (static_cast<uint32_t>(h[5]) << 16)
                 | (static_cast<uint32_t>(h[6]) << 24);
}
