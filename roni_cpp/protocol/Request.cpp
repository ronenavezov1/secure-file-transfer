#include "Request.h"
#include <cstring>

Request::Request(const uint8_t clientId[CLIENT_ID_SIZE], uint16_t code) : _code(code)
{
    memcpy(_clientId, clientId, CLIENT_ID_SIZE);
}

void Request::addPayload(const uint8_t* data, size_t size)
{
    _payload.insert(_payload.end(), data, data + size);
}

void Request::addPayload(const std::string& data)
{
    _payload.insert(_payload.end(), data.begin(), data.end());
}

std::vector<uint8_t> Request::serialize() const
{
    std::vector<uint8_t> out;
    out.reserve(REQUEST_HEADER_SIZE + _payload.size());

    out.insert(out.end(), _clientId, _clientId + CLIENT_ID_SIZE);
    out.push_back(CLIENT_VERSION);
    out.push_back(static_cast<uint8_t>(_code & 0xFF));
    out.push_back(static_cast<uint8_t>((_code >> 8) & 0xFF));

    const uint32_t ps = static_cast<uint32_t>(_payload.size());
    out.push_back(static_cast<uint8_t>(ps & 0xFF));
    out.push_back(static_cast<uint8_t>((ps >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((ps >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((ps >> 24) & 0xFF));

    out.insert(out.end(), _payload.begin(), _payload.end());
    return out;
}
