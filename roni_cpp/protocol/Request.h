#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include "protocol.h"

// builds the request bytes: header (id, version, code, size) then payload, little-endian
class Request {
public:
    Request(const uint8_t clientId[CLIENT_ID_SIZE], uint16_t code);

    void addPayload(const uint8_t* data, size_t size);
    void addPayload(const std::string& data);

    std::vector<uint8_t> serialize() const;

private:
    uint8_t _clientId[CLIENT_ID_SIZE];
    uint16_t _code;
    std::vector<uint8_t> _payload;
};
