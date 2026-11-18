#pragma once
#include <cstdint>
#include <string>
#include "../protocol/protocol.h"

// our identity, saved in me.info (name, uuid in hex, private key in base64)
class User {
public:
    User() = default;

    const std::string& name() const { return _name; }
    void setName(const std::string& name) { _name = name; }

    const uint8_t* uuid() const { return _uuid; }
    void setUuid(const uint8_t uuid[CLIENT_ID_SIZE]);
    std::string uuidHex() const;

    const std::string& privateKey() const { return _privateKey; }   // raw DER
    void setPrivateKey(const std::string& der) { _privateKey = der; }

    bool load(const std::string& path);
    bool save(const std::string& path) const;

private:
    std::string _name;
    uint8_t _uuid[CLIENT_ID_SIZE] = { 0 };
    std::string _privateKey;   // DER in memory, base64 in the file
};
