#pragma once
#include <string>

// base64 helper (CryptoPP), used for the private key in me.info
class Base64Wrapper {
public:
    static std::string encode(const std::string& str);
    static std::string decode(const std::string& str);
};
