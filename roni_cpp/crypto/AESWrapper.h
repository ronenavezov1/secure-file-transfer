#pragma once
#include <cstdint>
#include <string>

// standalone AES wrapper (CryptoPP). 256-bit CBC with a zero IV, like the server.
class AESWrapper {
public:
    static const unsigned int DEFAULT_KEYLENGTH = 32;   // 256-bit

private:
    uint8_t _key[DEFAULT_KEYLENGTH];

    AESWrapper(const AESWrapper&) = delete;
    AESWrapper& operator=(const AESWrapper&) = delete;

public:
    static uint8_t* generateKey(uint8_t* buffer, unsigned int length);

    AESWrapper();                                          // random key
    AESWrapper(const uint8_t* key, unsigned int length);   // key received from the server
    ~AESWrapper() = default;

    const uint8_t* getKey() const;

    std::string encrypt(const char* plain, unsigned int length);
    std::string decrypt(const char* cipher, unsigned int length);
};
