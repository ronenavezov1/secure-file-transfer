#include "AESWrapper.h"

#include <cstring>
#include <stdexcept>

#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>

uint8_t* AESWrapper::generateKey(uint8_t* buffer, unsigned int length)
{
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(buffer, length);
    return buffer;
}

AESWrapper::AESWrapper()
{
    generateKey(_key, DEFAULT_KEYLENGTH);
}

AESWrapper::AESWrapper(const uint8_t* key, unsigned int length)
{
    if (length != DEFAULT_KEYLENGTH)
        throw std::length_error("AES key must be 32 bytes (256-bit)");
    memcpy(_key, key, length);
}

const uint8_t* AESWrapper::getKey() const
{
    return _key;
}

std::string AESWrapper::encrypt(const char* plain, unsigned int length)
{
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };   // zero IV, per the protocol

    CryptoPP::AES::Encryption aes(_key, DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbc(aes, iv);

    std::string cipher;
    CryptoPP::StreamTransformationFilter stf(cbc, new CryptoPP::StringSink(cipher));
    stf.Put(reinterpret_cast<const CryptoPP::byte*>(plain), length);
    stf.MessageEnd();
    return cipher;
}

std::string AESWrapper::decrypt(const char* cipher, unsigned int length)
{
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };

    CryptoPP::AES::Decryption aes(_key, DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbc(aes, iv);

    std::string plain;
    CryptoPP::StreamTransformationFilter stf(cbc, new CryptoPP::StringSink(plain));
    stf.Put(reinterpret_cast<const CryptoPP::byte*>(cipher), length);
    stf.MessageEnd();
    return plain;
}
