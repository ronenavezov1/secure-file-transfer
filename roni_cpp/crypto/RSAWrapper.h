#pragma once
#include <string>

#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>

// standalone RSA wrapper (CryptoPP). 1024-bit, OAEP-SHA1 to match the server.

class RSAPublicWrapper {
public:
    static const unsigned int KEYSIZE = 160;   // X.509 public key length for RSA-1024
    static const unsigned int BITS = 1024;

private:
    CryptoPP::AutoSeededRandomPool _rng;
    CryptoPP::RSA::PublicKey _publicKey;

    RSAPublicWrapper(const RSAPublicWrapper&) = delete;
    RSAPublicWrapper& operator=(const RSAPublicWrapper&) = delete;

public:
    RSAPublicWrapper(const char* key, unsigned int length);
    explicit RSAPublicWrapper(const std::string& key);
    ~RSAPublicWrapper() = default;

    std::string getPublicKey() const;
    char* getPublicKey(char* keyout, unsigned int length) const;

    std::string encrypt(const std::string& plain);
    std::string encrypt(const char* plain, unsigned int length);
};

class RSAPrivateWrapper {
public:
    static const unsigned int BITS = 1024;

private:
    CryptoPP::AutoSeededRandomPool _rng;
    CryptoPP::RSA::PrivateKey _privateKey;

    RSAPrivateWrapper(const RSAPrivateWrapper&) = delete;
    RSAPrivateWrapper& operator=(const RSAPrivateWrapper&) = delete;

public:
    RSAPrivateWrapper();                                       // generate a new key pair
    RSAPrivateWrapper(const char* key, unsigned int length);   // load existing (DER)
    explicit RSAPrivateWrapper(const std::string& key);        // load existing (DER)
    ~RSAPrivateWrapper() = default;

    std::string getPrivateKey() const;                         // DER, for me.info
    char* getPrivateKey(char* keyout, unsigned int length) const;

    std::string getPublicKey() const;                          // X.509, sent in request 826
    char* getPublicKey(char* keyout, unsigned int length) const;

    std::string decrypt(const std::string& cipher);
    std::string decrypt(const char* cipher, unsigned int length);
};
