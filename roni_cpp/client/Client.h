#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "Config.h"
#include "User.h"
#include "../protocol/protocol.h"
#include "../transport/TCP.h"
#include "../crypto/RSAWrapper.h"

// runs the client flow: register or reconnect, key exchange, then send the file
class Client {
public:
    Client();
    ~Client();
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    void run();

private:
    bool sendRequest(const std::vector<uint8_t>& bytes);
    bool readResponse(uint16_t& code, std::vector<uint8_t>& payload);

    bool registerClient();
    bool sendPublicKey();
    bool reconnect();
    bool sendFile(const std::string& path);

    Config _config;
    User _user;
    TCP _tcp;
    RSAPrivateWrapper* _rsa;
    uint8_t _aesKey[AES_KEY_SIZE];
    bool _hasAes;
};
