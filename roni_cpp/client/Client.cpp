#include "Client.h"

#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>

#include "../protocol/Request.h"
#include "../protocol/Response.h"
#include "../crypto/AESWrapper.h"
#include "../crypto/cksum.h"

static const char* ME_INFO = "me.info";
static const char* TRANSFER_CONFIG = "transfer.json";
constexpr size_t FILE_PACKET = 8192;   // encrypted bytes per 828 packet
constexpr int    MAX_ATTEMPTS = 4;     // one try + up to three retries

// copy a string into a fixed null-padded field
static void fill(uint8_t* field, size_t fieldSize, const std::string& s)
{
    memset(field, 0, fieldSize);
    const size_t n = (s.size() < fieldSize) ? s.size() : fieldSize - 1;
    memcpy(field, s.data(), n);
}

static uint32_t le32(const uint8_t* p)
{
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

Client::Client() : _rsa(nullptr), _aesKey{ 0 }, _hasAes(false) {}
Client::~Client() { delete _rsa; }

void Client::run()
{
    if (!_config.load(TRANSFER_CONFIG)) {
        std::cout << "cannot read " << TRANSFER_CONFIG << "\n";
        return;
    }
    if (!_tcp.setSocketInfo(_config.address(), _config.port())) {
        std::cout << "invalid server address in " << TRANSFER_CONFIG << "\n";
        return;
    }
    if (!_tcp.connect()) {
        std::cout << "cannot connect to " << _config.address() << ":" << _config.port() << "\n";
        return;
    }

    std::ifstream me(ME_INFO);
    const bool known = me.good();
    me.close();

    bool ready = false;
    if (known && _user.load(ME_INFO)) {
        ready = reconnect();                       // 827
        if (!ready)
            std::cout << "reconnect rejected, registering as a new client\n";
    }
    if (!ready) {
        bool ok = false;
        for (int attempt = 1; attempt <= 3 && !ok; ++attempt) {   // register, up to 3 tries
            if (registerClient() && sendPublicKey())              // 825 then 826
                ok = true;
            else
                std::cout << "server responded with an error\n";
        }
        if (!ok) {
            std::cout << "Fatal error: could not register and exchange keys\n";
            return;
        }
        _user.save(ME_INFO);
    }

    if (_config.filePath().empty()) {
        std::cout << "no file to send (add a \"file\" entry to " << TRANSFER_CONFIG << ")\n";
        return;
    }
    if (sendFile(_config.filePath()))
        std::cout << "file sent and verified\n";
    else
        std::cout << "Fatal error: file transfer failed\n";
    _tcp.close();
}

bool Client::sendRequest(const std::vector<uint8_t>& bytes)
{
    return _tcp.send(bytes.data(), bytes.size());
}

bool Client::readResponse(uint16_t& code, std::vector<uint8_t>& payload)
{
    uint8_t header[RESPONSE_HEADER_SIZE];
    if (!_tcp.receive(header, RESPONSE_HEADER_SIZE))
        return false;
    Response resp;
    resp.parseHeader(header);
    code = resp.code();
    payload.resize(resp.payloadSize());
    if (resp.payloadSize() > 0)
        return _tcp.receive(payload.data(), payload.size());
    return true;
}

bool Client::registerClient()
{
    const uint8_t zeroId[CLIENT_ID_SIZE] = { 0 };
    Request req(zeroId, REQ_REGISTER);
    uint8_t nameField[NAME_SIZE];
    fill(nameField, NAME_SIZE, _config.name());
    req.addPayload(nameField, NAME_SIZE);
    if (!sendRequest(req.serialize()))
        return false;

    uint16_t code;
    std::vector<uint8_t> payload;
    if (!readResponse(code, payload))
        return false;
    if (code != RESP_REGISTER_OK || payload.size() < CLIENT_ID_SIZE)
        return false;

    _user.setName(_config.name());
    _user.setUuid(payload.data());
    std::cout << "registered as '" << _user.name() << "', client id " << _user.uuidHex() << "\n";
    return true;
}

bool Client::sendPublicKey()
{
    delete _rsa;
    _rsa = new RSAPrivateWrapper();                    // fresh RSA-1024 key pair
    _user.setPrivateKey(_rsa->getPrivateKey());
    const std::string pub = _rsa->getPublicKey();      // X.509, 160 bytes

    Request req(_user.uuid(), REQ_SEND_PUBLIC_KEY);
    uint8_t nameField[NAME_SIZE];
    fill(nameField, NAME_SIZE, _user.name());
    req.addPayload(nameField, NAME_SIZE);
    uint8_t keyField[PUBLIC_KEY_SIZE] = { 0 };                 // binary, copy all bytes (no null term)
    memcpy(keyField, pub.data(), pub.size() < PUBLIC_KEY_SIZE ? pub.size() : PUBLIC_KEY_SIZE);
    req.addPayload(keyField, PUBLIC_KEY_SIZE);
    if (!sendRequest(req.serialize()))
        return false;

    uint16_t code;
    std::vector<uint8_t> payload;
    if (!readResponse(code, payload))
        return false;
    if (code != RESP_PUBLIC_KEY_RECEIVED || payload.size() <= CLIENT_ID_SIZE)
        return false;

    const std::string encAes(reinterpret_cast<const char*>(payload.data() + CLIENT_ID_SIZE),
                             payload.size() - CLIENT_ID_SIZE);
    const std::string aes = _rsa->decrypt(encAes);
    if (aes.size() != AES_KEY_SIZE)
        return false;
    memcpy(_aesKey, aes.data(), AES_KEY_SIZE);
    _hasAes = true;
    std::cout << "public key sent, received and decrypted the AES key\n";
    return true;
}

bool Client::reconnect()
{
    Request req(_user.uuid(), REQ_RECONNECT);
    uint8_t nameField[NAME_SIZE];
    fill(nameField, NAME_SIZE, _user.name());
    req.addPayload(nameField, NAME_SIZE);
    if (!sendRequest(req.serialize()))
        return false;

    uint16_t code;
    std::vector<uint8_t> payload;
    if (!readResponse(code, payload))
        return false;
    if (code != RESP_RECONNECT_OK || payload.size() <= CLIENT_ID_SIZE)
        return false;   // 1606 or error -> caller registers again

    delete _rsa;
    _rsa = new RSAPrivateWrapper(_user.privateKey());   // reload our key from me.info
    const std::string encAes(reinterpret_cast<const char*>(payload.data() + CLIENT_ID_SIZE),
                             payload.size() - CLIENT_ID_SIZE);
    const std::string aes = _rsa->decrypt(encAes);
    if (aes.size() != AES_KEY_SIZE)
        return false;
    memcpy(_aesKey, aes.data(), AES_KEY_SIZE);
    _hasAes = true;
    std::cout << "reconnected as '" << _user.name() << "', received and decrypted the AES key\n";
    return true;
}

bool Client::sendFile(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        std::cout << "cannot open file: " << path << "\n";
        return false;
    }
    const std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)),
                                    std::istreambuf_iterator<char>());
    f.close();

    std::string fileName = path;
    const size_t slash = fileName.find_last_of("/\\");
    if (slash != std::string::npos)
        fileName = fileName.substr(slash + 1);

    const uint32_t myCrc = memcrc(data.data(), data.size());

    AESWrapper aes(_aesKey, AES_KEY_SIZE);
    const std::string cipher = aes.encrypt(reinterpret_cast<const char*>(data.data()),
                                           static_cast<unsigned int>(data.size()));
    const uint32_t contentSize = static_cast<uint32_t>(cipher.size());
    const uint32_t origSize = static_cast<uint32_t>(data.size());
    uint16_t totalPackets = static_cast<uint16_t>((cipher.size() + FILE_PACKET - 1) / FILE_PACKET);
    if (totalPackets == 0)
        totalPackets = 1;
    std::cout << "sending '" << fileName << "' (" << origSize << " bytes, " << totalPackets << " packet(s))\n";

    for (int attempt = 1; attempt <= MAX_ATTEMPTS; ++attempt) {
        for (uint16_t i = 0; i < totalPackets; ++i) {
            const size_t off = static_cast<size_t>(i) * FILE_PACKET;
            const size_t len = (off + FILE_PACKET <= cipher.size()) ? FILE_PACKET : (cipher.size() - off);

            Request req(_user.uuid(), REQ_SEND_FILE);
            uint8_t meta[FILE_META_SIZE] = { 0 };
            meta[0] = contentSize & 0xFF; meta[1] = (contentSize >> 8) & 0xFF;
            meta[2] = (contentSize >> 16) & 0xFF; meta[3] = (contentSize >> 24) & 0xFF;
            meta[4] = origSize & 0xFF; meta[5] = (origSize >> 8) & 0xFF;
            meta[6] = (origSize >> 16) & 0xFF; meta[7] = (origSize >> 24) & 0xFF;
            const uint16_t pnum = i + 1;
            meta[8] = pnum & 0xFF; meta[9] = (pnum >> 8) & 0xFF;
            meta[10] = totalPackets & 0xFF; meta[11] = (totalPackets >> 8) & 0xFF;
            fill(meta + 12, FILE_NAME_SIZE, fileName);
            req.addPayload(meta, FILE_META_SIZE);
            if (len > 0)
                req.addPayload(reinterpret_cast<const uint8_t*>(cipher.data() + off), len);
            if (!sendRequest(req.serialize()))
                return false;
        }

        uint16_t code;
        std::vector<uint8_t> payload;
        if (!readResponse(code, payload))        // server replies only after the last packet
            return false;
        if (code != RESP_FILE_OK_CRC ||
            payload.size() < CLIENT_ID_SIZE + 4 + FILE_NAME_SIZE + 4) {
            std::cout << "server responded with an error\n";
            return false;
        }
        const uint32_t serverCrc = le32(payload.data() + CLIENT_ID_SIZE + 4 + FILE_NAME_SIZE);

        uint8_t nameField[FILE_NAME_SIZE];
        fill(nameField, FILE_NAME_SIZE, fileName);

        if (serverCrc == myCrc) {
            Request ok(_user.uuid(), REQ_CRC_OK);
            ok.addPayload(nameField, FILE_NAME_SIZE);
            sendRequest(ok.serialize());
            readResponse(code, payload);         // 1604
            return true;
        }
        if (attempt < MAX_ATTEMPTS) {
            Request retry(_user.uuid(), REQ_CRC_INVALID_RETRY);
            retry.addPayload(nameField, FILE_NAME_SIZE);
            sendRequest(retry.serialize());      // server sends no reply, resend the file
        } else {
            Request abort(_user.uuid(), REQ_CRC_INVALID_ABORT);
            abort.addPayload(nameField, FILE_NAME_SIZE);
            sendRequest(abort.serialize());
            readResponse(code, payload);         // 1604
            return false;
        }
    }
    return false;
}
