#include "User.h"

#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>

#include "../crypto/Base64Wrapper.h"

// the assignment also keeps the private key on its own in priv.key, reused on reconnect
static const char* PRIV_KEY_FILE = "priv.key";

void User::setUuid(const uint8_t uuid[CLIENT_ID_SIZE])
{
    memcpy(_uuid, uuid, CLIENT_ID_SIZE);
}

std::string User::uuidHex() const
{
    std::ostringstream os;
    for (size_t i = 0; i < CLIENT_ID_SIZE; ++i)
        os << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(_uuid[i]);
    return os.str();
}

static void hexToBytes(const std::string& hex, uint8_t* out, size_t outLen)
{
    for (size_t i = 0; i < outLen && (i * 2 + 1) < hex.size(); ++i)
        out[i] = static_cast<uint8_t>(std::stoi(hex.substr(i * 2, 2), nullptr, 16));
}

static std::string readAll(std::ifstream& in)
{
    std::string data, line;
    while (std::getline(in, line))
        data += line;   // base64 may span several lines
    return data;
}

bool User::load(const std::string& path)
{
    std::ifstream f(path);
    if (!f)
        return false;

    std::string name, hex;
    if (!std::getline(f, name) || !std::getline(f, hex))
        return false;
    std::string keyBase64 = readAll(f);
    f.close();

    // on reconnect the key comes from priv.key, fall back to the one in me.info
    std::ifstream pk(PRIV_KEY_FILE);
    if (pk) {
        const std::string fromPriv = readAll(pk);
        if (!fromPriv.empty())
            keyBase64 = fromPriv;
    }

    _name = name;
    memset(_uuid, 0, CLIENT_ID_SIZE);
    hexToBytes(hex, _uuid, CLIENT_ID_SIZE);
    _privateKey = Base64Wrapper::decode(keyBase64);
    return true;
}

bool User::save(const std::string& path) const
{
    const std::string keyBase64 = Base64Wrapper::encode(_privateKey);

    std::ofstream f(path);
    if (!f)
        return false;
    f << _name << "\n" << uuidHex() << "\n" << keyBase64;
    f.close();

    std::ofstream pk(PRIV_KEY_FILE);
    if (pk)
        pk << keyBase64;
    return true;
}
