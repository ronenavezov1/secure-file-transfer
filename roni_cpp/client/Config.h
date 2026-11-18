#pragma once
#include <string>

// reads transfer.json: server ip, port, client name, and the file to send
class Config {
public:
    bool load(const std::string& path);
    const std::string& address() const { return _address; }
    const std::string& port() const { return _port; }
    const std::string& name() const { return _name; }
    const std::string& filePath() const { return _filePath; }

private:
    std::string _address;
    std::string _port;
    std::string _name;
    std::string _filePath;
};
