#pragma once
#include <cstdint>
#include <string>
#include <boost/asio/ip/tcp.hpp>

// one TCP connection (Boost.Asio), kept open so a multi-packet file goes out before we read the reply
class TCP {
public:
    TCP();
    ~TCP();
    TCP(const TCP&) = delete;
    TCP& operator=(const TCP&) = delete;

    static bool isValidAddress(const std::string& address);
    static bool isValidPort(const std::string& port);

    bool setSocketInfo(const std::string& address, const std::string& port);
    bool connect();
    void close();
    bool send(const uint8_t* buffer, size_t size) const;
    bool receive(uint8_t* buffer, size_t size) const;

private:
    std::string _address;
    std::string _port;
    boost::asio::io_context* _ioContext;
    boost::asio::ip::tcp::resolver* _resolver;
    boost::asio::ip::tcp::socket* _socket;
    bool _connected;
};
