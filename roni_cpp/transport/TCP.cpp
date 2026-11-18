#include "TCP.h"
#include <boost/asio.hpp>

using boost::asio::io_context;
using boost::asio::ip::tcp;

TCP::TCP() : _ioContext(nullptr), _resolver(nullptr), _socket(nullptr), _connected(false) {}

TCP::~TCP() { close(); }

bool TCP::isValidAddress(const std::string& address)
{
    if (address == "localhost" || address == "LOCALHOST")
        return true;
    try {
        (void)boost::asio::ip::make_address(address);
    }
    catch (...) {
        return false;
    }
    return true;
}

bool TCP::isValidPort(const std::string& port)
{
    try {
        const int p = std::stoi(port);
        return p > 0 && p <= 65535;
    }
    catch (...) {
        return false;
    }
}

bool TCP::setSocketInfo(const std::string& address, const std::string& port)
{
    if (!isValidAddress(address) || !isValidPort(port))
        return false;
    _address = address;
    _port = port;
    return true;
}

bool TCP::connect()
{
    if (!isValidAddress(_address) || !isValidPort(_port))
        return false;
    try {
        close();                          // drop any previous socket
        _ioContext = new io_context;
        _resolver = new tcp::resolver(*_ioContext);
        _socket = new tcp::socket(*_ioContext);
        boost::asio::connect(*_socket, _resolver->resolve(_address, _port));
        _socket->non_blocking(false);
        _connected = true;
    }
    catch (...) {
        _connected = false;
    }
    return _connected;
}

void TCP::close()
{
    try {
        if (_socket != nullptr)
            _socket->close();
    }
    catch (...) {}
    delete _ioContext;
    delete _resolver;
    delete _socket;
    _ioContext = nullptr;
    _resolver = nullptr;
    _socket = nullptr;
    _connected = false;
}

// send exactly size bytes
bool TCP::send(const uint8_t* buffer, size_t size) const
{
    if (_socket == nullptr || !_connected || buffer == nullptr || size == 0)
        return false;
    boost::system::error_code ec;
    boost::asio::write(*_socket, boost::asio::buffer(buffer, size), ec);
    return !ec;
}

// receive exactly size bytes
bool TCP::receive(uint8_t* buffer, size_t size) const
{
    if (_socket == nullptr || !_connected || buffer == nullptr || size == 0)
        return false;
    boost::system::error_code ec;
    boost::asio::read(*_socket, boost::asio::buffer(buffer, size), ec);
    return !ec;
}
