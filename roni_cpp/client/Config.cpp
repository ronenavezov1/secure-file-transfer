#include "Config.h"

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

bool Config::load(const std::string& path)
{
    boost::property_tree::ptree pt;
    try {
        boost::property_tree::read_json(path, pt);
    }
    catch (...) {
        return false;
    }

    _address = pt.get<std::string>("server.ip", "");
    _port    = pt.get<std::string>("server.port", "");   // read as string, the port is a json number
    _name    = pt.get<std::string>("server.client", "");

    // the file to send is not in the assignment example, so accept a few spellings
    _filePath = pt.get<std::string>("file", "");
    if (_filePath.empty()) _filePath = pt.get<std::string>("server.file", "");
    if (_filePath.empty()) _filePath = pt.get<std::string>("filepath", "");

    return !_address.empty() && !_port.empty() && !_name.empty();
}
