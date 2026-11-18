#pragma once
#include <cstddef>
#include <cstdint>

// Maman 06 protocol, version 3. Wire values are little-endian, unsigned.

constexpr uint8_t CLIENT_VERSION = 3;

// field sizes (bytes)
constexpr size_t CLIENT_ID_SIZE   = 16;
constexpr size_t NAME_SIZE        = 255;   // ascii, null-terminated
constexpr size_t PUBLIC_KEY_SIZE  = 160;   // RSA-1024, X.509
constexpr size_t AES_KEY_SIZE     = 32;    // 256-bit
constexpr size_t FILE_NAME_SIZE   = 255;

constexpr size_t REQUEST_HEADER_SIZE  = CLIENT_ID_SIZE + 1 + 2 + 4;   // 23
constexpr size_t RESPONSE_HEADER_SIZE = 1 + 2 + 4;                    // 7
// 828 payload before the content: content size(4) + orig size(4) + packet(2) + total(2) + name(255)
constexpr size_t FILE_META_SIZE = 4 + 4 + 2 + 2 + FILE_NAME_SIZE;     // 267

enum RequestCode : uint16_t {
    REQ_REGISTER          = 825,
    REQ_SEND_PUBLIC_KEY   = 826,
    REQ_RECONNECT         = 827,
    REQ_SEND_FILE         = 828,
    REQ_CRC_OK            = 900,
    REQ_CRC_INVALID_RETRY = 901,
    REQ_CRC_INVALID_ABORT = 902,
};

enum ResponseCode : uint16_t {
    RESP_REGISTER_OK         = 1600,
    RESP_REGISTER_FAIL       = 1601,
    RESP_PUBLIC_KEY_RECEIVED = 1602,   // client id + AES key encrypted with the client's public key
    RESP_FILE_OK_CRC         = 1603,   // client id + content size + file name + cksum
    RESP_MSG_ACK             = 1604,   // client id
    RESP_RECONNECT_OK        = 1605,   // same shape as 1602
    RESP_RECONNECT_REJECT    = 1606,   // client id
    RESP_GENERAL_ERROR       = 1607,
};
