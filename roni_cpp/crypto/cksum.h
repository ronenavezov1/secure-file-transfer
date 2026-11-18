#pragma once
#include <cstddef>
#include <cstdint>

// CRC matching the linux cksum command
uint32_t memcrc(const uint8_t* data, size_t length);
