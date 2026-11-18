#include "cksum.h"

static uint32_t crctab[256];
static bool built = false;

static void buildTable()
{
    for (unsigned int i = 0; i < 256; ++i)
    {
        uint32_t c = i << 24;
        for (int k = 0; k < 8; ++k)
            c = (c & 0x80000000) ? (c << 1) ^ 0x04C11DB7 : (c << 1);
        crctab[i] = c;
    }
    built = true;
}

uint32_t memcrc(const uint8_t* data, size_t length)
{
    if (!built)
        buildTable();

    uint32_t crc = 0;
    for (size_t i = 0; i < length; ++i)
        crc = (crc << 8) ^ crctab[((crc >> 24) ^ data[i]) & 0xFF];

    size_t n = length;
    while (n)
    {
        crc = (crc << 8) ^ crctab[((crc >> 24) ^ (n & 0xFF)) & 0xFF];
        n >>= 8;
    }
    return ~crc;
}
