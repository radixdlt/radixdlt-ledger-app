#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

// UInt256 max value: 115792089237316195423570985008687907853269984665640564039457584007913129639936
// which is 78 digits long.
#define UINT256_DEC_STRING_MAX_LENGTH  78

#define RADIX_AMOUNT_BYTE_COUNT 32

typedef struct {
    uint8_t bytes[RADIX_AMOUNT_BYTE_COUNT]; // Unsigned 256 bit integer
} UnsignedInteger256;

size_t to_string_uint256(
    UnsignedInteger256 *uint256,
    char *outstr,
    const size_t outstr_length);