#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "radix.h"

#define RADIX_ADDRESS_BYTE_COUNT 38 // MagicByte(1) + PubKeyCompr(33) + Checksum(4)
// #define RADIX_ADDRESS_BASE58_CHAR_COUNT_MIN 51
// #define RADIX_ADDRESS_BASE58_CHAR_COUNT_MAX 52

typedef struct {
    uint8_t bytes[RADIX_ADDRESS_BYTE_COUNT];
} RadixAddress;


// RadixAddressFromCborError from_cbor_to_RadixAddress(
//     const char *input_cbor_bytes,
//     const size_t input_cbor_byte_count,
//     RadixAddress *output_radixAddress
// );

// size_t to_string_radix_address(
//     RadixAddress *address,
//     char *output_buffer,
//     const size_t max_length
// );