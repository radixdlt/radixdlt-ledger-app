#include <stdlib.h>
#include "RadixAddressFromCborError.h"

#define RADIX_ADDRESS_BYTE_COUNT 39 // MagicByte(1) + PubKeyCompr(33) + Checksum(4) + What is the last byte?
#define RADIX_ADDRESS_BASE58_CHAR_COUNT 51

typedef struct {
    char bytes[RADIX_ADDRESS_BYTE_COUNT];
} RadixAddress;


RadixAddressFromCborError from_cbor_to_RadixAddress(
    const char *input_cbor_bytes,
    const size_t input_cbor_byte_count,
    RadixAddress *output_radixAddress
);

size_t to_string_radix_address(
    RadixAddress *address,
    char *output_buffer,
    const size_t max_length
);