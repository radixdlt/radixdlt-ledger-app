#include "RadixAddress.h"
#include <stdint.h>
#include "libbase58.h"

RadixAddressFromCborError from_cbor_to_RadixAddress(
    const char *input_cbor_bytes,
    const size_t input_cbor_byte_count,
    RadixAddress *output_radixAddress
) {
    if (input_cbor_bytes != RADIX_ADDRESS_BYTE_COUNT) {
        PRINTF("Too few bytes, expected: %d, but got: %d\n", RADIX_ADDRESS_BYTE_COUNT, input_cbor_bytes);
        return RADIX_ADDRESS_FROM_CBOR_ERROR_TOO_FEW_BYTES;
    }

    RadixAddress address = {
        .bytes = input_cbor_bytes
    };

    *output_radixAddress = address;
    return RADIX_ADDRESS_NO_ERROR;
}

size_t to_string_radix_address(
    RadixAddress *address,
    char *output_buffer,
    const size_t max_length
) {
    if (max_length < RADIX_ADDRESS_BYTE_COUNT + 1) { // + 1 for NULL
        int exception = 0x9111;
        PRINTF("Cannot write Radix address, too small buffer!, throwing error: %d\n", exception);
        THROW(exception);
    }
    int string_length_incl_null;
    char address_base58[max_length];
    bool successful = b58enc(address_base58, &string_length_incl_null, address->bytes, RADIX_ADDRESS_BYTE_COUNT);
    
    if (!successful) {
       int exception = 0x9112;
        PRINTF("Failed to base58 encode data!, throwing error: %d\n", exception);
        THROW(exception);
    }

    return (size_t) string_length_incl_null;
}
