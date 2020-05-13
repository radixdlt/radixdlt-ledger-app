#include "RadixAddress.h"
#include "stdint.h"
#include "libbase58.h"

// RadixAddressFromCborError from_cbor_to_RadixAddress(
//     const char *input_cbor_bytes,
//     const size_t input_cbor_byte_count,
//     RadixAddress *output_radixAddress
// ) {
//     if (input_cbor_bytes != RADIX_ADDRESS_BYTE_COUNT) {
//         PRINTF("Too few bytes, expected: %d, but got: %d\n", RADIX_ADDRESS_BYTE_COUNT, input_cbor_bytes);
//         return RADIX_ADDRESS_FROM_CBOR_ERROR_TOO_FEW_BYTES;
//     }

//     RadixAddress address = {
//         .bytes = input_cbor_bytes
//     };

//     *output_radixAddress = address;
//     return RADIX_ADDRESS_NO_ERROR;
// }

// Returns the de-facto length of the address copied over to `output_buffer` (including the null terminator).
size_t to_string_radix_address(
    RadixAddress *address,
    char *output_buffer,
    const size_t size_of_buffer
) { 

    assert(size_of_buffer >= (RADIX_ADDRESS_BASE58_CHAR_COUNT_MAX + 1)); // +1 for NULL

    size_t string_length_incl_null = (RADIX_ADDRESS_BASE58_CHAR_COUNT_MAX + 1);
    bool successful = b58enc(
        output_buffer,
        &string_length_incl_null, // <-- modifies with de-facto length (including the null terminator)
        address->bytes,
        RADIX_ADDRESS_BYTE_COUNT);

    if (!successful) {
        FATAL_ERROR("Failed to base58 encode data!");
    }

    // (including the null terminator)
    return string_length_incl_null;
}