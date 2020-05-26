#include "RadixAddress.h"
#include "stdint.h"
#include "base_conversion.h"

// Returns the de-facto length of the address copied over to `output_buffer` (including the null terminator).
size_t to_string_radix_address(
    RadixAddress *address,
    char *output_buffer,
    const size_t size_of_buffer
) { 
    assert(size_of_buffer == RADIX_ADDRESS_BASE58_CHAR_COUNT_MAX + 1); // +1 for null
    return convertByteBufferIntoBase58(address->bytes, RADIX_ADDRESS_BYTE_COUNT, output_buffer);
}