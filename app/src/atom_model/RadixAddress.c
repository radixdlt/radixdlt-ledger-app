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
    uint8_t base58 = 58;
    size_t de_facto_length = convertByteBufferIntoDigitsWithBase(address->bytes, RADIX_ADDRESS_BYTE_COUNT, output_buffer, base58);

    static const char base58_digits[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    for (unsigned int i = 0; i < de_facto_length; ++i)
    {
        uint8_t digitValue = (uint8_t) output_buffer[i];
        uint8_t mappedIndex = digitValue - (base58-10); // should probably change this, a bit confusing..
        char base58Char = base58_digits[mappedIndex];
        output_buffer[i] = base58Char;
    }
    output_buffer[de_facto_length] = '\0'; // NULL terminate
    return de_facto_length;
}