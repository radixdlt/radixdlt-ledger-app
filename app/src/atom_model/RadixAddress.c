#include "RadixAddress.h"
#include "stdint.h"
#include "base_conversion.h"
#include "common_macros.h"

// Returns the de-facto length of the address copied over to `output_buffer` (including the null terminator).
size_t to_string_radix_address(
    RadixAddress *address,
    char *output_buffer,
    const size_t size_of_buffer
) { 
    assert(size_of_buffer == RADIX_ADDRESS_BASE58_CHAR_COUNT_MAX + 1); // +1 for null
    return convertByteBufferIntoBase58(address->bytes, RADIX_ADDRESS_BYTE_COUNT, output_buffer);
}

bool matchesPublicKey(RadixAddress *address, cx_ecfp_public_key_t *compressedPublicKey) {
    return matchesPublicKeyBytes(address, compressedPublicKey->W);
}

bool matchesPublicKeyBytes(RadixAddress *address, uint8_t *compressedPublicKeyBytes)
{
    // Might result in false negatives, you need to know that you
    // really are in fact passing in a compressed public key
    assert(compressedPublicKeyBytes[0] == 0x02 || compressedPublicKeyBytes[0] == 0x03);

    // 1 "magic" byte prefixes the address
    const size_t offsetOfPubKeyWithinAddress = 1; 

    for (int i = 0; i < PUBLIC_KEY_COMPRESSEED_BYTE_COUNT; ++i)
    {
        if (compressedPublicKeyBytes[i] != address->bytes[i + offsetOfPubKeyWithinAddress]) {
            return false;
        }
    }
    return true;
}

void printRadixAddress(RadixAddress *address) {
    const size_t max_length = RADIX_ADDRESS_BASE58_CHAR_COUNT_MAX + 1;  // +1 for null terminator
    char address_b58[max_length];
    
    to_string_radix_address(address, address_b58, max_length);

    PRINTF("%s", address_b58);
}