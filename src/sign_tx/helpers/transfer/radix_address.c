#include "radix_address.h"
#include "stdint.h"
#include "base_conversion.h"
#include "common_macros.h"
#include "sha256_hash.h"
#include <os_io_seproxyhal.h>

// Returns the de-facto length of the address copied over to `output_buffer` (including the null terminator).
size_t to_string_radix_address(
    radix_address_t *address,
    char *output_buffer,
    const size_t size_of_buffer
) { 
    assert(size_of_buffer == RADIX_ADDRESS_BASE58_CHAR_COUNT_MAX + 1); // +1 for null
    return convert_byte_buffer_into_base58(address->bytes, RADIX_ADDRESS_BYTE_COUNT, output_buffer);
}


#define ADDRESS_CHECKSUM_BYTE_COUNT 4

int generate_public_address_from_pub_key_and_universe_magic(
    uint8_t magicByte, uint8_t *compressed_public_key_bytes,
    char *output_radix_addr_str, const size_t length_of_output_radix_addr_str) 
{
    
    assert(length_of_output_radix_addr_str == RADIX_ADDRESS_BASE58_CHAR_COUNT_MAX + 1); // +1 for null
    os_memset(output_radix_addr_str, 0x00, length_of_output_radix_addr_str);

    size_t length_unhashed = 1 + PUBLIC_KEY_COMPRESSEED_BYTE_COUNT; // +1 for magic byte
    uint8_t magic_concat_pubkey[length_unhashed + ADDRESS_CHECKSUM_BYTE_COUNT];
    os_memcpy(magic_concat_pubkey, &magicByte, 1);
    os_memcpy(magic_concat_pubkey + 1, compressed_public_key_bytes, PUBLIC_KEY_COMPRESSEED_BYTE_COUNT);
    uint8_t hash_of_mb_concat_pk[HASH256_BYTE_COUNT];

    cx_sha256_t hasher;        
    
    cx_sha256_init(&hasher);

    if (!sha256_hash(&hasher, magic_concat_pubkey, length_unhashed, true, hash_of_mb_concat_pk)) {
        FATAL_ERROR("ERROR hash creating Radix address");
    }
    
     // re-initiate hasher for second run, since we do hash of hash at Radix
      cx_sha256_init(&hasher);

    if (!sha256_hash(&hasher, hash_of_mb_concat_pk, HASH256_BYTE_COUNT, true, hash_of_mb_concat_pk)) {
        FATAL_ERROR("ERROR hash creating Radix address");
    }

    os_memcpy(magic_concat_pubkey + length_unhashed, hash_of_mb_concat_pk, ADDRESS_CHECKSUM_BYTE_COUNT);

    return convert_byte_buffer_into_base58(magic_concat_pubkey, length_unhashed + ADDRESS_CHECKSUM_BYTE_COUNT, output_radix_addr_str);
}

bool does_address_contain_public_key(radix_address_t *address, cx_ecfp_public_key_t *compressed_public_key) {
    return does_address_contain_public_key_bytes(address, compressed_public_key->W);
}

bool does_address_contain_public_key_bytes(radix_address_t *address, uint8_t *compressed_public_key_bytes)
{
    // Might result in false negatives, you need to know that you
    // really are in fact passing in a compressed public key
    assert(compressed_public_key_bytes[0] == 0x02 || compressed_public_key_bytes[0] == 0x03);

    // 1 "magic" byte prefixes the address
    const size_t offset_of_public_key_within_address = 1; 

    for (int i = 0; i < PUBLIC_KEY_COMPRESSEED_BYTE_COUNT; ++i)
    {
        if (compressed_public_key_bytes[i] != address->bytes[i + offset_of_public_key_within_address]) {
            return false;
        }
    }
    return true;
}

void printRadixAddress(radix_address_t *address) {
    const size_t max_length = RADIX_ADDRESS_BASE58_CHAR_COUNT_MAX + 1;  // +1 for null terminator
    char address_b58[max_length];
    
    to_string_radix_address(address, address_b58, max_length);

    PRINTF("%s", address_b58);
}