#include "account_address.h"
#include "stdint.h"
#include "base_conversion.h"
#include "common_macros.h"
#include "sha256_hash.h"
#include <os_io_seproxyhal.h>
#include "abstract_address.h"

// Returns the de-facto length of the address copied over to `output_buffer`
size_t to_string_account_address(
    account_address_t *address,
    char *output_buffer,
    const size_t size_of_buffer
) { 
    assert(size_of_buffer >= ACCOUNT_ADDRESS_BECH32_CHAR_COUNT_MAX + 1); // +1 for null
    
    if (!abstract_address_from_network_and_bytes(
            address->is_mainnet ? ACCOUNT_ADDRESS_HRP_MAINNET : ACCOUNT_ADDRESS_HRP_BETANET,
            ACCOUNT_ADDRESS_HRP_LENGTH,
            address->bytes,
            ACCOUNT_ADDRESS_BYTE_COUNT,
            true, // should pad
            output_buffer,
            size_of_buffer)
        ) {
        PRINTF("Bech32 encoding of account address failed.\n");
        return 0;
    }
    return ACCOUNT_ADDRESS_BECH32_CHAR_COUNT_MAX;
}


bool does_account_address_contain_public_key(account_address_t *address, cx_ecfp_public_key_t *compressed_public_key) {
    return does_account_address_contain_public_key_bytes(address, compressed_public_key->W);
}

bool does_account_address_contain_public_key_bytes(account_address_t *address, uint8_t *compressed_public_key_bytes)
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

void print_account_address(account_address_t *address) {
    const size_t max_length = ACCOUNT_ADDRESS_BECH32_CHAR_COUNT_MAX + 1;  // +1 for null terminator
    char bech_address[max_length];
    
    to_string_account_address(address, bech_address, max_length);

    PRINTF("%s", address);
}
