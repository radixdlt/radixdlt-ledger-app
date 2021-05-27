//
//  validator_address.c
//  LedgerXcodeProj
//
//  Created by Alexander Cyon on 2021-05-26.
//

#include "validator_address.h"
#include "abstract_address.h"

// Returns the de-facto length of the address copied over to `output_buffer`
size_t to_string_validator_address(
    validator_address_t *address,
    char *output_buffer,
    const size_t size_of_buffer
) {
    assert(size_of_buffer >= VALIDATOR_ADDRESS_BECH32_CHAR_COUNT_MAX + 1); // +1 for null
    
    if (!abstract_address_from_network_and_bytes(
            address->is_mainnet ? VALIDATOR_ADDRESS_HRP_MAINNET : VALIDATOR_ADDRESS_HRP_BETANET,
            VALIDATOR_ADDRESS_HRP_LENGTH,
            address->bytes,
            VALIDATOR_ADDRESS_BYTE_COUNT,
            true, // should pad
            output_buffer,
            size_of_buffer)
        ) {
        PRINTF("Bech32 encoding of validator address failed.\n");
        return 0;
    }
    return VALIDATOR_ADDRESS_BECH32_CHAR_COUNT_MAX;
}

void print_validator_address(validator_address_t *address) {
    const size_t max_length = VALIDATOR_ADDRESS_BECH32_CHAR_COUNT_MAX + 1;  // +1 for null terminator
    char bech_address[max_length];
    
    to_string_validator_address(address, bech_address, max_length);

    PRINTF("%s", address);
}
