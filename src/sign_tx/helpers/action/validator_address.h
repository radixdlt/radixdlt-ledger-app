//
//  validator_address.h
//  LedgerXcodeProj
//
//  Created by Alexander Cyon on 2021-05-26.
//

#ifndef validator_address_h
#define validator_address_h


#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "key_and_signatures.h"
#include "common_macros.h"

#define VALIDATOR_ADDRESS_HRP_LENGTH 2
#define VALIDATOR_ADDRESS_HRP_MAINNET "vr"
#define VALIDATOR_ADDRESS_HRP_BETANET "vb"

#define VALIDATOR_ADDRESS_BYTE_COUNT PUBLIC_KEY_COMPRESSEED_BYTE_COUNT
#define VALIDATOR_ADDRESS_BECH32_CHAR_COUNT_MAX 62

typedef struct {
    bool is_mainnet;
    uint8_t bytes[VALIDATOR_ADDRESS_BYTE_COUNT];
} validator_address_t;

size_t to_string_validator_address(
    validator_address_t *address,
    char *output_buffer,
    const size_t size_of_buffer);

void print_validator_address(validator_address_t *address);

#endif /* validator_address_h */
