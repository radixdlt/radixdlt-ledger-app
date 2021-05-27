#ifndef RADIXADDRESS_H
#define RADIXADDRESS_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "key_and_signatures.h"
#include "common_macros.h"

#define ACCOUNT_ADDRESS_VERSION_BYTE 0x04
#define ACCOUNT_ADDRESS_VERSION_DATA_LENGTH 1 // one byte

#define ACCOUNT_ADDRESS_HRP_LENGTH 3
#define ACCOUNT_ADDRESS_HRP_MAINNET "rdx"
#define ACCOUNT_ADDRESS_HRP_BETANET "brx"

#define ACCOUNT_ADDRESS_BYTE_COUNT (PUBLIC_KEY_COMPRESSEED_BYTE_COUNT + ACCOUNT_ADDRESS_VERSION_DATA_LENGTH)
#define ACCOUNT_ADDRESS_BECH32_CHAR_COUNT_MAX 65

typedef struct {
    bool is_mainnet;
    uint8_t bytes[ACCOUNT_ADDRESS_BYTE_COUNT];
} account_address_t;

size_t to_string_account_address(
    account_address_t *address,
    char *output_buffer,
    const size_t size_of_buffer);

void print_account_address(account_address_t *address);

bool does_account_address_contain_public_key(account_address_t *address, cx_ecfp_public_key_t *compressed_public_key);
bool does_account_address_contain_public_key_bytes(account_address_t *address, uint8_t *compressed_public_key_bytes);

#endif
