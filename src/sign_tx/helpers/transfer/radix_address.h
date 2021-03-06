#ifndef RADIXADDRESS_H
#define RADIXADDRESS_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "key_and_signatures.h"
#include "common_macros.h"


#define RADIX_ADDRESS_VERSION_BYTE 0x04
#define RADIX_ADDRESS_VERSION_DATA_LENGTH 1 // one byte

#define RADIX_ADDRESS_BYTE_COUNT (PUBLIC_KEY_COMPRESSEED_BYTE_COUNT + RADIX_ADDRESS_VERSION_DATA_LENGTH)
#define RADIX_ADDRESS_BECH32_CHAR_COUNT_MAX 65

typedef struct {
    bool is_mainnet;
    uint8_t bytes[RADIX_ADDRESS_BYTE_COUNT];
} radix_address_t;

size_t to_string_radix_address(
    radix_address_t *address,
    char *output_buffer,
    const size_t size_of_buffer);

void printRadixAddress(radix_address_t *address);

bool does_address_contain_public_key(radix_address_t *address, cx_ecfp_public_key_t *compressed_public_key);
bool does_address_contain_public_key_bytes(radix_address_t *address, uint8_t *compressed_public_key_bytes);

#endif
