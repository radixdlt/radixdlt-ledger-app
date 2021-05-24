#ifndef RADIXADDRESS_H
#define RADIXADDRESS_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "key_and_signatures.h"

#define RADIX_ADDRESS_BYTE_COUNT 41 // Network(1) + VersionByte(1) + PubKeyCompr(33) + Checksum(6)
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
