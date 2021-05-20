#ifndef RADIXADDRESS_H
#define RADIXADDRESS_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "key_and_signatures.h"

#define RADIX_ADDRESS_BYTE_COUNT 38 // MagicByte(1) + PubKeyCompr(33) + Checksum(4)
#define RADIX_ADDRESS_BASE58_CHAR_COUNT_MAX 52

typedef struct {
    uint8_t bytes[RADIX_ADDRESS_BYTE_COUNT];
} radix_address_t;

size_t to_string_radix_address(
    radix_address_t *address,
    char *output_buffer,
    const size_t size_of_buffer);

void printRadixAddress(radix_address_t *address);

bool does_address_contain_public_key(radix_address_t *address, cx_ecfp_public_key_t *compressed_public_key);
bool does_address_contain_public_key_bytes(radix_address_t *address, uint8_t *compressed_public_key_bytes);

int generate_public_address_from_pub_key_and_universe_magic(
    uint8_t magicByte, uint8_t *compressed_public_key_bytes,
    char *output_radix_addr_str, const size_t length_of_output_radix_addr_str);

#endif