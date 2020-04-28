#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "radix.h"
#include "ux.h"
#include "cbor.h"

static bool sha256_hash(
    cx_sha256_t *hash_context,
    const uint8_t *bytes_to_hash, size_t byte_count, // INPUT

    bool should_finalize_else_update, // If this is set to FALSE, the `output_hash_digest` is not use
    uint8_t *output_hash_digest // OUTPUT length 32 bytes
) {
    if (!bytes_to_hash) {
        PRINTF("'sha256_hash': variable 'bytes_to_hash' is NULL, returning 'false'\n");
        return false;
    }

    if (byte_count <= 0) {
        PRINTF("'sha256_hash': variable 'byte_count' LEQ 0, returning 'false'\n");
        return false;
    }


    if (!output_hash_digest) {
        PRINTF("'sha256_hash': variable 'output_hash_digest' is null, returning 'false'\n");
        return false;
    }

    cx_hash(
        (cx_hash_t *)hash_context,
        should_finalize_else_update ? CX_LAST : 0, 
        bytes_to_hash, byte_count, 
        should_finalize_else_update ? output_hash_digest : NULL, 
        should_finalize_else_update ? 32 : 0
    );

    return true;
}

// p1, p2 not used
// 
// `dataLength` ought to be min 
// `dataBuffer`: CBOR encode atom bytes
// 
void handleSignAtom(
    uint8_t p1, 
    uint8_t p2, 
    uint8_t *dataBuffer, 
    uint16_t dataLength, 
    volatile unsigned int *flags, 
    volatile unsigned int *tx
) {
    if (dataLength != 4) {
        PRINTF("Expected 4 bytes of data buffer\n");
        THROW(0x9101);
    }
    uint32_t deadbeef_count = U4BE(dataBuffer, 0);
    PRINTF("deadbeef_count: %u\nNow performing SHA256 hash on it in chuncks", deadbeef_count);

    cx_sha256_t sha2;
    cx_sha256_init(&sha2);
    uint8_t hashed[32];
    for (uint32_t i = 0; i < deadbeef_count; ++i) {
        size_t byte_count_deadbeef = 4;
        const uint8_t oneBeef[] = { 0xde, 0xad, 0xbe, 0xef};
        bool should_finalize_digest = (i == deadbeef_count-1);
        if (should_finalize_digest) {
            PRINTF("Finalizing Hash digest now\n");
        }
        if (!sha256_hash(&sha2, oneBeef, byte_count_deadbeef, should_finalize_digest, hashed)) {
            PRINTF("FAILED TO HASH, iteration: %d\n", i);
            break;
        }
    }

    os_memmove(G_io_apdu_buffer, hashed, 32);
    io_exchange_with_code(SW_OK, 32);
}
	