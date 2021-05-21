#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "key_and_signatures.h"
#include "ui.h"
#include "common_macros.h"

bool sha256_hash(
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

void update_hash_and_maybe_finalize(
    uint8_t* bytes, 
    uint16_t byte_count, 
    bool should_finalize_hash,
    cx_sha256_t *hasher,
    uint8_t* output_bytes
) {
    // UPDATE HASH
    bool success = sha256_hash(
        hasher,
        bytes,
        byte_count,
        should_finalize_hash,
        output_bytes);

    assert(success);

    if (should_finalize_hash) {
        cx_sha256_init(hasher);

        // tmp copy of firstHash
        uint8_t hashedOnce[HASH256_BYTE_COUNT];
        os_memcpy(hashedOnce, output_bytes, HASH256_BYTE_COUNT);

        success = sha256_hash(
            hasher,
            hashedOnce,
            HASH256_BYTE_COUNT,
            true,
            output_bytes // put hash of hash in ctx->hash
        );

        assert(success);

        PRINTF("Finalized hash to: '%.*h'\n", HASH256_BYTE_COUNT, output_bytes);
    }
}
