#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "radix.h"
#include "ux.h"
#include "cbor.h"

// Get a pointer to signHash's state variables. This is purely for
// convenience, so that we can refer to these variables concisely from any
// signHash-related function.
static signAtomContext_t *ctx = &global.signAtomContext;

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

// void handleSignAtom(
//     uint8_t p1, 
//     uint8_t p2, 
//     uint8_t *dataBuffer, 
//     uint16_t dataLength, 
//     volatile unsigned int *flags, 
//     volatile unsigned int *tx
// ) {
//     if (dataLength != 4) {
//         PRINTF("Expected 4 bytes of data buffer\n");
//         THROW(0x9101);
//     }
//     uint32_t deadbeef_count = U4BE(dataBuffer, 0);
//     PRINTF("deadbeef_count: %u\nNow performing SHA256 hash on it in chuncks", deadbeef_count);

//     cx_sha256_t sha2;
//     cx_sha256_init(&sha2);
//     uint8_t hashed[32];
//     for (uint32_t i = 0; i < deadbeef_count; ++i) {
//         size_t byte_count_deadbeef = 4;
//         const uint8_t oneBeef[] = { 0xde, 0xad, 0xbe, 0xef};
//         bool should_finalize_digest = (i == deadbeef_count-1);
//         if (should_finalize_digest) {
//             PRINTF("Finalizing Hash digest now\n");
//         }
//         if (!sha256_hash(&sha2, oneBeef, byte_count_deadbeef, should_finalize_digest, hashed)) {
//             PRINTF("FAILED TO HASH, iteration: %d\n", i);
//             break;
//         }
//     }

//     os_memmove(G_io_apdu_buffer, hashed, 32);
//     io_exchange_with_code(SW_OK, 32);
// }

#define LEDGER_MEMORY_MAX 1660 // dependent on size of code?

// Returns a boolean value indicating whether or not all `ctx->atomByteCount` bytes
// have been parsed, i.e. the whole atom has been parsed.
static bool parseParticlesAndUpdateHash() {
    return false;
}

static void parseAtom() {
    while(!parseParticlesAndUpdateHash()) {
        PRINTF("Finished parsing %u/%u particles", ctx->numberOfParticlesParsed, ctx->numberOfParticlesWithSpinUp);
        PRINTF("Finished parsing %u/%u bytes of the Atom", ctx->atomByteCountParsed, ctx->atomByteCount);
    }
}

// p1 = #particlesWithSpinUp
// p2 = NOT USED
// dataBuffer:
//          12 bytes: BIP32 PATH
//          2 bytes:  Atom Byte Count (CBOR encoded)
//          4-240 bytes: `P1` many offsets to particles à 4 bytes.
void handleSignAtom(
    uint8_t p1, 
    uint8_t p2, 
    uint8_t *dataBuffer, 
    uint16_t dataLength, 
    volatile unsigned int *flags, 
    volatile unsigned int *tx
) {
    // INPUT VALIDATION
    uint16_t expected_number_of_bip32_compents = 3;
    uint16_t byte_count_bip_component = 4;
    uint16_t expected_bip32_byte_count = expected_number_of_bip32_compents * byte_count_bip_component;
    
    if (dataLength < expected_bip32_byte_count) {
        PRINTF("'dataLength' should be at least: %u, but was: %d\n", expected_bip32_byte_count, dataLength);
        THROW(SW_INVALID_PARAM);
    }

    ctx->numberOfParticlesWithSpinUp = p1;
    if (ctx->numberOfParticlesWithSpinUp > MAX_AMOUNT_OF_PARTICLES_WITH_SPIN_UP || ctx->numberOfParticlesWithSpinUp < 1) {
        PRINTF("Number of particles with spin up must be at least 1 and cannot exceed: %d, but got: %d\n", MAX_AMOUNT_OF_PARTICLES_WITH_SPIN_UP, ctx->numberOfParticlesWithSpinUp);
        THROW(SW_INVALID_PARAM);
    }
 
    // PARSE DATA
    int dataOffset = 0;

    // READ BIP32 path from first chunk, available directly
    parse_bip32_path_from_apdu_command(dataBuffer, ctx->bip32Path, ctx->bip32PathString, sizeof(ctx->bip32PathString)); dataOffset += expected_bip32_byte_count;
    PRINTF("BIP 32 Path used for signing: %s\n", ctx->bip32PathString);

    // READ Atom Byte Count (CBOR encoded data)
    ctx->atomByteCount = U2LE(dataBuffer, dataOffset); dataOffset += 2;
    ctx->atomByteCountParsed = 0;

    // READ offsets to particles from first chunk, available directly
    ctx->numberOfParticlesParsed = 0;
    for (uint8_t particleIndex = 0; particleIndex < ctx->numberOfParticlesWithSpinUp; ++particleIndex) {
        uint16_t particleStartsAt = U2LE(dataBuffer, dataOffset); dataOffset += 2;
		uint16_t particleByteCount = U2LE(dataBuffer, dataOffset); dataOffset += 2;
        OffsetInAtom particleOffsetInAtom = { 
            .startsAt = particleStartsAt,
            .byteCount =particleByteCount
        };
        ctx->offsetsOfParticlesWithSpinUp[particleIndex] = particleOffsetInAtom;
    }

    // INSTRUCTIONS ON HOW TO PARSE PARTICLES FROM ATOM RECEIVED => start parsing
    // This will be done in `ctx->atomByteCount / CHUNK_SIZE` number of chunks
    // by 'streaming' data in this chunks using multiple `io_exchange` calls.

    parseAtom();
}