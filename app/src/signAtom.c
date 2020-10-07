#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "key_and_signatures.h"
#include "ui.h"
#include "global_state.h"
#include "sha256_hash.h"
#include "base_conversion.h"
#include "signAtomUX.h"
#include "common_macros.h"

static signAtomContext_t *ctx = &global.signAtomContext;

static void reset_state() {
    ctx->atom_byte_count = 0;
    ctx->number_of_atom_bytes_received = 0;
    explicit_bzero(&ctx->bip32_path, NUMBER_OF_BIP32_COMPONENTS_IN_PATH * sizeof(uint32_t));
    reset_ux_state();
}

static void initiate_hasher() {
    explicit_bzero(&ctx->hash, HASH256_BYTE_COUNT);
    cx_sha256_init(&ctx->hasher);
}

static void initiate_state() {
    reset_state();
    initiate_hasher();
}

static void empty_buffer() {
    explicit_bzero(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
}

static void parse_bip_and_atom_size(
    uint8_t *dataBuffer,
    const uint16_t dataLength
) {
    // Input validation
    uint16_t expected_number_of_bip32_compents = 3;
    uint16_t byte_count_bip_component = 4;
    uint16_t expected_bip32_byte_count = expected_number_of_bip32_compents * byte_count_bip_component;
    size_t byte_count_of_atom_size = 2;
    uint16_t expected_data_length = expected_bip32_byte_count + byte_count_of_atom_size;
    
    if (dataLength != expected_data_length) {
        FATAL_ERROR("Incorrect 'dataLength', expected: %d, but got: %d", expected_data_length, dataLength);
    }

    // READ BIP32 path (12 bytes)
    parse_bip32_path_from_apdu_command(dataBuffer, ctx->bip32_path, NULL, 0);

    // READ Atom Byte Count (CBOR encoded data, max 2 bytes)
    ctx->atom_byte_count = U2BE(dataBuffer, expected_bip32_byte_count);
}

typedef enum {
    PayloadTypeIsParticleMetaData = 3,
    PayloadTypeIsAtomBytes = 4
} PayloadType;


static void update_hash(
    uint8_t* bytes, 
    uint16_t byte_count, 
    bool should_finalize_hash
) {
    PRINTF("Updating hash with #%d bytes\n", byte_count);
    update_hash_and_maybe_finalize(
        bytes,
        byte_count,
        should_finalize_hash,
        &ctx->hasher,
        ctx->hash
    );
}


static void receive_bytes_and_update_hash_and_update_ux() {
    // Get bytes from host machine
    empty_buffer();
    G_io_apdu_buffer[0] = 0x90; // 0x9000 == 'SW_OK'
    G_io_apdu_buffer[1] = 0x00; // 0x9000 == 'SW_OK'
    io_exchange(CHANNEL_APDU, 2);

    uint8_t p1 = G_io_apdu_buffer[OFFSET_P1];
    uint8_t* dataBuffer = G_io_apdu_buffer + OFFSET_CDATA;
    uint16_t number_of_atom_bytes_newly_received = G_io_apdu_buffer[OFFSET_LC];

    PayloadType payloadType = p1;

    // Check what kind of payload the bytes represent
    switch (payloadType)
    {
    case PayloadTypeIsAtomBytes:
        ctx->number_of_atom_bytes_received += number_of_atom_bytes_newly_received;

        // Update hash
        bool should_finalize_hash = ctx->number_of_atom_bytes_received == ctx->atom_byte_count;

        update_hash(
            dataBuffer,
            number_of_atom_bytes_newly_received,
            should_finalize_hash
        );

        received_atom_bytes_from_host_machine(dataBuffer, number_of_atom_bytes_newly_received);
    
    case PayloadTypeIsParticleMetaData:
        received_particle_meta_data_bytes_from_host_machine(dataBuffer, number_of_atom_bytes_newly_received);
    default:
        FATAL_ERROR("Unrecognized P1 value: %d\n", p1)
    }
}

static void parse_atom() {
    while (ctx->number_of_atom_bytes_parsed < ctx->atom_byte_count) {
        receive_bytes_and_update_hash_and_update_ux();
    }
    PRINTF("Finished parsing all atom bytes => Asking user to confirm hash on Ledger...\n");
    askUserForConfirmationOfHash();
}

static void parse_and_sign_atom(
    const uint8_t number_of_up_particles,
    uint8_t *dataBuffer,
    const uint16_t dataLength
) {
	initiate_state();
    ctx.ux_state.number_of_up_particles = number_of_up_particles;
	parse_bip_and_atom_size(dataBuffer, dataLength);
    
    parse_atom();
}

void handleSignAtom(
    uint8_t p1,
    uint8_t p2,
    uint8_t *dataBuffer,
    uint16_t dataLength,
    volatile unsigned int *flags,
    volatile unsigned int *tx)
{
    parse_and_sign_atom(
        p1,
        dataBuffer,
        dataLength
    );

    *flags |= IO_ASYNCH_REPLY;
}
