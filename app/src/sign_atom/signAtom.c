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
#include "signAtomUI.h"
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

    assert(dataLength == expected_data_length);

    uint8_t bip_32_string[BIP32_PATH_STRING_MAX_LENGTH];

    parse_bip32_path_from_apdu_command(dataBuffer, ctx->bip32_path, bip_32_string, BIP32_PATH_STRING_MAX_LENGTH);
    ctx->atom_byte_count = U2BE(dataBuffer, expected_bip32_byte_count);

    PRINTF("Finished parsing initial setup package specifying that the Atom we are about to parse contains #%d bytes and #%d up particles and is to be signed with key at BIP32 derivation path: '%s'\n", ctx->atom_byte_count, total_number_of_up_particles(&ctx->ux_state.up_particles_counter.in_atom), bip_32_string);
}

typedef enum {
    PayloadTypeIsAtomBytes = 100,
    PayloadTypeIsParticleFieldMetaData = 101
} PayloadType;


static void update_hash(
    uint8_t* bytes, 
    uint16_t byte_count, 
    bool should_finalize_hash
) {
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
    if (G_io_apdu_buffer[OFFSET_LC] == 0) {
        // Requesting more bytes from host machine
        empty_buffer();
        G_io_apdu_buffer[0] = 0x90; // 0x9000 == 'SW_OK'
        G_io_apdu_buffer[1] = 0x00; // 0x9000 == 'SW_OK'
        io_exchange(CHANNEL_APDU, 2);
        
    } else {
       // Got bytes during UX flow... nothing to do.
    }

    uint8_t p1 = G_io_apdu_buffer[OFFSET_P1];
    uint8_t p2 = G_io_apdu_buffer[OFFSET_P2];
    uint8_t* dataBuffer = G_io_apdu_buffer + OFFSET_CDATA;
    uint16_t number_of_bytes_received = G_io_apdu_buffer[OFFSET_LC];
    G_io_apdu_buffer[OFFSET_LC] = 0;

    PayloadType payloadType = p1;

    uint16_t bytes_received_before_this_payload = ctx->number_of_atom_bytes_received;
    uint16_t bytes_received_incl_this_payload = bytes_received_before_this_payload + number_of_bytes_received;

    // Check what kind of payload the bytes represent
    switch (payloadType)
    {
    case PayloadTypeIsAtomBytes:
        ctx->number_of_atom_bytes_received = bytes_received_incl_this_payload;
        
        PRINTF("Received atom bytes window: [%d-%d] (#%d), got #%d/#%d of whole atom.\n", bytes_received_before_this_payload, bytes_received_incl_this_payload, number_of_bytes_received, bytes_received_incl_this_payload, ctx->atom_byte_count); 

        // Update hash
        bool should_finalize_hash = bytes_received_incl_this_payload == ctx->atom_byte_count;

        update_hash(
            dataBuffer,
            number_of_bytes_received,
            should_finalize_hash
        );

        received_atom_bytes_from_host_machine(
            dataBuffer, 
            number_of_bytes_received
        );
    
        break;
    case PayloadTypeIsParticleFieldMetaData:
        PRINTF("Received payload from host machine - particle field metadata\n");
        ParticleFieldType particle_field_type = (ParticleFieldType) p2;
        assert(is_valid_particle_field_type(particle_field_type));
        received_particle_field_metadata_bytes_from_host_machine(
            particle_field_type,
            dataBuffer, 
            number_of_bytes_received
        );
        print_next_particle_field_to_parse();PRINTF("\n");

        break;
    default:
        FATAL_ERROR("Unrecognized P1 value: %d\n", p1)
    }
}

static void parse_atom() {
    empty_buffer();
    while (ctx->number_of_atom_bytes_received < ctx->atom_byte_count) {
        receive_bytes_and_update_hash_and_update_ux();
    }
}

void handleSignAtom(
    uint8_t p1,
    uint8_t p2,
    uint8_t *dataBuffer,
    uint16_t dataLength,
    volatile unsigned int *flags,
    volatile unsigned int *tx)
{

    PRINTF("\n\n\n._-=~$#@   START OF SIGN ATOM   @#$=~-_.\n\n\n");

	initiate_state();
    init_particles_counter(
        &ctx->ux_state.up_particles_counter,
        p1, // total_number_of_up_particles
        p2 // number_of_up_transferrable_tokens_particles
    );
    ctx->ux_state.__DEBUG_MODE_skip_short_transfer_reviews = false;
	parse_bip_and_atom_size(dataBuffer, dataLength);
    parse_atom();
    *flags |= IO_ASYNCH_REPLY; 

    PRINTF("\n\n  ---> Waiting for input from user on Ledger device, needs to verify the hash, and confirm signing of it.\n");
    ask_user_to_verify_hash_before_signing();

}