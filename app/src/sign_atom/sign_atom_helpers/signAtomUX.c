#include "signAtomUX.h"

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "key_and_signatures.h"
#include "ui.h"
#include "ux.h"
#include "global_state.h"
#include "sha256_hash.h"
#include "dson.h"
#include "base_conversion.h"
#include "signAtomUI.h"
#include "common_macros.h"
#include "RadixAddress.h"

static signAtomContext_t *ctx = &global.signAtomContext;
static signAtomUX_t *ux_state = &global.signAtomContext.ux_state;

static void empty_transfer() {
    explicit_bzero(&ux_state->transfer, sizeof(Transfer));
    ux_state->transfer.has_confirmed_serializer = false;
    ux_state->transfer.is_address_set = false;
    ux_state->transfer.is_amount_set = false;
    ux_state->transfer.is_token_definition_reference_set = false;
}

static void empty_particle_field() {
    explicit_bzero(&ux_state->next_particle_field_to_parse, sizeof(ParticleField));
    ux_state->next_particle_field_to_parse.is_destroyed = true;
}

static void did_identify_a_transferrable_tokens_particle() {
    identified_a_transferrable_tokens_particle(&ux_state->up_particles_counter);
}

static void did_identify_a_non_transferrable_tokens_particle() {
    identified_a_non_transferrable_tokens_particle(&ux_state->up_particles_counter);
}

static bool has_particle_field() {
    return !ux_state->next_particle_field_to_parse.is_destroyed;
}

static bool user_has_accepted_non_transfer_data() {
    return ux_state->user_has_accepted_non_transfer_data;
}

void reset_ux_state();

static bool is_transfer_change_back_to_me() {
    if (!ux_state->is_users_public_key_calculated) {
        derive_radix_key_pair(
            ctx->bip32_path, 
            &ctx->ux_state.my_public_key_compressed, 
            NULL // dont write private key
        );
        ux_state->is_users_public_key_calculated = true;
    }

    bool matching_pub_keys = matchesPublicKey(&ux_state->transfer.address, &ux_state->my_public_key_compressed);
    return matching_pub_keys;
}

static void user_accepted_non_transfer_data() {
    empty_particle_field();
    ux_state->user_has_accepted_non_transfer_data = true;
}

static void user_accepted_transfer_data() {
    empty_transfer();
    empty_particle_field();
}

static void ux_block() {
    io_exchange(IO_ASYNCH_REPLY, 0); // BLOCK ux
}
static void do_parse_field_from_atom_bytes(
    ParticleField *particle_field,
    uint8_t *bytes
) {
    ParseFieldResult parse_result = parse_field_from_bytes_and_populate_transfer(
        particle_field,
        bytes,
        &ux_state->transfer
    );

    empty_buffer();
   
    switch (parse_result) {
        case ParseFieldResultFinishedParsingTransfer:
            
            PRINTF("\n-=#$ Finished parsing whole transfer $#=-\n\n");

            did_identify_a_transferrable_tokens_particle();

            bool ask_user_to_confirm_transfer = !is_transfer_change_back_to_me();
            if (ask_user_to_confirm_transfer) {
            
                ask_user_for_confirmation_of_transfer_if_to_other_address();
                PRINTF("\n\n  ---> Waiting for input from user on Ledger device, needs to review & accept the transfer.\n");

                Transfer deep_copy_transfer;
                os_memcpy(&deep_copy_transfer, &ux_state->transfer, sizeof(Transfer));
                print_transfer(&deep_copy_transfer);

                ux_block();
            }
            user_accepted_transfer_data();
            break;
        case ParseFieldResultNonTransferDataFound:
            // PRINTF("@@@ Finished parsing non Transferrable Tokens Particle @@@\n");

            did_identify_a_non_transferrable_tokens_particle();

            if (ux_state->user_has_accepted_non_transfer_data) {
                user_accepted_non_transfer_data();
            } else {
                ask_user_for_confirmation_of_non_transfer_data();
                PRINTF("\n\n  ---> Waiting for input from user on Ledger device, needs to accept non-transfer data.\n");
                ux_block();
                user_accepted_non_transfer_data();
            }
            break;
        case ParseFieldResultParsedPartOfTransfer:
            break;
    }
}



void empty_buffer() {
    explicit_bzero(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
}

void received_atom_bytes_from_host_machine(
    uint8_t *bytes,
    uint16_t number_of_newly_received_atom_bytes
) {
    ui_update_progress_display();

    if (finished_parsing_all_particles() || !has_particle_field()) {
        // PRINTF("Skipping parsing field, finished parsing particles: %s, has particle field: %s\n", finished_parsing_all_particles() ? "TRUE" : "FALSE", has_particle_field() ? "TRUE" : "FALSE");
        return;
    }
     
    do_parse_field_from_atom_bytes(
        &ux_state->next_particle_field_to_parse,
        bytes
    );
    ux_state->next_particle_field_to_parse.is_destroyed = true;
  
}

void print_next_particle_field_to_parse() {
    print_particle_field(&ux_state->next_particle_field_to_parse);
}

void received_particle_field_metadata_bytes_from_host_machine(
    ParticleFieldType particle_field_type,
    uint8_t *bytes,
    uint16_t number_of_bytes_received
) {
    empty_particle_field();

    initialize_particle_field_with_bytes(
        &ux_state->next_particle_field_to_parse,
        particle_field_type,
        bytes,
        number_of_bytes_received
    );

    assert(ux_state->next_particle_field_to_parse.byte_interval.startsAt == ctx->number_of_atom_bytes_received);
}

void reset_ux_state() {
    ux_state->user_has_accepted_non_transfer_data = false;
    ux_state->is_users_public_key_calculated = false;
    
    empty_particle_field();
    empty_transfer();

    ui_init_progress_display();
}
