#include "signAtomUX.h"

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "key_and_signatures.h"
#include "ui.h"
#include "global_state.h"
#include "sha256_hash.h"
#include "dson.h"
#include "base_conversion.h"
#include "signAtomUI.h"
#include "common_macros.h"


static signAtomContext_t *ctx = &global.signAtomContext;
static signAtomUX_t *ux_state = &ctx.ux_state

static void empty_particle_meta_data() {
    explicit_bzero(&ux_state->particle_meta_data, sizeof(ParticleMetaData));
    ux_state->particle_meta_data.is_initialized = false;
}

static void empty_transfer() {
    explicit_bzero(&ux_state->transfer, sizeof(Transfer));
    ux_state->transfer.has_confirmed_serializer = false;
    ux_state->transfer.is_address_set = false;
    ux_state->transfer.is_amount_set = false;
    ux_state->transfer.is_token_definition_reference_set = false;
}

static void empty_atom_bytes_window() {
    empty_bytes(ux_state->atom_bytes_window);
}

void reset_ux_state() {
    ux_state->number_of_cached_bytes = 0;
    ux_state->user_has_accepted_non_transfer_data = false;
    ux_state->number_of_identified_up_particles = 0;
    empty_particle_meta_data();
    empty_transfer();
    empty_atom_bytes_window();
}

static void print_atom_bytes_window() {
    do_print_atom_bytes_window(ux_state->atom_bytes_window);
}

static void print_particle_metadata() {
    do_print_particle_metadata(ux_state->particle_meta_data);
}


static uint16_t end_of_atom_bytes_window() {
    return get_end_of_atom_bytes_window(&ux_state->atom_bytes_window);
}


static uint16_t start_of_atom_bytes_window() {
    return get_start_of_atom_bytes_window(&ux_state->atom_bytes_window);
}

static uint16_t offset_of_field_in_atom_bytes_window(
    ParticleField *particle_field
) {
    uint16_t offset = particle_field->startsAt - start_of_atom_bytes_window();

    return offset;
}

static bool can_parse_field_given_atom_bytes_window(ParticleField *particle_field) {

    if (end_of_atom_bytes_window() > end_index(particle_field->byte_interval)) {
        return false;
    } else {
        return true;
    }

}

static void cache_bytes(
    uint8_t *bytes,
    uint16_t number_of_bytes_to_cache
) {

    do_cache_bytes(
        &ux_state->atom_bytes_window,
        bytes,
        number_of_bytes_to_cache
    );
}


void received_particle_meta_data_bytes_from_host_machine(
    uint8_t *bytes,
    uint16_t number_of_bytes_received
) {

    do_populate_particle_meta_data(
        ux_state->particle_meta_data,
        bytes,
        number_of_bytes_received
    );

    if (!is_transfer_particle() && ux_state->user_has_accepted_non_transfer_data) {
        PRINTF("Just received meta data about non Transfer particle, but user has already accepted 'non transfer data', so we will ignore parsing the bytes for this particle, thus will will mark the meta data irrelevant and also cheat by increasing 'number_of_identified_up_particles' by one. Cheating... I know.\n");
        ux_state->number_of_identified_up_particles++; // cheating....
        zero_out_particle_metadata(&ux_state->particle_meta_data);
        assert(ux_state->atom_bytes_window.number_of_cached_bytes_from_last_payload == 0);
    }
}

static bool has_particle_meta_data() {
    return ux_state->particle_meta_data.is_initialized;
}

static bool finished_parsing_all_particles() {
    bool parsed_all_particles = ux_state->number_of_identified_up_particles == number_of_up_particles;
    if (parsed_all_particles) {
        assert(!has_particle_meta_data());
        assert(ux_state->atom_bytes_window.number_of_cached_bytes_from_last_payload == 0);
    }
    return parsed_all_particles;
}

static bool is_transfer_particle() {
    assert(has_particle_meta_data());
    return is_meta_data_about_transferrable_tokens_particle(ux_state->particle_meta_data);
}

static bool should_parse_atom_bytes() {
    if (finished_parsing_all_particles()) {
        PRINTF("Skipped parsing atom bytes since all particles have been parsed\n");
        return false;
    }

    // There are particles left to parse

    if (!has_particle_meta_data()) {
        PRINTF("Skipped parsing atom bytes since we don't have any particle meta data\n");
        return false;
    }

    // We have particle meta data

    if (!is_transfer_particle() && ux_state->user_has_accepted_non_transfer_data) {
        PRINTF("Skipped parsing atom bytes since it is non transfer which user has already accepted\n");
        return false;
    }
}

static void update_atom_bytes_window(
    uint8_t *bytes,
    uint16_t number_of_newly_received_atom_bytes
) {

    do_update_atom_bytes_window(
        &ux_state->atom_bytes_window,
        bytes,
        number_of_newly_received_atom_bytes
    );
}

static bool update_relevant_fields_and_get_first_relevant_one_if_any(
    ParticleField *candidate_field,
    void *output_relevat_field
) {
    return do_update_relevant_fields_and_get_first_relevant_one_if_any(
        candidate_field, 
        output_relevat_field,
        ux_state->atom_window->interval.startsAt
    );
}

// Returns sets `output_first_interval := candidate_interval` and returns `true` iff `candidate_interval.startsAt >= pointer_in_atom`,
// else does not set `output_first_interval`, marks `candidate_interval` as zero length and returns false
static bool do_update_relevant_fields_and_get_first_relevant_one_if_any(
    ParticleField *candidate_field,
    ParticleField *output_relevat_field,
    uint16_t pointer_in_atom
) {

    if (
        is_field_empty(candidate_field) ||
        candidate_field->byte_interval.startsAt < pointer_in_atom
    ) {
        PRINTF("WARNING Setting `byteCount` and `startsAt` to 0 in `candiate_field` to mark it as irrelevant/used!\n");
        candidate_field->byte_interval.byteCount = 0;
        candidate_field->byte_interval.startsAt = 0;
        return false;
    }

    *output_relevat_field = *candidate_field;
    return true;
}

// Returns `true` iff `output_particle_field` is set
static bool next_interval_to_parse_from_particle_meta_data(
    ParticleField *output_particle_field
) {
    assert(ux_state->particle_meta_data->is_initialized);

    bool is_output_set = iterate_fields_of_metadata(
        &ux_state->particle_meta_data,
        update_relevant_fields_and_get_first_relevant_one_if_any,
        output_particle_field
    );

    if (mark_metadata_uninitialized_if_all_intervals_are_zero()) {
        assert(!is_output_set);
    }

    return is_output_set;
}

static void ask_user_for_confirmation_of_non_transfer_data() {
    FATAL_ERROR("IMPL ME");
}


static void ask_user_for_confirmation_of_transfer() {
    FATAL_ERROR("IMPL ME");
}


static void do_parse_field_from_atom_bytes(
    ParticleField *particle_field,
    uint8_t *bytes
) {

    assert(can_parse_field_given_atom_bytes_window(particle_field));

    ParseFieldResult parse_result = parse_field_from_bytes_and_populate_transfer(
        particle_field,
        bytes,
        &ux_state->transfer
    );
    
    switch (parse_result) {
        case ParseFieldResultFinishedParsingTransfer:
            ask_user_for_confirmation_of_transfer();
            io_exchange(CHANNEL_APDU | IO_ASYNCH_REPLY, 0);
            // Blocked UX, waiting for user input
            empty_transfer();
            empty_particle_meta_data();
            break;
        
        case ParseFieldResultNonTransferDataFound:
            ask_user_for_confirmation_of_non_transfer_data();
            io_exchange(CHANNEL_APDU | IO_ASYNCH_REPLY, 0);
            // Blocked UX, waiting for user input
            ux_state->user_has_accepted_non_transfer_data = true;
            empty_particle_meta_data();
            break;
        
        case ParseFieldResultParsedPartOfTransfer:
            PRINTF("Parsed part of transfer...\n");
            break
    }

}

static void parse_atom_bytes() {
    assert(is_transfer_particle() || !ux_state->user_has_accepted_non_transfer_data);

    ParticleField next_particle_field;
    uint8_t parse_payload_loop_counter = 0;
    while (
        next_interval_to_parse_from_particle_meta_data(&next_particle_field)
    ) {
        PRINTF("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        PRINTF("Parse atom bytes loop: %d\n", parse_payload_loop_counter);
        print_atom_bytes_window();
        print_particle_metadata();

        if (end_of_atom_bytes_window() < next_particle_field.byte_interval.startsAt) {
            PRINTF("Skipped parsing atom bytes, since `atom_window` doesn't contain bytes of next relevant particle field (yet).\n");
            return;
        }

        uint8_t *read_bytes_needle_head = ux_state->atom_bytes_window.bytes + offset_of_field_in_atom_bytes_window(&particle_field);

        if (end_index(next_particle_field.byte_interval) > end_of_atom_bytes_window()) {
            PRINTF("Skipped parsing atom bytes, since we only have some of the relevant bytes of next particle field, we will cache the bytes we have and try parsing once we get the remaining particle fields bytes in the next payload.\n");
            uint16_t number_of_bytes_to_cache = end_index(next_particle_field.byte_interval) - end_of_atom_bytes_window();
            cache_bytes(
                read_bytes_needle_head,
                number_of_bytes_to_cache
            );
            return;
        }

        do_parse_field_from_atom_bytes(
            &particle_field,
            read_bytes_needle_head
        );

        parse_payload_loop_counter++;
    }
}

void received_atom_bytes_from_host_machine(
    uint8_t *bytes,
    uint16_t number_of_newly_received_atom_bytes
) {
    PRINTF("\n===================================================\n");

    if (!should_parse_atom_bytes()) {
        PRINTF("Skipped parsing atom bytes, since not needed\n");
        assert(ux_state->atom_bytes_window->number_of_cached_bytes_from_last_payload == 0); // validation of state consistency
        return;
    }

    update_atom_bytes_window(bytes, number_of_newly_received_atom_bytes);
    parse_atom_bytes();
}