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
#include "AtomBytesWindow.h"


static signAtomContext_t *ctx = &global.signAtomContext;
static signAtomUX_t *ux_state = &global.signAtomContext.ux_state;

static void empty_particle_meta_data() {
    PRINTF("Emptying particle meta data\n");
    zero_out_particle_metadata(&ux_state->particle_meta_data);
}

static void empty_transfer() {
    PRINTF("Emptying transfer\n");
    explicit_bzero(&ux_state->transfer, sizeof(Transfer));
    ux_state->transfer.has_confirmed_serializer = false;
    ux_state->transfer.is_address_set = false;
    ux_state->transfer.is_amount_set = false;
    ux_state->transfer.is_token_definition_reference_set = false;
}

static void empty_atom_bytes_window() {
    empty_bytes(&ux_state->atom_bytes_window);
}

void reset_ux_state() {
    ux_state->atom_bytes_window.number_of_cached_bytes_from_last_payload = 0;
    ux_state->user_has_accepted_non_transfer_data = false;
    ux_state->is_users_public_key_calculated = false;
    ux_state->number_of_identified_up_particles = 0;
    ux_state->number_of_particle_meta_data_received = 0;
    
    empty_particle_meta_data();
    empty_transfer();
    empty_atom_bytes_window();
}

static void print_atom_bytes_window() {
    do_print_atom_bytes_window(&ux_state->atom_bytes_window);
}

static void print_particle_metadata() {
    do_print_particle_metadata(&ux_state->particle_meta_data);
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
    uint16_t offset = particle_field->byte_interval.startsAt - start_of_atom_bytes_window();
    PRINTF("Offset to start of field within atom bytes window: %d\n", offset);
    return offset;
}

static bool can_parse_field_given_atom_bytes_window(ParticleField *particle_field) {
    return end_of_atom_bytes_window() > end_index(&particle_field->byte_interval);
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

static bool has_particle_meta_data() {
    return ux_state->particle_meta_data.is_initialized;
}

static bool user_has_accepted_non_transfer_data() {
    return ux_state->user_has_accepted_non_transfer_data;
}

static bool finished_parsing_all_particles() {
    bool parsed_all_particles = ux_state->number_of_identified_up_particles == ux_state->number_of_up_particles;
    if (parsed_all_particles) {
        assert(!has_particle_meta_data());
        assert(ux_state->atom_bytes_window.number_of_cached_bytes_from_last_payload == 0);
    }
    return parsed_all_particles;
}

static bool is_transfer_particle() {
    assert(has_particle_meta_data());
    return is_meta_data_about_transferrable_tokens_particle(&ux_state->particle_meta_data);
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

    if (!is_transfer_particle() && user_has_accepted_non_transfer_data()) {
        PRINTF("Skipped parsing atom bytes since it is non transfer which user has already accepted\n");
        return false;
    }

    return true;
}

static void update_atom_bytes_window_by_sliding_bytes_since_parsed_field(
    ParticleField *parsed_particle_field
) {
    do_update_atom_bytes_window_by_sliding_bytes_since_parsed_field(
        &ux_state->atom_bytes_window,
        parsed_particle_field
    );
}

static void update_atom_bytes_window_with_new_bytes(
    uint8_t *bytes,
    uint16_t number_of_newly_received_atom_bytes
) {

    uint16_t number_of_processed_bytes_before_this_payload = ctx->number_of_atom_bytes_received - ux_state->atom_bytes_window.number_of_cached_bytes_from_last_payload - number_of_newly_received_atom_bytes;

    do_update_atom_bytes_window_with_new_bytes(
        &ux_state->atom_bytes_window,
        bytes,
        number_of_processed_bytes_before_this_payload,
        number_of_newly_received_atom_bytes
    );
}


// Returns sets `output_first_interval := candidate_interval` and returns `true` iff `candidate_interval.startsAt >= pointer_in_atom`,
// else does not set `output_first_interval`, marks `candidate_interval` as zero length and returns false
static bool do_update_relevant_fields_and_get_first_relevant_one_if_any(
    ParticleField *candidate_field,
    ParticleField *output_relevant_field,
    uint16_t pointer_in_atom
) {

    if (is_field_empty(candidate_field)) {
        return false;
    }

    if (candidate_field->byte_interval.startsAt < pointer_in_atom) {
        candidate_field->byte_interval.byteCount = 0;
        return false;
    }

    *output_relevant_field = *candidate_field;
    return true;
}


static bool update_relevant_fields_and_get_first_relevant_one_if_any(
    ParticleField *candidate_field,
    void *output_relevant_field
) {
    return do_update_relevant_fields_and_get_first_relevant_one_if_any(
        candidate_field, 
        output_relevant_field,
        ux_state->atom_bytes_window.interval.startsAt
    );
}

// Returns `true` iff `output_particle_field` is set
static bool next_particle_field_to_parse_from_particle_meta_data(
    ParticleField *output_particle_field
) {
    assert(has_particle_meta_data());

    bool is_output_set = iterate_fields_of_metadata(
        &ux_state->particle_meta_data,
        update_relevant_fields_and_get_first_relevant_one_if_any,
        output_particle_field
    );

    if (mark_metadata_uninitialized_if_all_intervals_are_zero(&ux_state->particle_meta_data)) {
        assert(!is_output_set);
    }

    return is_output_set;
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
    
    switch (parse_result) {
        case ParseFieldResultFinishedParsingTransfer:
            ux_state->number_of_identified_up_particles++;
            PRINTF("\n------------------------------------------------------\n");       
            PRINTF("\n===####!!!$$$ FINISHED PARSING TRANSFER $$$!!!###===\n");
            PRINTF("------------------------------------------------------\n");    
            ask_user_for_confirmation_of_transfer_if_to_other_address();
            empty_transfer();
            empty_particle_meta_data();
            break;
        
        case ParseFieldResultNonTransferDataFound:
            ux_state->number_of_identified_up_particles++;
            ask_user_for_confirmation_of_non_transfer_data();
            ux_state->user_has_accepted_non_transfer_data = true;
            empty_particle_meta_data();
            break;
        
        case ParseFieldResultParsedPartOfTransfer:
            PRINTF("Parsed part of transfer...\n");
            break;
    }
}

static void parse_atom_bytes() {
    assert(is_transfer_particle() || !user_has_accepted_non_transfer_data());

    ParticleField next_particle_field;

    while (has_particle_meta_data()) {

        print_atom_bytes_window();
        print_particle_metadata();

        if (!next_particle_field_to_parse_from_particle_meta_data(&next_particle_field)) {
            PRINTF("Skipped parsing atom bytes since we don't have ");
            break;
        }

        if (end_of_atom_bytes_window() < next_particle_field.byte_interval.startsAt) {
            PRINTF("Skipped parsing atom bytes, since `atom_window` doesn't contain bytes of next relevant particle field (yet).\n");
            return;
        }

        uint8_t *read_bytes_needle_head = ux_state->atom_bytes_window.bytes + offset_of_field_in_atom_bytes_window(&next_particle_field);

        if (!can_parse_field_given_atom_bytes_window(&next_particle_field)) {
            PRINTF("Skipped parsing atom bytes, since we only have some of the relevant bytes of next particle field, we will cache the bytes we have and try parsing once we get the remaining particle fields bytes in the next payload.\n");
            uint16_t number_of_bytes_to_cache = end_index(&next_particle_field.byte_interval) - end_of_atom_bytes_window();
            cache_bytes(
                read_bytes_needle_head,
                number_of_bytes_to_cache
            );
            return;
        }

        do_parse_field_from_atom_bytes(
            &next_particle_field,
            read_bytes_needle_head
        );

        update_atom_bytes_window_by_sliding_bytes_since_parsed_field(
            &next_particle_field
        );
    }
}

void received_atom_bytes_from_host_machine(
    uint8_t *bytes,
    uint16_t number_of_newly_received_atom_bytes
) {

    if (!should_parse_atom_bytes()) {
        assert(ux_state->atom_bytes_window.number_of_cached_bytes_from_last_payload == 0); // validation of state consistency
        return;
    }

    update_atom_bytes_window_with_new_bytes(bytes, number_of_newly_received_atom_bytes);
    parse_atom_bytes();
}

void received_particle_meta_data_bytes_from_host_machine(
    uint8_t *bytes,
    uint16_t number_of_bytes_received
) {

    do_populate_particle_meta_data(
        &ux_state->particle_meta_data,
        bytes,
        number_of_bytes_received
    );

    assert(ux_state->number_of_particle_meta_data_received == ux_state->number_of_identified_up_particles);

    ux_state->number_of_particle_meta_data_received++;

    assert(ux_state->particle_meta_data.byte_interval_of_particle_itself.startsAt == ctx->number_of_atom_bytes_received);

    if (!is_transfer_particle() && user_has_accepted_non_transfer_data()) {
        PRINTF("Just received meta data about non Transfer particle, but user has already accepted 'non transfer data', so we will ignore parsing the bytes for this particle, thus will will mark the meta data irrelevant and also cheat by increasing 'number_of_identified_up_particles' by one. Cheating... I know.\n");
        ux_state->number_of_identified_up_particles++; // cheating....
        zero_out_particle_metadata(&ux_state->particle_meta_data);
        assert(ux_state->atom_bytes_window.number_of_cached_bytes_from_last_payload == 0);
    }
}
