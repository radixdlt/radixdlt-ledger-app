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
#include "cbor.h"
#include "base_conversion.h"
#include "signAtomUI.h"
#include "common_macros.h"
#include "dson.h"


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

static uint16_t offset_of_field_in_atom_bytes_window(
    ParticleField *particle_field
) {
    uint16_t offset = particle_field->startsAt - ux_state->atom_bytes_window->interval.startsAt;

    return offset;
}

static bool can_parse_field_given_atom_bytes_window(ParticleField *particle_field) {

    uint16_t offset = offset_of_field_in_atom_bytes_window(particle_field);

    if (end_index(ux_state->atom_bytes_window->interval) > (offset + particle_field->byte_interval.byteCount)) {
        return false;
    } else {
        return true;
    }

}

static void parse_particle_field_from_atom_slice(
    ParticleField *particle_field
) {

    assert(can_parse_field_given_atom_bytes_window(particle_field));


    CborParser cborParser;
    CborValue cborValue;
    CborError cborError = cbor_parser_init(
        ux_state->atom_slice + offset_to_bytes_in_slice,
        field_byte_count,
        0, // flags
        &cborParser,
        &cborValue);

    if (cborError)
    {
        FATAL_ERROR("Failed to init cbor parser, CBOR eror: '%s'\n", cbor_error_string(cborError));
    }

    CborType type = cbor_value_get_type(&cborValue);
    size_t readLength;
    cborError = cbor_value_calculate_string_length(&cborValue, &readLength);

    if (cborError)
    {
        FATAL_ERROR("Failed to calculate length of coming cbor value, CBOR error: '%s'\n", cbor_error_string(cborError));
    }

    switch (type_of_field_to_parse)
    {
        case ParticleFieldTypeNoField: 
        FATAL_ERROR("Incorrect impl");
        break;

    case ParticleFieldTypeAddress:
        assert(type == CborByteStringType);
        assert(!ux_state->transfer.is_address_set);

        parseParticleFieldType(
            readLength, 
            &cborValue, 
            ParticleFieldTypeAddress, 
            ux_state->transfer.address.bytes
        );
        
        ux_state->transfer.is_address_set = true;

        PRINTF("Parsed address\n");
        // PRINTF("Parsed address: "); printRadixAddress(&ux_state->transfer.address);PRINTF("\n");

        break;

    case ParticleFieldTypeAmount:
        assert(type == CborByteStringType);
        assert(ux_state->transfer.is_address_set);
        assert(!ux_state->transfer.is_amount_set);

        parseParticleFieldType(
            readLength, 
            &cborValue, 
            ParticleFieldTypeAmount, 
            ux_state->transfer.amount.bytes
        );
        ux_state->transfer.is_amount_set = true;

        PRINTF("Parsed amount\n");
        // PRINTF("Parsed amount: "); printTokenAmount(&ux_state->transfer.amount);PRINTF("\n");

        break;

    case ParticleFieldTypeSerializer:
        assert(type == CborTextStringType);
        assert(!ux_state->transfer.has_confirmed_serializer);
        
        bool is_transferrable_tokens_particle_serializer = parseSerializer_is_ttp(readLength, &cborValue);

        assert(ux_state->transfer.is_address_set == is_transferrable_tokens_particle_serializer);
        assert(ux_state->transfer.is_amount_set == is_transferrable_tokens_particle_serializer);

        if (!is_transferrable_tokens_particle_serializer) {
            ux_state->non_transfer_data_found = true;
        } else {
            ux_state->transfer.has_confirmed_serializer = true;
        }

        break;

    case ParticleFieldTypeTokenDefinitionReference:
        assert(type == CborByteStringType);
        assert(ux_state->transfer.has_confirmed_serializer);
        assert(ux_state->transfer.is_address_set);
        assert(ux_state->transfer.is_amount_set);
        // assert(!ux_state->transfer.is_token_definition_reference_set);
        
        parseParticleFieldType(
            readLength, 
            &cborValue, 
            ParticleFieldTypeTokenDefinitionReference, 
            ux_state->transfer.token_definition_reference.bytes
        );

        // ux_state->transfer.is_token_definition_reference_set = true;
        
        PRINTF("Parsed RRI\n");
        // PRINTF("Parsed RRI: "); printRRI(&ux_state->transfer.token_definition_reference);PRINTF("\n");

        if (!is_transfer_change_back_to_me()) {
            PRINTF("Asking for input from user to approve transfer\n");
    
            // display_lines("Review", "Transfer", resume_parsing_atom);
            display_lines("Review", "Transfer", prepareForApprovalOfAddress);
    
            io_exchange(CHANNEL_APDU | IO_ASYNCH_REPLY, 0);
        } else {
            PRINTF("Found transfer, but is change back to me, so skipping it..\n");
        }

  
        PRINTF("Awesome, resumed program...now emptying transfer\n");
        empty_transfer();

        break;
    }

    // return readLength;
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
        assert(ux_state->number_of_cached_bytes == 0);
    }
}

static bool has_particle_meta_data() {
    return ux_state->particle_meta_data.is_initialized;
}

static bool finished_parsing_all_particles() {
    bool parsed_all_particles = ux_state->number_of_identified_up_particles == number_of_up_particles;
    if (parsed_all_particles) {
        assert(!has_particle_meta_data());
        assert(ux_state->number_of_cached_bytes == 0);
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

    uint8_t number_of_cached_bytes_from_last_payload = ux_state->atom_bytes_window.number_of_cached_bytes_from_last_payload;

    uint16_t number_of_processed_bytes_before_this_payload = ctx->number_of_atom_bytes_received - number_of_cached_bytes_from_last_payload - number_of_newly_received_atom_bytes;

    uint16_t number_of_bytes_to_process = number_of_newly_received_atom_bytes + number_of_cached_bytes_from_last_payload;

    ux_state->atom_bytes_window->interval = {
        .startsAt = number_of_processed_bytes_before_this_payload,
        .byteCount = number_of_bytes_to_process
    };

    os_memcpy(
        ux_state->atom_bytes_window->bytes + number_of_cached_bytes_from_last_payload,
        bytes,
        number_of_newly_received_atom_bytes
    );

    // 'atom_slice' should now contain 'number_of_bytes_to_process' bytes
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

static void parse_atom_bytes() {
    assert(is_transfer_particle() || !ux_state->user_has_accepted_non_transfer_data);


    ParticleField next_particle_field;
    uint8_t parse_payload_loop_counter = 0;
    while (
        next_interval_to_parse_from_particle_meta_data(&next_particle_field)
    ) {
        PRINTF("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        PRINTF("Parse atom bytes loop: %d\n");
        print_atom_bytes_window();
        print_particle_metadata();

        if (end_index(ux_state->atom_window->interval) < next_particle_field.byte_interval.startsAt) {
            PRINTF("Skipped parsing atom bytes, since `atom_window` doesn't contain bytes of next relevant particle field (yet).\n");
            return;
        }

        if (end_index(next_particle_field.byte_interval) > end_index(ux_state->atom_window->interval)) {
            PRINTF("Skipped parsing atom bytes, since we only have some of the relevant bytes of next particle field, we will cache the bytes we have and try parsing once we get the remaining particle fields bytes in the next payload.\n");
            cache_bytes();
            return;
        }

        parse_particle_field_from_atom_slice(&next_particle_field);

        parse_payload_loop_counter ++;
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