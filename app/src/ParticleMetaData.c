#include "ParticleMetaData.h"
#include <os_io_seproxyhal.h>
#include "common_macros.h"

uint16_t last_byte_of_particle_from_its_meta_data(ParticleMetaData *particle_meta_data) {
    assert(particle_meta_data->is_initialized);
    return end_index(&particle_meta_data->byte_interval_of_particle_itself);
}

bool is_meta_data_about_transferrable_tokens_particle(ParticleMetaData *particle_meta_data) {
    assert(particle_meta_data->is_initialized);

    return !(
		is_field_interval_empty(&particle_meta_data->address_field) ||
		is_field_interval_empty(&particle_meta_data->amount_field) ||
		is_field_interval_empty(&particle_meta_data->token_definition_reference_field)
	);
}

// Returns `true` iff all intervals of particle_meta_data are zero
bool are_all_fields_empty(
    ParticleMetaData *particle_meta_data
) {
    return is_field_empty(&particle_meta_data->address_field) &&
        is_field_empty(&particle_meta_data->amount_field) &&
        is_field_empty(&particle_meta_data->serializer_field) &&
        is_field_empty(&particle_meta_data->token_definition_reference_field);
}

// Returns `true` iff all intervals of particle_meta_data are zero
bool mark_metadata_uninitialized_if_all_intervals_are_zero(
    ParticleMetaData *particle_meta_data
) {
    if (are_all_fields_empty(particle_meta_data)) {
        particle_meta_data->is_initialized = false;
        return true;
    }

    return false;
}

// void get_first_interval_to_parse_from_particle_meta_data(
//     ParticleMetaData *particle_meta_data
//     ByteInterval *output_first_interval
// ) {

//     assert(particle_meta_data->is_initialized);

//     if (particle_meta_data->addressOfRecipientByteInterval.byteCount > 0) {
//         *output_first_interval = *particle_meta_data->addressOfRecipientByteInterval;
//         return;
//     }

//     if (particle_meta_data->amountByteInterval.byteCount > 0) {
//         *output_first_interval = *particle_meta_data->amountByteInterval;
//         return;
//     }

//     if (particle_meta_data->serializerValueByteInterval.byteCount > 0) {
//         *output_first_interval = *particle_meta_data->serializerValueByteInterval;
//         return;
//     }

//     if (particle_meta_data->token_definition_referenceByteInterval.byteCount > 0) {
//         *output_first_interval = *particle_meta_data->token_definition_referenceByteInterval;
//         return;
//     }

//     FATAL_ERROR("Bad state, only zero byte intervals.");
// }

// void iterate_intervals_of_metadata(
// 	ParticleMetaData *particle_meta_data,
// 	CheckByteInterval check_if_done_with_metadata,
// 	void *result
// ) {
// 	if (
// 		check_if_done_with_metadata(
// 			particle_meta_data->addressOfRecipientByteInterval,
// 			result
// 		)
// 	) {
// 		return;
// 	}

// 	if (
// 		check_if_done_with_metadata(
// 			particle_meta_data->amountByteInterval,
// 			result
// 		)
// 	) {
// 		return;
// 	}

// 	if (
// 		check_if_done_with_metadata(
// 			particle_meta_data->serializerValueByteInterval,
// 			result
// 		)
// 	) {
// 		return;
// 	}

// 	if (
// 		check_if_done_with_metadata(
// 			particle_meta_data->token_definition_referenceByteInterval,
// 			result
// 		)
// 	) {
// 		return;
// 	}
// }

typedef bool (*CheckParticleField)(ParticleField *check_field, void* result);

// returns true if any field in particle_meta_data fulfilled `conditional_set_result_based_on_particle_field`
bool iterate_intervals_of_metadata(
	ParticleMetaData *particle_meta_data,
	CheckParticleField conditional_set_result_based_on_particle_field,
	void *result
) {
	if (
		conditional_set_result_based_on_particle_field(
			&particle_meta_data->address_field,
			result
		)
	) {
		return true;
	}

	if (
		conditional_set_result_based_on_particle_field(
			&particle_meta_data->amount_field,
			result
		)
	) {
		return true;
	}

	if (
		conditional_set_result_based_on_particle_field(
			&particle_meta_data->serializer_field,
			result
		)
	) {
		return true;
	}

	if (
		conditional_set_result_based_on_particle_field(
			&particle_meta_data->token_definition_reference_field,
			result
		)
	) {
		return true;
	}

    return false;
}

static void populate_interval(
	ByteInterval *interval,
	uint8_t *bytes,
	uint16_t *offset
) {
	
	interval->startsAt = U2BE(bytes, *offset); *offset += 2;
    interval->byteCount = U2BE(bytes, *offset); *offset += 2;
}

static void populate_field(
	ParticleField *field,
	uint8_t *bytes,
	uint16_t *offset
) {
	populate_interval(
		&field->byte_interval,
		bytes,
		offset
	);
}

void zero_out_particle_metadata(ParticleMetaData *particle_meta_data) {
	zero_out_interval(&particle_meta_data->byte_interval_of_particle_itself);
	zero_out_interval_in_field(&particle_meta_data->address_field);
	zero_out_interval_in_field(&particle_meta_data->amount_field);
	zero_out_interval_in_field(&particle_meta_data->serializer_field);
	zero_out_interval_in_field(&particle_meta_data->token_definition_reference_field);
	particle_meta_data->is_initialized = false;
}

void do_populate_particle_meta_data(
	ParticleMetaData *particle_meta_data,
    uint8_t *bytes,
    const uint16_t number_of_particle_meta_data_bytes
) {
    assert(!particle_meta_data->is_initialized);

    // READ meta data about particles from first chunk, available directly
    assert(number_of_particle_meta_data_bytes == 20);
    
    PRINTF("Received particle meta data hex string:\n%.*H\n", number_of_particle_meta_data_bytes, bytes);
    uint16_t offset = 0;

    PRINTF("Zeroing out old particle meta data now...\n");
    zero_out_particle_metadata(particle_meta_data);

	populate_interval(&particle_meta_data->byte_interval_of_particle_itself, bytes, &offset);

	populate_field(&particle_meta_data->amount_field, bytes, &offset);
	populate_field(&particle_meta_data->serializer_field, bytes, &offset);
	populate_field(&particle_meta_data->token_definition_reference_field, bytes, &offset);

    PRINTF("Finished parsing particle meta data...\n");

    particle_meta_data->is_initialized = true;

	assert(offset == number_of_particle_meta_data_bytes);
}

void do_print_particle_metadata(ParticleMetaData *particle_meta_data) {

	PRINTF("Particle Meta Data\n");
	print_interval(&particle_meta_data->byte_interval_of_particle_itself);
	print_particle_field(&particle_meta_data->address_field);
	print_particle_field(&particle_meta_data->amount_field);
	print_particle_field(&particle_meta_data->serializer_field);
	print_particle_field(&particle_meta_data->token_definition_reference_field);
	PRINTF("\n");
}
