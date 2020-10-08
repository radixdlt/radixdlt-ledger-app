#ifndef PARTICLEMETADATA_H
#define PARTICLEMETADATA_H

#include <stdint.h>
#include <stdbool.h>
#include "ParticleField.h"

// A 16 byte struct, containing byte intervals (offset + count) to 
// fields (values) of interest inside of a Particle. The byte offsets are
// measured from the start of the Atom (that the particle is part of).
// In case of a Non-TransferrableTokensParticle the byte interval tuple
// will have value (0, 0), thus we can distinquish between this ParticleMetaData
// being meta data for a `TransferrableTokensParticle` of other particle type
// by looking at `[addressOfRecipientByteInterval, amountByteInterval,
// token_definition_referenceByteInterval]` and check if all zero or not.
typedef struct {

	// since ctx has storage for a 'ParticleMetaData', but not being a pointer, and
	// we want to avoid using 'is all zero' solution.
	bool is_initialized;

	ByteInterval byte_interval_of_particle_itself;

	// In case of Non-TransferrableTokensParticle this will have value (0, 0)
	ParticleField address_field;

	// In case of Non-TransferrableTokensParticle this will have value (0, 0)
	ParticleField amount_field;

	// Always present, disregarding of particle type
	ParticleField serializer_field;

	// In case of Non-TransferrableTokensParticle this will have value (0, 0)
	ParticleField token_definition_reference_field;
} ParticleMetaData;


uint16_t last_byte_of_particle_from_its_meta_data(ParticleMetaData *particle_meta_data);

bool is_meta_data_about_transferrable_tokens_particle(ParticleMetaData *particle_meta_data);

bool is_all_zero(
    ParticleMetaData *particle_meta_data
);

// Returns `true` iff all intervals of particle_meta_data are zero
bool mark_metadata_uninitialized_if_all_intervals_are_zero(
    ParticleMetaData *particle_meta_data
);

// void get_first_interval_to_parse_from_particle_meta_data(
//     ParticleMetaData *particle_meta_data
//     ByteInterval *output_first_interval
// );

// // `(ByteInterval) -> bool` - returns true if done
// typedef bool (*CheckByteInterval)(ByteInterval *check_interval, void* result);

// void iterate_intervals_of_metadata(
// 	ParticleMetaData *particle_meta_data,
// 	CheckByteInterval check_if_done_with_metadata,
// 	void *result
// );


typedef bool (*CheckParticleField)(ParticleField *check_field, void* result);

// returns true if any field in particle_meta_data fulfilled `conditional_set_result_based_on_particle_field`
bool iterate_fields_of_metadata(
	ParticleMetaData *particle_meta_data,
	CheckParticleField conditional_set_result_based_on_particle_field,
	void *result
);

void do_print_particle_metadata(ParticleMetaData *particle_meta_data);

void do_populate_particle_meta_data(
	ParticleMetaData *particle_meta_data,
    uint8_t *bytes,
    const uint16_t number_of_particle_meta_data_bytes
);

void zero_out_particle_metadata(ParticleMetaData *particle_meta_data);

#endif