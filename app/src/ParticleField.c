#include "ParticleField.h"
#include <os.h>
#include "common_macros.h"

static uint16_t populate_interval(
	ByteInterval *interval,
	uint8_t *bytes
) {
	
	uint16_t offset = 0;
	interval->startsAt = U2BE(bytes, offset); offset += 2;
    interval->byteCount = U2BE(bytes, offset); offset += 2;
    return offset;
}

void print_particle_field(ParticleField *field) {
    assert(field->is_destroyed == false);
    print_particle_field_type(field->field_type);
    PRINTF(" ");
    print_interval(&field->byte_interval);
}


void initialize_particle_field_with_bytes(
    ParticleField *field, 
    ParticleFieldType field_type,
    uint8_t *bytes, uint16_t byte_count
) {
    assert(is_valid_particle_field_type(field_type));
    assert(byte_count == 4);
    populate_interval(
        &field->byte_interval,
        bytes
    );
    field->is_destroyed = false;
    assert(field->byte_interval.byteCount > 0);
}