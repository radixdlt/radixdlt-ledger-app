#include "ParticleField.h"
#include "ByteInterval.h"

bool is_field_empty(ParticleField *field) {
    return is_interval_empty(field->byte_interval);
}

void print_particle_field(ParticleField *field) {
    print_particle_field_type(field->field_type);
    print_interval(field->byte_interval);
}

void zero_out_interval_in_field(ParticleField *field) {
	zero_out_interval(&field->byte_interval);
}

bool is_field_interval_empty(ParticleField *field) {
    return is_interval_empty(&field->byte_interval);
}