#ifndef PARTICLEFIELD_H
#define PARTICLEFIELD_H

#include "ByteInterval.h"
#include "ParticleFieldType.h"

typedef struct {
    ParticleFieldType field_type;
    ByteInterval byte_interval;
    bool is_destroyed;
} ParticleField;

void print_particle_field(ParticleField *field);

void initialize_particle_field_with_bytes(
    ParticleField *field, 
    ParticleFieldType field_type,
    uint8_t *bytes, uint16_t byte_count
);

#endif