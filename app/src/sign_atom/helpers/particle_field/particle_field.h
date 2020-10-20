#ifndef PARTICLEFIELD_H
#define PARTICLEFIELD_H

#include "byte_interval.h"
#include "particle_field_type.h"

typedef struct {
    ParticleFieldType field_type;
    byte_interval_t byte_interval;
    bool is_destroyed;
} particle_field_t;

void print_particle_field(particle_field_t *field);

void initialize_particle_field_with_bytes(
    particle_field_t *field, 
    ParticleFieldType field_type,
    uint8_t *bytes, uint16_t byte_count
);

#endif