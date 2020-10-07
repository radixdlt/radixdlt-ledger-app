#ifndef PARTICLEFIELD_H
#define PARTICLEFIELD_H

#include "ByteInterval.h"
#include "ParticleFieldType.h"

typedef struct {
    ParticleFieldType field_type;
    ByteInterval byte_interval;
} ParticleField;

bool is_field_empty(ParticleField *field);

void print_particle_field(ParticleField *field);

void zero_out_interval_in_field(ParticleField *field);

bool is_field_interval_empty(ParticleField *field);

#endif