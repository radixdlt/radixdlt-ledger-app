#ifndef PARTICLEFIELDTYPE_H
#define PARTICLEFIELDTYPE_H

#include <stdbool.h>

typedef enum {
    ParticleFieldTypeNoField = 0,
    ParticleFieldTypeAddress = 200,
    ParticleFieldTypeAmount = 201,
    ParticleFieldTypeSerializer = 202,
    ParticleFieldTypeTokenDefinitionReference = 203,
} ParticleFieldType;

void print_particle_field_type(ParticleFieldType field_type);
bool is_valid_particle_field_type(ParticleFieldType field_type);

#endif