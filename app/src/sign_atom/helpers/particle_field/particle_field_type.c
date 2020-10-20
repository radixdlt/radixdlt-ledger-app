#include "particle_field_type.h"
#include <os.h>
#include "common_macros.h"

void print_particle_field_type(ParticleFieldType field_type) {
    switch (field_type)
    {
    case ParticleFieldTypeNoField:
        PRINTF("ERROR No Field");
        break;
    case ParticleFieldTypeAddress:
        PRINTF("Address Field");
        break;
    case ParticleFieldTypeAmount:
        PRINTF("Amount Field");
        break;
    case ParticleFieldTypeSerializer:
        PRINTF("Serializer Field");
        break;
    case ParticleFieldTypeTokenDefinitionReference:
        PRINTF("TokenDefinitionReference Field");
        break;
    }
}


bool is_valid_particle_field_type(ParticleFieldType field_type) {
        switch (field_type)
    {
 
    case ParticleFieldTypeAddress:
    case ParticleFieldTypeAmount:
    case ParticleFieldTypeSerializer:
    case ParticleFieldTypeTokenDefinitionReference:
        return true;

    case ParticleFieldTypeNoField:
    default:
        FATAL_ERROR("ERROR No Field");
        return false;
    }
}