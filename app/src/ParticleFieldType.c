#include "ParticleFieldType.h"
#include <os.h>

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
