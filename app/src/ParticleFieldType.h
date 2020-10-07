
typedef enum {
    ParticleFieldTypeNoField = 0,
    ParticleFieldTypeAddress = 1,
    ParticleFieldTypeAmount,
    ParticleFieldTypeSerializer,
    ParticleFieldTypeTokenDefinitionReference,
} ParticleFieldType;

void print_particle_field_type(ParticleFieldType field_type);