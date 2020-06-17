typedef enum {
    NoParticleTypeParsedYet = 0,
    MessageParticleType = 1,
    RRIParticleType,
    FixedSupplyTokenDefinitionParticleType,
    MutableSupplyTokenDefinitionParticleType,
    UnallocatedTokensParticleType,
    TransferrableTokensParticleType,
    UniqueParticleType,

    ParticleType_is_unknown
} RadixParticleTypes;