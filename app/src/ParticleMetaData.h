typedef struct {
	uint16_t startsAt;
	uint16_t byteCount;
} ByteInterval;

// A 16 byte struct, containing byte intervals (offset + count) to 
// fields (values) of interest inside of a Particle. The byte offsets are
// measured from the start of the Atom (that the particle is part of).
// In case of a Non-TransferrableTokensParticle the byte interval tuple
// will have value (0, 0), thus we can distinquish between this ParticleMetaData
// being meta data for a `TransferrableTokensParticle` of other particle type
// by looking at `[addressOfRecipientByteInterval, amountByteInterval,
// tokenDefinitionReferenceByteInterval]` and check if all zero or not.
typedef struct {

	// ByteInterval particleItself;

	// In case of Non-TransferrableTokensParticle this will have value (0, 0)
	ByteInterval addressOfRecipientByteInterval;

	// In case of Non-TransferrableTokensParticle this will have value (0, 0)
	ByteInterval amountByteInterval;

	// Always present, disregarding of particle type
	ByteInterval serializerValueByteInterval;

	// In case of Non-TransferrableTokensParticle this will have value (0, 0)
	ByteInterval tokenDefinitionReferenceByteInterval;
} ParticleMetaData;