#include "ParticleFieldType.h"

// Please see column "Additional info" in table "CBOR Major types": https://radixdlt.atlassian.net/wiki/spaces/AM/pages/56557727/DSON+Encoding
typedef enum
{
    ByteStringCBORPrefixByte_address = 4,

    // Used for `amount`
    ByteStringCBORPrefixByte_uint256 = 5,

    // Used for `token_definition_reference`
    ByteStringCBORPrefixByte_rri = 6
} CBORBytePrefixForByteArray;

CBORBytePrefixForByteArray cborBytePrefixForParticleFieldType(ParticleFieldType field);

// Returns `true` iff `utf8_string` indicates a TransferrableTokensParticle
bool is_transferrable_tokens_particle_serializer(
    const char *utf8_string,
    const size_t string_length
);


// Returns `true` iff `cborValue` indicates a TransferrableTokensParticle
bool parseSerializer_is_ttp(
    const size_t valueByteCount,
    CborValue *cborValue);

void parseParticleFieldType(
    const size_t valueByteCount,
    CborValue *cborValue,
    ParticleFieldType field,

    uint8_t *output_buffer
);

void print_particle_field_type(ParticleFieldType field_type);