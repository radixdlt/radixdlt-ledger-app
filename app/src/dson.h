#include "cbor.h"
#include "Transfer.h"
#include "ParticleField.h"

// Please see column "Additional info" in table "CBOR Major types": https://radixdlt.atlassian.net/wiki/spaces/AM/pages/56557727/DSON+Encoding
typedef enum
{
    ByteStringCBORPrefixByte_address = 4,

    // Used for `amount`
    ByteStringCBORPrefixByte_uint256 = 5,

    // Used for `token_definition_reference`
    ByteStringCBORPrefixByte_rri = 6
} CBORBytePrefixForByteArray;

typedef enum {
  ParseFieldResultNonTransferDataFound = 1,
  ParseFieldResultParsedPartOfTransfer,  
  ParseFieldResultFinishedParsingTransfer  
} ParseFieldResult;

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

ParseFieldResult parse_field_from_bytes_and_populate_transfer(
    ParticleField *particle_field,
    uint8_t *bytes,
    Transfer *transfer
);