#ifndef DSON_H
#define DSON_H

#include "cbor.h"
#include "transfer.h"
#include "particle_field.h"

// Please see column "Additional info" in table "CBOR Major types": https://radixdlt.atlassian.net/wiki/spaces/AM/pages/56557727/DSON+Encoding
typedef enum
{
    CBORBytePrefixByteStringAddress = 4,

    // Used for `amount`
    CBORBytePrefixByteStringUInt256 = 5,

    // Used for `token_definition_reference`
    CBORBytePrefixByteStringRadixResourceIdentifier = 6
} CBORBytePrefixByteStringType;

typedef enum {
  ParseFieldResultNonTransferDataFound = 1,
  ParseFieldResultParsedPartOfTransfer,  
  ParseFieldResultFinishedParsingTransfer  
} ParseFieldResult;

CBORBytePrefixByteStringType cbor_byte_prefix_for_particle_field_type(ParticleFieldType field);

// Returns `true` iff `utf8_string` indicates a TransferrableTokensParticle
bool is_transferrable_tokens_particle_serializer(
    const char *utf8_string,
    const size_t string_length
);

// Returns `true` iff `cbor_value` indicates a TransferrableTokensParticle
bool parse_serializer_check_if_transferrable_tokens_particle(
    const size_t value_byte_count,
    CborValue *cbor_value);

ParseFieldResult parse_field_from_bytes_and_populate_transfer(
    particle_field_t *particle_field,
    uint8_t *bytes,
    transfer_t *transfer
);

#endif