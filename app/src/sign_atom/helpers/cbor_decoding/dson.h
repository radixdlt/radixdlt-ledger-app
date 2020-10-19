#ifndef DSON_H
#define DSON_H

#include "cbor.h"
#include "transfer.h"
#include "particle_field.h"

// Please see column "Additional info" in table "CBOR Major types": https://radixdlt.atlassian.net/wiki/spaces/AM/pages/56557727/DSON+Encoding
typedef enum
{
    CBORBytePrefixAddressByteString = 4,

    // Used for `amount`
    CBORBytePrefixUInt256ByteString = 5,

    // Used for `token_definition_reference`
    CBORBytePrefixRRIByteString = 6
} cbor_byte_prefix_t;

typedef enum {
  ParseFieldResultNonTransferDataFound = 1,
  ParseFieldResultParsedPartOfTransfer,  
  ParseFieldResultFinishedParsingTransfer  
} parse_field_result_t;

cbor_byte_prefix_t cborBytePrefixForParticleFieldType(particle_field_type_t field);

// Returns `true` iff `utf8_string` indicates a TransferrableTokensParticle
bool is_transferrable_tokens_particle_serializer(
    const char *utf8_string,
    const size_t string_length
);

// Returns `true` iff `cborValue` indicates a TransferrableTokensParticle
bool parseSerializer_is_ttp(
    const size_t valueByteCount,
    CborValue *cborValue);

parse_field_result_t parse_field_from_bytes_and_populate_transfer(
    particle_field_t *particle_field,
    uint8_t *bytes,
    transfer_t *transfer
);

#endif