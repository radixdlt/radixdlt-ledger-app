//
//  parse_field.h
//  LedgerXcodeProj
//
//  Created by Alexander Cyon on 2021-05-25.
//

#ifndef parse_field_h
#define parse_field_h

#include <stdio.h>
#include "transfer.h"
#include "action_field.h"

typedef enum {
  ParseFieldResultNonTransferDataFound = 1,
  ParseFieldResultParsedPartOfTransfer,
  ParseFieldResultFinishedParsingTransfer
} ParseFieldResult;

// Returns `true` iff `utf8_string` indicates a TransferrableTokensParticle
bool is_transferrable_tokens_particle_action_type(
    const char *utf8_string,
    const size_t string_length
);

// Returns `true` iff `bytes` indicates a TransferrableTokensParticle
bool parse_action_type_check_if_transferrable_tokens_particle(
    const size_t value_byte_count,
    uint8_t *bytes,
    const size_t bytecount
);

ParseFieldResult parse_field_from_bytes_and_populate_transfer(
    action_field_t *action_field,
    uint8_t *bytes,
    transfer_t *transfer,
    uint8_t *out_bytes,
    const size_t out_len
);

#endif /* parse_field_h */
