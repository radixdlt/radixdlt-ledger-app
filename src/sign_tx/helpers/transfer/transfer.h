#ifndef TRANSFER_H
#define TRANSFER_H


#include "radix_resource_identifier.h"
#include "token_amount.h"

typedef struct {
    bool has_confirmed_serializer;

    bool is_address_set;
    radix_address_t address;

    bool is_amount_set;
    token_amount_t amount;

    bool is_token_definition_reference_set;
    radix_resource_identifier_t token_definition_reference;
} transfer_t;

void print_transfer(transfer_t *transfer);

#endif