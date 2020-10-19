#ifndef TRANSFER_H
#define TRANSFER_H


#include "RadixResourceIdentifier.h"
#include "TokenAmount.h"

typedef struct {
    bool has_confirmed_serializer;

    bool is_address_set;
    RadixAddress address;

    bool is_amount_set;
    TokenAmount amount;

    bool is_token_definition_reference_set;
    RadixResourceIdentifier token_definition_reference;
} Transfer;

void print_transfer(Transfer *transfer);

#endif