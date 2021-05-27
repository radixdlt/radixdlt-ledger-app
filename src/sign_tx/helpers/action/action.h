#ifndef TRANSFER_H
#define TRANSFER_H

#include "action_type.h"

#include "radix_resource_identifier.h"
#include "account_address.h"
#include "validator_address.h"
#include "token_amount.h"

typedef struct {
    
    ActionType action_type;
    
    account_address_t from;
    
    // To save memory, we store the "to" context types in a global union,
    // taking advantage of the fact that we either send "to" a validator address
    // or an account address
    union {
        validator_address_t validator_address;
        account_address_t account_address;
    } to_u;

    token_amount_t amount;

    radix_resource_identifier_t rri;
} action_t;

void print_action(action_t *action);

#endif
