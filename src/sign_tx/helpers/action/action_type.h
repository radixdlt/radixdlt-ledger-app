//
//  action_type.h
//  LedgerXcodeProj
//
//  Created by Alexander Cyon on 2021-05-26.
//

#ifndef action_type_h
#define action_type_h

#include <stdbool.h>

typedef enum {
    ActionTypeNotSet = 0,
    ActionTypeTransferTokens = 1,
    ActionTypeStakeTokens = 2,
    ActionTypeUnstakeTokens = 3
} ActionType;

char * to_string_action_type(ActionType action_type);
void print_action_type(ActionType action_type);
bool is_valid_action_type(ActionType action_type);


#endif /* action_type_h */
