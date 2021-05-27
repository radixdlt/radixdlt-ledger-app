//
//  action_type.c
//  LedgerXcodeProj
//
//  Created by Alexander Cyon on 2021-05-26.
//

#include "action_type.h"
#include <os.h>
#include "common_macros.h"

char * to_string_action_type(ActionType action_type) {
    switch (action_type) {
        case ActionTypeTransferTokens: {
            return "Transfer\0";
            }
        case ActionTypeStakeTokens: {
            return "Stake\0";
            }
        case ActionTypeUnstakeTokens: {
            return "Unstake\0";
            }
        case ActionTypeNotSet:
        default:
            FATAL_ERROR("ERROR unknown action_type");
            return "unknown";
    }
}

void print_action_type(ActionType action_type) {
    switch (action_type)
    {
    case ActionTypeNotSet: {
        PRINTF("ERROR No action type");
        break;
        }
    case ActionTypeTransferTokens: {
        PRINTF("TransferTokens ");
        break;
        }
    case ActionTypeStakeTokens: {
        PRINTF("StakeTokens ");
        break;
        }
    case ActionTypeUnstakeTokens: {
        PRINTF("UnstakeTokens ");
        break;
        }
    default:
        FATAL_ERROR("ERROR unknown action_type");
        return;
    }
}


bool is_valid_action_type(ActionType action_type) {
        switch (action_type)
    {
 
        case ActionTypeTransferTokens:
        case ActionTypeStakeTokens:
        case ActionTypeUnstakeTokens:
        return true;

    case ActionTypeNotSet:
    default:
        FATAL_ERROR("ERROR invalid action_type");
        return false;
    }
}
