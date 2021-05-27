#include "action.h"

void print_action(action_t *action) {
    
    switch (action->action_type) {
        case ActionTypeNotSet:
            FATAL_ERROR("Trying to print an action which is not set.");
        case ActionTypeTransferTokens:
            PRINTF("\n\n$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
            PRINTF("TransferTokens(\n");
            PRINTF("    From: "); print_account_address(&action->from); PRINTF("\n");
            PRINTF("    To account: "); print_account_address(&action->to_u.account_address); PRINTF("\n");
            PRINTF("    Amount (dec): "); print_token_amount(&action->amount); PRINTF(" E-18\n");
            PRINTF("    Token symbol: "); print_radix_resource_identifier(&action->rri); PRINTF("\n");
            PRINTF(")\n");
            PRINTF("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n\n");
            break;
        case ActionTypeStakeTokens:
            PRINTF("\n\n$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
            PRINTF("StakeTokens(\n");
            PRINTF("    From: "); print_account_address(&action->from); PRINTF("\n");
            PRINTF("    To validator: "); print_validator_address(&action->to_u.validator_address); PRINTF("\n");
            PRINTF("    Amount (dec): "); print_token_amount(&action->amount); PRINTF(" E-18\n");
            PRINTF(")\n");
            PRINTF("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n\n");
            break;
        case ActionTypeUnstakeTokens:
            PRINTF("\n\n$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
            PRINTF("UnstakeTokens(\n");
            PRINTF("    Staker: "); print_account_address(&action->from); PRINTF("\n");
            PRINTF("    Validator: "); print_validator_address(&action->to_u.validator_address); PRINTF("\n");
            PRINTF("    Amount (dec): "); print_token_amount(&action->amount); PRINTF(" E-18\n");
            PRINTF(")\n");
            PRINTF("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n\n");
            break;
    }
    

}
