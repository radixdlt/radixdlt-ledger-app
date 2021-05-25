#include "action_field_type.h"
#include <os.h>
#include "common_macros.h"

void print_action_field_type(ActionFieldType field_type) {
    switch (field_type)
    {
    case ActionFieldTypeNoField:
        PRINTF("ERROR No Field");
        break;
    case ActionFieldTypeActionType:
        PRINTF("ActionType Field");
        break;
    case ActionFieldTypeAccountAddress:
        PRINTF("Account Address Field");
        break;
    case ActionFieldTypeAmount:
        PRINTF("Amount Field");
        break;

    case ActionFieldTypeTokenDefinitionReference:
        PRINTF("TokenDefinitionReference Field");
        break;
    case ActionFieldTypeValidatorAddress:
        PRINTF("Validator Address Field");
        break;
    }
    
}


bool is_valid_action_field_type(ActionFieldType field_type) {
        switch (field_type)
    {
 
    case ActionFieldTypeAccountAddress:
    case ActionFieldTypeAmount:
    case ActionFieldTypeActionType:
    case ActionFieldTypeTokenDefinitionReference:
    case ActionFieldTypeValidatorAddress:
        return true;

    case ActionFieldTypeNoField:
    default:
        FATAL_ERROR("ERROR No Field");
        return false;
    }
}
