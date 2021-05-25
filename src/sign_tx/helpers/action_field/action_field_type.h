#ifndef ACTIONFIELDTYPE_H
#define ACTIONFIELDTYPE_H

#include <stdbool.h>

typedef enum {
    ActionFieldTypeNoField = 0,
    ActionFieldTypeActionType = 1,
    ActionFieldTypeAccountAddress = 2,
    ActionFieldTypeAmount = 3,
    ActionFieldTypeTokenDefinitionReference = 4,
    ActionFieldTypeValidatorAddress = 5,
} ActionFieldType;

void print_action_field_type(ActionFieldType field_type);
bool is_valid_action_field_type(ActionFieldType field_type);

#endif
