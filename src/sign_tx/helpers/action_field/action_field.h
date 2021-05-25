#ifndef ACTIONFIELD_H
#define ACTIONFIELD_H

#include "byte_interval.h"
#include "action_field_type.h"

typedef struct {
    ActionFieldType field_type;
    byte_interval_t byte_interval;
    bool is_destroyed;
} action_field_t;

void print_action_field(action_field_t *field);

void initialize_action_field_with_bytes(
    action_field_t *field, 
    ActionFieldType field_type,
    uint8_t *bytes, uint16_t byte_count
);

#endif
