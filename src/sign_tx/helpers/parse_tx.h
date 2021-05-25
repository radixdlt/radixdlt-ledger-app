#ifndef SIGNTXUX_H
#define SIGNTXUX_H

#include "stdint.h"
#include "action_field_type.h"

void reset_parse_state();

void received_action_field_metadata_bytes_from_host_machine(
    ActionFieldType action_field_type,
    uint8_t *bytes,
    uint16_t number_of_bytes_received
);

void received_tx_bytes_from_host_machine(
    uint8_t *bytes,
    uint16_t number_of_bytes_received
);

void print_next_action_field_to_parse();

void empty_buffer();
#endif
