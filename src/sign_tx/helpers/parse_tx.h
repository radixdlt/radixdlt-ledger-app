#ifndef SIGNTXUX_H
#define SIGNTXUX_H

#include "stdint.h"

void reset_parse_state(void);

void received_action_from_host_machine(
    int action_index,
    uint8_t *action_bytes,
    uint16_t number_of_bytes_received
);

void empty_buffer();
#endif
