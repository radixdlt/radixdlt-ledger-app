#ifndef SIGNATOMUX_H
#define SIGNATOMUX_H

#include "stdint.h"

void reset_ux_state();

void received_particle_meta_data_bytes_from_host_machine(
    uint8_t *bytes,
    uint16_t number_of_bytes_received
);

void received_atom_bytes_from_host_machine(
    uint8_t *bytes,
    uint16_t number_of_bytes_received
);

#endif