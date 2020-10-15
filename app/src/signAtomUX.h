#ifndef SIGNATOMUX_H
#define SIGNATOMUX_H

#include "stdint.h"
#include "ParticleFieldType.h"

void reset_ux_state();

void received_particle_field_metadata_bytes_from_host_machine(
    ParticleFieldType particle_field_type,
    uint8_t *bytes,
    uint16_t number_of_bytes_received
);

void received_atom_bytes_from_host_machine(
    uint8_t *bytes,
    uint16_t number_of_bytes_received
);

void print_atom_bytes_window();

void print_particle_metadata();

#endif