#ifndef PARTICLESCOUNTER_H
#define PARTICLESCOUNTER_H

#include <stdbool.h>
#include <stdint.h>
#include "up_particle_count.h"

typedef struct {
	up_particle_count_t in_atom;
	up_particle_count_t identified;
} particles_counter_t;


void init_particles_counter(
    particles_counter_t *counter,
    uint8_t total_number_of_up_particles,
    uint8_t number_of_up_transferrable_tokens_particles
);

void identified_a_transferrable_tokens_particle(
    particles_counter_t *counter
);

void identified_a_non_transferrable_tokens_particle(
    particles_counter_t *counter
);

bool has_identified_all_particles(
    particles_counter_t *counter
);

#endif