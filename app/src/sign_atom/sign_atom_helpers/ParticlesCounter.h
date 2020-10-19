#ifndef PARTICLESCOUNTER_H
#define PARTICLESCOUNTER_H

#include <stdbool.h>
#include <stdint.h>
#include "UpParticleCount.h"

typedef struct {
	UpParticleCount in_atom;
	UpParticleCount identified;
} ParticlesCounter;


void init_particles_counter(
    ParticlesCounter *counter,
    uint8_t total_number_of_up_particles,
    uint8_t number_of_up_transferrable_tokens_particles
);

void identified_a_transferrable_tokens_particle(
    ParticlesCounter *counter
);

void identified_a_non_transferrable_tokens_particle(
    ParticlesCounter *counter
);

bool has_identified_all_particles(
    ParticlesCounter *counter
);

#endif