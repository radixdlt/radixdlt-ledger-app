#ifndef UPPARTICLECOUNT_H
#define UPPARTICLECOUNT_H

#include <stdint.h>

typedef struct {
	uint8_t non_transfer;
	uint8_t transferrable_tokens_particle;
} up_particle_count_t;

uint8_t total_number_of_up_particles(up_particle_count_t *count);

#endif