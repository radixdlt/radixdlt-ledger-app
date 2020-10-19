#ifndef UPPARTICLECOUNT_H
#define UPPARTICLECOUNT_H

#include <stdint.h>

typedef struct {
	uint8_t non_transfer;
	uint8_t transferrable_tokens_particle;
} UpParticleCount;

uint8_t total_number_of_up_particles(UpParticleCount *count);

#endif