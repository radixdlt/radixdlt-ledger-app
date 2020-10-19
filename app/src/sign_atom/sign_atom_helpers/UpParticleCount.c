#include "UpParticleCount.h"

uint8_t total_number_of_up_particles(UpParticleCount *count) {
    return count->transferrable_tokens_particle + count->non_transfer;
}