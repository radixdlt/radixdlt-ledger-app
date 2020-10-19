#include "up_particle_count.h"

uint8_t total_number_of_up_particles(up_particle_count_t *count) {
    return count->transferrable_tokens_particle + count->non_transfer;
}